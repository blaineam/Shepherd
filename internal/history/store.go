// SPDX-License-Identifier: AGPL-3.0-or-later

package history

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"shepherd/internal/dnsengine"
)

const (
	magic     = "SHSEG\x01"
	headerLen = len(magic) + 16
	maxFrame  = 64 << 20
	ext       = ".shseg"
)

// Options configures a Store. Zero values get sensible defaults.
type Options struct {
	Dir  string
	Keys KeySource

	RetentionDays   int           // delete sealed segments older than this (0 = keep)
	MaxBytes        int64         // delete the oldest segments past this size (0 = no cap)
	SegmentMaxAge   time.Duration // rotate after this long (default 24h)
	SegmentMaxBytes int64         // rotate past this size (default 16 MiB)
	FlushEntries    int           // flush after this many pending entries (default 200)
	FlushEvery      time.Duration // Run flushes on this interval (default 5s)
	PruneEvery      time.Duration // Run prunes on this interval (default 1h)
	LockedBuffer    int           // entries held in memory while locked (default 50000)
	Now             func() time.Time
}

type segInfo struct {
	ID     string    `json:"id"`
	Min    time.Time `json:"min"`
	Max    time.Time `json:"max"`
	Count  int       `json:"count"`
	Bytes  int64     `json:"bytes"`
	Sealed bool      `json:"sealed"`
}

type manifest struct {
	Version  int       `json:"version"`
	Segments []segInfo `json:"segments"`
}

type segWriter struct {
	f      *os.File
	aead   cipher.AEAD
	header []byte
	index  uint64
	opened time.Time
}

// Store is the encrypted history. It is safe for concurrent use.
type Store struct {
	o Options

	mu      sync.Mutex
	master  []byte // nil while locked
	man     manifest
	active  *segWriter
	pending []dnsengine.Entry
}

// Open opens (creating if needed) the store in o.Dir. If the key source needs a
// passphrase the store starts locked: Append keeps working in memory and
// Unlock later writes everything out.
func Open(o Options) (*Store, error) {
	if o.Keys == nil {
		return nil, errors.New("history: a key source is required")
	}
	if o.SegmentMaxAge <= 0 {
		o.SegmentMaxAge = 24 * time.Hour
	}
	if o.SegmentMaxBytes <= 0 {
		o.SegmentMaxBytes = 16 << 20
	}
	if o.FlushEntries <= 0 {
		o.FlushEntries = 200
	}
	if o.FlushEvery <= 0 {
		o.FlushEvery = 5 * time.Second
	}
	if o.PruneEvery <= 0 {
		o.PruneEvery = time.Hour
	}
	if o.LockedBuffer <= 0 {
		o.LockedBuffer = 50000
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if err := os.MkdirAll(filepath.Join(o.Dir, "segments"), 0o700); err != nil {
		return nil, err
	}
	s := &Store{o: o}
	key, err := o.Keys.Key()
	switch {
	case err == nil:
		if err := s.activate(key); err != nil {
			return nil, err
		}
	case errors.Is(err, dnsengine.ErrLocked):
	default:
		return nil, err
	}
	return s, nil
}

func (s *Store) Mode() string      { return "encrypted" }
func (s *Store) Initialized() bool { return s.o.Keys.Initialized() }

func (s *Store) Locked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.master == nil
}

// Unlock supplies the passphrase and writes anything held while locked.
func (s *Store) Unlock(passphrase string) error {
	if err := s.o.Keys.Unlock(passphrase); err != nil {
		return err
	}
	key, err := s.o.Keys.Key()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.master != nil {
		return nil
	}
	if err := s.activateLocked(key); err != nil {
		return err
	}
	return s.flushLocked()
}

func (s *Store) activate(key []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activateLocked(key)
}

// activateLocked loads (or rebuilds) the manifest and seals old segments.
func (s *Store) activateLocked(key []byte) error {
	s.master = key
	if err := s.loadManifestLocked(); err != nil {
		s.master = nil
		return err
	}
	return nil
}

func (s *Store) segPath(id string) string { return filepath.Join(s.o.Dir, "segments", id+ext) }
func (s *Store) manifestPath() string     { return filepath.Join(s.o.Dir, "manifest.shm") }

func (s *Store) loadManifestLocked() error {
	if m, err := s.readManifest(); err == nil {
		s.man = m
		changed := false
		for i := range s.man.Segments { // a crash may have left one unsealed
			if !s.man.Segments[i].Sealed {
				s.man.Segments[i].Sealed = true
				changed = true
			}
		}
		if changed {
			return s.saveManifestLocked()
		}
		return nil
	}
	return s.rebuildLocked()
}

func (s *Store) readManifest() (manifest, error) {
	var m manifest
	blob, err := os.ReadFile(s.manifestPath())
	if err != nil {
		return m, err
	}
	g := aeadFor(s.master, "manifest")
	if len(blob) < g.NonceSize() {
		return m, errors.New("short manifest")
	}
	pt, err := g.Open(nil, blob[:g.NonceSize()], blob[g.NonceSize():], nil)
	if err != nil {
		return m, err
	}
	return m, json.Unmarshal(pt, &m)
}

func (s *Store) saveManifestLocked() error {
	s.man.Version = 1
	pt, _ := json.Marshal(s.man) // a struct of strings, times and numbers cannot fail to encode
	g := aeadFor(s.master, "manifest")
	nonce := randBytes(g.NonceSize())
	return writeFile0600(s.manifestPath(), g.Seal(nonce, nonce, pt, nil))
}

// rebuildLocked reconstructs the manifest by reading every segment. It refuses
// to continue if segments exist but none can be decrypted with this key.
func (s *Store) rebuildLocked() error {
	files, err := filepath.Glob(filepath.Join(s.o.Dir, "segments", "*"+ext))
	if err != nil {
		return err
	}
	var segs []segInfo
	readable := 0
	for _, f := range files {
		id := strings.TrimSuffix(filepath.Base(f), ext)
		info := segInfo{ID: id, Sealed: true}
		if st, err := os.Stat(f); err == nil {
			info.Bytes = st.Size()
		}
		skipped, err := scanSegment(f, s.master, func(e dnsengine.Entry) {
			if info.Count == 0 || e.Time.Before(info.Min) {
				info.Min = e.Time
			}
			if info.Count == 0 || e.Time.After(info.Max) {
				info.Max = e.Time
			}
			info.Count++
		})
		if err == nil && info.Count > 0 {
			readable++
		}
		_ = skipped
		segs = append(segs, info)
	}
	if len(files) > 0 && readable == 0 {
		return errors.New("history: existing data cannot be decrypted with this key")
	}
	sort.Slice(segs, func(i, j int) bool { return segs[i].Min.Before(segs[j].Min) })
	s.man = manifest{Version: 1, Segments: segs}
	return s.saveManifestLocked()
}

// Append records an entry. It never blocks on disk for long: entries are
// batched and flushed.
func (s *Store) Append(e dnsengine.Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending = append(s.pending, e)
	if s.master == nil {
		if over := len(s.pending) - s.o.LockedBuffer; over > 0 {
			s.pending = append([]dnsengine.Entry(nil), s.pending[over:]...)
		}
		return
	}
	if len(s.pending) >= s.o.FlushEntries {
		if err := s.flushLocked(); err != nil {
			log.Printf("history: flush: %v", err)
		}
	}
}

// Flush writes pending entries to disk now.
func (s *Store) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.flushLocked()
}

func (s *Store) flushLocked() error {
	if s.master == nil || len(s.pending) == 0 {
		return nil
	}
	if s.active != nil && (s.o.Now().Sub(s.active.opened) >= s.o.SegmentMaxAge || s.activeSize() >= s.o.SegmentMaxBytes) {
		s.sealActiveLocked()
	}
	if s.active == nil {
		if err := s.openActiveLocked(); err != nil {
			return err
		}
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	enc := json.NewEncoder(gz)
	for _, e := range s.pending {
		_ = enc.Encode(e) // an Entry always encodes; writes go to memory
	}
	_ = gz.Close()
	w := s.active
	nonce := frameNonce(w.index)
	ct := w.aead.Seal(nil, nonce, buf.Bytes(), frameAAD(w.header, w.index))
	frame := make([]byte, 4+len(ct))
	binary.BigEndian.PutUint32(frame, uint32(len(ct)))
	copy(frame[4:], ct)
	if _, err := w.f.Write(frame); err != nil {
		return err
	}
	if err := w.f.Sync(); err != nil {
		return err
	}
	w.index++

	info := &s.man.Segments[len(s.man.Segments)-1]
	for _, e := range s.pending {
		if info.Count == 0 || e.Time.Before(info.Min) {
			info.Min = e.Time
		}
		if info.Count == 0 || e.Time.After(info.Max) {
			info.Max = e.Time
		}
		info.Count++
	}
	info.Bytes += int64(len(frame))
	s.pending = nil
	return s.saveManifestLocked()
}

func (s *Store) activeSize() int64 {
	return s.man.Segments[len(s.man.Segments)-1].Bytes
}

func frameNonce(idx uint64) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:], idx)
	return n
}

func frameAAD(header []byte, idx uint64) []byte {
	aad := make([]byte, len(header)+8)
	copy(aad, header)
	binary.BigEndian.PutUint64(aad[len(header):], idx)
	return aad
}

func segmentAEAD(master, header []byte) cipher.AEAD {
	return aeadFor(master, "segment "+hex.EncodeToString(header[len(magic):]))
}

func (s *Store) openActiveLocked() error {
	id := randBytes(16)
	header := append([]byte(magic), id...)
	aead := segmentAEAD(s.master, header)
	name := hex.EncodeToString(id)
	f, err := os.OpenFile(s.segPath(name), os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(header); err != nil {
		f.Close()
		return err
	}
	s.active = &segWriter{f: f, aead: aead, header: header, opened: s.o.Now()}
	s.man.Segments = append(s.man.Segments, segInfo{ID: name, Bytes: int64(len(header))})
	return nil
}

func (s *Store) sealActiveLocked() {
	if s.active == nil {
		return
	}
	s.active.f.Close()
	s.active = nil
	s.man.Segments[len(s.man.Segments)-1].Sealed = true
}

// scanSegment decrypts every frame of the segment at path and calls fn for each
// entry. A truncated tail (an interrupted write) ends the scan quietly; a frame
// that fails authentication ends it and is reported through skipped.
func scanSegment(path string, master []byte, fn func(dnsengine.Entry)) (skipped int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	header := make([]byte, headerLen)
	if _, err := io.ReadFull(f, header); err != nil || string(header[:len(magic)]) != magic {
		return 1, errors.New("not a history segment")
	}
	aead := segmentAEAD(master, header)
	for idx := uint64(0); ; idx++ {
		var lenBuf [4]byte
		if _, err := io.ReadFull(f, lenBuf[:]); err != nil {
			return skipped, nil // clean end or truncated length
		}
		n := binary.BigEndian.Uint32(lenBuf[:])
		if n == 0 || n > maxFrame {
			return skipped + 1, nil
		}
		ct := make([]byte, n)
		if _, err := io.ReadFull(f, ct); err != nil {
			return skipped, nil // truncated final frame
		}
		pt, err := aead.Open(nil, frameNonce(idx), ct, frameAAD(header, idx))
		if err != nil {
			return skipped + 1, nil // tampered or wrong key
		}
		gz, err := gzip.NewReader(bytes.NewReader(pt))
		if err != nil {
			return skipped + 1, nil
		}
		dec := json.NewDecoder(gz)
		for {
			var e dnsengine.Entry
			if err := dec.Decode(&e); err != nil {
				break
			}
			fn(e)
		}
	}
}

// Query returns matching entries oldest first, keeping only the newest q.Limit.
func (s *Store) Query(q dnsengine.HistoryQuery) ([]dnsengine.Entry, dnsengine.Span, error) {
	s.mu.Lock()
	if s.master == nil {
		s.mu.Unlock()
		return nil, dnsengine.Span{}, dnsengine.ErrLocked
	}
	master := s.master
	segs := append([]segInfo(nil), s.man.Segments...)
	pending := append([]dnsengine.Entry(nil), s.pending...)
	s.mu.Unlock()

	var span dnsengine.Span
	widen := func(t time.Time) {
		if span.Oldest.IsZero() || t.Before(span.Oldest) {
			span.Oldest = t
		}
		if t.After(span.Newest) {
			span.Newest = t
		}
	}
	var out []dnsengine.Entry
	for _, sg := range segs {
		if sg.Count == 0 {
			continue
		}
		widen(sg.Min)
		widen(sg.Max)
		if (!q.From.IsZero() && sg.Max.Before(q.From)) || (!q.To.IsZero() && sg.Min.After(q.To)) {
			continue
		}
		skipped, err := scanSegment(s.segPath(sg.ID), master, func(e dnsengine.Entry) {
			if q.Match(e) {
				out = append(out, e)
			}
		})
		span.Skipped += skipped
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			span.Skipped++
		}
	}
	for _, e := range pending {
		widen(e.Time)
		if q.Match(e) {
			out = append(out, e)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
	return dnsengine.Newest(out, q.Limit), span, nil
}

// Prune deletes sealed segments past the retention window, then the oldest
// ones while the store is over its size cap.
func (s *Store) Prune() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.master == nil {
		return nil
	}
	now := s.o.Now()
	var keep []segInfo
	var total int64
	for _, sg := range s.man.Segments {
		old := s.o.RetentionDays > 0 && sg.Sealed && sg.Count > 0 && sg.Max.Before(now.AddDate(0, 0, -s.o.RetentionDays))
		if old {
			_ = os.Remove(s.segPath(sg.ID))
			continue
		}
		keep = append(keep, sg)
		total += sg.Bytes
	}
	if s.o.MaxBytes > 0 {
		for len(keep) > 1 && total > s.o.MaxBytes && keep[0].Sealed {
			total -= keep[0].Bytes
			_ = os.Remove(s.segPath(keep[0].ID))
			keep = keep[1:]
		}
	}
	if len(keep) == len(s.man.Segments) {
		return nil
	}
	s.man.Segments = keep
	return s.saveManifestLocked()
}

// Run flushes and prunes on their intervals until ctx ends, then flushes once more.
func (s *Store) Run(ctx context.Context) {
	flush := time.NewTicker(s.o.FlushEvery)
	prune := time.NewTicker(s.o.PruneEvery)
	defer flush.Stop()
	defer prune.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = s.Flush()
			return
		case <-flush.C:
			if err := s.Flush(); err != nil {
				log.Printf("history: flush: %v", err)
			}
		case <-prune.C:
			if err := s.Prune(); err != nil {
				log.Printf("history: prune: %v", err)
			}
		}
	}
}

// Close flushes and releases the active segment.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.flushLocked()
	s.sealActiveLocked()
	if s.master != nil {
		if e := s.saveManifestLocked(); err == nil {
			err = e
		}
	}
	return err
}

// Stats reports how much the store holds, for the portal.
type Stats struct {
	Segments int   `json:"segments"`
	Entries  int   `json:"entries"`
	Bytes    int64 `json:"bytes"`
	Pending  int   `json:"pending"`
}

func (s *Store) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Stats{Segments: len(s.man.Segments), Pending: len(s.pending)}
	for _, sg := range s.man.Segments {
		st.Entries += sg.Count
		st.Bytes += sg.Bytes
	}
	return st
}
