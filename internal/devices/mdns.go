// SPDX-License-Identifier: AGPL-3.0-or-later

package devices

import (
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// MDNSHost is what one mDNS packet reveals about a host.
type MDNSHost struct {
	Name     string // hostname without ".local"
	IPs      []netip.Addr
	Services []string // service types such as "_airplay._tcp"
	Hints    []string // model strings and friendly names
	Vendor   string   // vendor hint, if a model string names one
}

// txtHintKeys carry model or product strings worth keeping.
var txtHintKeys = map[string]bool{
	"model": true, "md": true, "am": true, "ty": true, "usb_mdl": true, "product": true,
	"rpmd": true, "mdl": true, "hw": true, "fn": true, "ty-name": true,
}

var txtVendorKeys = map[string]bool{"manufacturer": true, "mf": true, "usb_mfg": true, "vendor": true, "mfg": true}

var appleModelPrefixes = []string{"appletv", "iphone", "ipad", "ipod", "macbook", "macmini", "imac", "macpro",
	"macstudio", "mac1", "mac2", "audioaccessory", "watch", "homepod"}

// ParseMDNS decodes one mDNS packet. Only responses carry identity; queries
// yield no hosts. It is a pure function over the packet bytes.
func ParseMDNS(packet []byte) (map[string]*MDNSHost, error) {
	var msg dns.Msg
	if err := msg.Unpack(packet); err != nil {
		return nil, err
	}
	hosts := map[string]*MDNSHost{}
	if !msg.Response {
		return hosts, nil
	}
	type instance struct {
		name, svc, target string
		txt               map[string]string
	}
	insts := map[string]*instance{}
	inst := func(fqdn string) *instance {
		k := strings.ToLower(fqdn)
		i := insts[k]
		if i == nil {
			i = &instance{txt: map[string]string{}}
			i.name, i.svc = splitInstance(fqdn)
			insts[k] = i
		}
		return i
	}
	host := func(fqdn string) *MDNSHost {
		k := strings.ToLower(strings.TrimSuffix(fqdn, "."))
		h := hosts[k]
		if h == nil {
			h = &MDNSHost{Name: cleanName(unescapeDNS(fqdn))}
			hosts[k] = h
		}
		return h
	}
	rrs := append(append(append([]dns.RR{}, msg.Answer...), msg.Ns...), msg.Extra...)
	for _, rr := range rrs {
		switch v := rr.(type) {
		case *dns.A:
			if a, ok := netip.AddrFromSlice(v.A); ok {
				host(v.Hdr.Name).IPs = addAddr(host(v.Hdr.Name).IPs, a.Unmap())
			}
		case *dns.AAAA:
			if a, ok := netip.AddrFromSlice(v.AAAA); ok {
				host(v.Hdr.Name).IPs = addAddr(host(v.Hdr.Name).IPs, a)
			}
		case *dns.PTR:
			if strings.HasPrefix(strings.ToLower(v.Hdr.Name), "_services._dns-sd") {
				continue
			}
			inst(v.Ptr)
		case *dns.SRV:
			inst(v.Hdr.Name).target = v.Target
		case *dns.TXT:
			i := inst(v.Hdr.Name)
			for _, kv := range v.Txt {
				if k, val, ok := strings.Cut(kv, "="); ok {
					i.txt[strings.ToLower(k)] = val
				}
			}
		}
	}
	for _, i := range insts {
		if i.target == "" || i.target == "." {
			continue
		}
		h := host(i.target)
		if i.svc != "" {
			h.Services = union(h.Services, []string{i.svc}, 0)
		}
		if i.name != "" {
			h.Hints = union(h.Hints, []string{i.name}, 0)
		}
		for k, val := range i.txt {
			val = strings.Trim(strings.TrimSpace(val), "()")
			switch {
			case txtHintKeys[k] && val != "":
				h.Hints = union(h.Hints, []string{val}, 0)
				if h.Vendor == "" && hasApplePrefix(val) {
					h.Vendor = "Apple"
				}
			case txtVendorKeys[k] && val != "":
				h.Vendor = val
			}
		}
	}
	for _, h := range hosts {
		sort.Strings(h.Services)
		sort.Strings(h.Hints)
		sort.Slice(h.IPs, func(a, b int) bool { return h.IPs[a].Less(h.IPs[b]) })
	}
	return hosts, nil
}

func hasApplePrefix(s string) bool {
	l := strings.ToLower(s)
	for _, p := range appleModelPrefixes {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	return false
}

func addAddr(list []netip.Addr, a netip.Addr) []netip.Addr {
	for _, x := range list {
		if x == a {
			return list
		}
	}
	return append(list, a)
}

// splitInstance splits "Living Room._googlecast._tcp.local." into the
// instance name and the service type "_googlecast._tcp".
func splitInstance(fqdn string) (name, svc string) {
	labels := dns.SplitDomainName(fqdn)
	for i, l := range labels {
		if strings.HasPrefix(l, "_") && i+1 < len(labels) && strings.HasPrefix(labels[i+1], "_") {
			return unescapeDNS(strings.Join(labels[:i], ".")), strings.ToLower(l + "." + labels[i+1])
		}
	}
	return "", ""
}

// unescapeDNS undoes the presentation escapes in a domain label (\032 for a
// space, \. and so on).
func unescapeDNS(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		if i+3 < len(s) && isDigit(s[i+1]) && isDigit(s[i+2]) && isDigit(s[i+3]) {
			b.WriteByte(byte(int(s[i+1]-'0')*100 + int(s[i+2]-'0')*10 + int(s[i+3]-'0')))
			i += 3
			continue
		}
		b.WriteByte(s[i+1])
		i++
	}
	return b.String()
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// MDNSAggregator accumulates what several mDNS packets say about each host
// (addresses arrive in one packet, services in another) and emits
// observations when something is new, so chatty hosts do not flood the
// registry.
type MDNSAggregator struct {
	mu    sync.Mutex
	hosts map[string]*aggHost
}

type aggHost struct {
	host    MDNSHost
	fp      string
	emitted time.Time
	seen    time.Time
}

const (
	mdnsReemit  = 5 * time.Minute
	mdnsMaxKeep = 512
	mdnsExpire  = 2 * time.Hour
)

// NewMDNSAggregator creates an empty aggregator.
func NewMDNSAggregator() *MDNSAggregator {
	return &MDNSAggregator{hosts: map[string]*aggHost{}}
}

// Ingest parses a packet and returns the observations worth sending.
func (a *MDNSAggregator) Ingest(packet []byte, now time.Time) ([]Observation, error) {
	parsed, err := ParseMDNS(packet)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.hosts) > mdnsMaxKeep {
		for k, h := range a.hosts {
			if now.Sub(h.seen) > mdnsExpire {
				delete(a.hosts, k)
			}
		}
	}
	keys := make([]string, 0, len(parsed))
	for k := range parsed {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []Observation
	for _, k := range keys {
		p := parsed[k]
		h := a.hosts[k]
		if h == nil {
			h = &aggHost{host: MDNSHost{Name: p.Name}}
			a.hosts[k] = h
		}
		h.seen = now
		for _, ip := range p.IPs {
			h.host.IPs = addAddr(h.host.IPs, ip)
		}
		h.host.Services = union(h.host.Services, p.Services, maxServices)
		h.host.Hints = union(h.host.Hints, p.Hints, maxHints)
		if p.Vendor != "" {
			h.host.Vendor = p.Vendor
		}
		if len(h.host.IPs) == 0 {
			continue
		}
		fp := fingerprint(&h.host)
		if fp == h.fp && now.Sub(h.emitted) < mdnsReemit {
			continue
		}
		h.fp, h.emitted = fp, now
		for _, ip := range h.host.IPs {
			out = append(out, Observation{
				Source: SourceMDNS, IP: ip.String(), Hostname: h.host.Name,
				Services: append([]string(nil), h.host.Services...), Hints: append([]string(nil), h.host.Hints...),
				VendorHint: h.host.Vendor, Time: now,
			})
		}
	}
	return out, nil
}

func fingerprint(h *MDNSHost) string {
	var b strings.Builder
	for _, ip := range h.IPs {
		b.WriteString(ip.String() + ",")
	}
	b.WriteString("|" + strings.Join(h.Services, ",") + "|" + strings.Join(h.Hints, ",") + "|" + h.Vendor)
	return b.String()
}
