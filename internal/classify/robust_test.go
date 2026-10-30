// SPDX-License-Identifier: AGPL-3.0-or-later

package classify

import (
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"shepherd/internal/devices"
)

// A flood of random domains from many clients must not grow memory without bound.
func TestMemoryStaysBoundedUnderAFloodOfRandomDomains(t *testing.T) {
	const maxDev, maxDom = 64, 8
	c, _ := newClassifier(t, func(o *Options) { o.MaxDevices = maxDev; o.MaxDomains = maxDom; o.MaxASNs = 4 })
	rng := rand.New(rand.NewSource(1))
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := 0; i < 300000; i++ {
		client := fmt.Sprintf("192.0.2.%d", rng.Intn(250)+1)
		name := fmt.Sprintf("%x.d%x.example", rng.Int63(), rng.Int63()) // a fresh registrable domain every time
		name = strings.Replace(name, ".example", ".net", 1)
		c.Observe(client, name, ips(fmt.Sprintf("198.51.100.%d", rng.Intn(250)), fmt.Sprintf("203.0.113.%d", rng.Intn(250))))
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	st := c.Stats()
	perShard := (maxDev + shardCount - 1) / shardCount
	if st.Devices > perShard*shardCount {
		t.Errorf("tracking %d devices, cap is %d", st.Devices, perShard*shardCount)
	}
	if st.Domains > st.Devices*maxDom {
		t.Errorf("retaining %d domains across %d devices, cap is %d each", st.Domains, st.Devices, maxDom)
	}
	for i := range c.st.shards {
		for _, e := range c.st.shards[i].m {
			if len(e.domains) > maxDom || len(e.asns) > 4 {
				t.Fatalf("device %s keeps %d domains and %d ASNs", e.key, len(e.domains), len(e.asns))
			}
		}
	}
	if grown := int64(after.HeapAlloc) - int64(before.HeapAlloc); grown > 8<<20 {
		t.Errorf("heap grew by %d bytes under the flood", grown)
	}
}

// A flood must not push out what a device really talks to.
func TestRealTrafficSurvivesAFloodOfNoise(t *testing.T) {
	c, _ := newClassifier(t, func(o *Options) { o.MaxDomains = 8 })
	c.SetResolver(func(string) string { return "cam" })
	c.ObserveDevice("cam", "", nil, false)
	look(c, "192.0.2.90", "ius.hik-connect.com", "203.0.113.10", 40)
	look(c, "192.0.2.90", "api.ezvizlife.com", "203.0.113.11", 40)
	for i := 0; i < 5000; i++ {
		c.Observe("192.0.2.90", fmt.Sprintf("www.noise%d.org", i), nil) // each a different registrable domain
		if i%500 == 0 {
			c.Observe("192.0.2.90", "ius.hik-connect.com", nil)
		}
	}
	ret, _ := c.Retained("cam")
	have := map[string]bool{}
	for _, d := range ret.Domains {
		have[d.Domain] = true
	}
	if !have["hik-connect.com"] || !have["ezvizlife.com"] {
		t.Errorf("the device's real domains were pushed out: %+v", ret.Domains)
	}
	if r := c.Classify("cam"); r.Type != devices.TypeCamera {
		t.Errorf("noise changed the answer: %s", describe(r))
	}
}

// Only counts and registrable domains are kept: no history, no full names, no addresses.
func TestPrivacyNothingButRegistrableDomainsIsRetained(t *testing.T) {
	c, _ := newClassifier(t)
	c.SetResolver(func(string) string { return "p" })
	c.ObserveDevice("p", "Sonos", []string{"_sonos._tcp.local"}, false)
	secrets := []string{"my-private-search-term", "alice-laptop-backup", "198.51.100.7", "203.0.113.9"}
	c.Observe("192.0.2.91", "my-private-search-term.alice-laptop-backup.example.com", ips("198.51.100.7"))
	c.Observe("192.0.2.91", "WWW.Example.com.", ips("203.0.113.9"))
	c.Observe("192.0.2.91", "ius.hik-connect.com", ips("198.51.100.7", "203.0.113.9"))

	ret, ok := c.Retained("p")
	if !ok {
		t.Fatal("expected retained data")
	}
	names := map[string]bool{}
	for _, d := range ret.Domains {
		names[d.Domain] = true
	}
	if len(names) != 2 || !names["example.com"] || !names["hik-connect.com"] {
		t.Errorf("only registrable domains may be kept, got %+v", ret.Domains)
	}
	// Dump every byte of internal state and look for anything that should not be there.
	e := c.st.shardFor("p").m["p"]
	dump := fmt.Sprintf("%#v %+v", *e, ret)
	for _, s := range secrets {
		if strings.Contains(dump, s) {
			t.Errorf("retained state contains %q", s)
		}
	}
	for _, s := range []string{"192.0.2.91", "www.", "WWW"} {
		if strings.Contains(dump, s) {
			t.Errorf("retained state contains %q", s)
		}
	}
	// No per-lookup timestamps: the only time kept is one "last seen" and one decay mark.
	if e.last.IsZero() || e.decayAt.IsZero() {
		t.Error("expected the two coarse timestamps")
	}
	// Reverse lookups, local names and single labels are not even counted.
	before := e.lookups
	c.Observe("192.0.2.91", "4.3.2.1.in-addr.arpa", nil)
	c.Observe("192.0.2.91", "printer.local", nil)
	c.Observe("192.0.2.91", "intranet", nil)
	c.Observe("", "www.example.com", nil)
	if e.lookups != before {
		t.Error("names that say nothing about the device must not be recorded")
	}
	// A retained snapshot is a copy: editing it changes nothing inside.
	ret.Domains[0].Domain = "tampered"
	if again, _ := c.Retained("p"); again.Domains[0].Domain == "tampered" {
		t.Error("Retained must return a copy")
	}
}

func TestObserveHotPathAllocatesNothingForKnownNames(t *testing.T) {
	c, _ := newClassifier(t)
	c.SetResolver(func(string) string { return "hot" })
	c.ObserveDevice("hot", "", nil, false)
	ans := ips("198.51.100.5", "203.0.113.5")
	c.Observe("192.0.2.92", "cdn.eu.hik-connect.com", ans)
	n := testing.AllocsPerRun(200, func() { c.Observe("192.0.2.92", "cdn.eu.hik-connect.com", ans) })
	if n > 0 {
		t.Errorf("Observe allocated %v times for a name it already knows", n)
	}
}

func TestNonBlockingObserveDropsInsteadOfWaiting(t *testing.T) {
	c, _ := newClassifier(t, func(o *Options) { o.NonBlocking = true })
	sh := c.st.shardFor("192.0.2.93")
	sh.mu.Lock() // the shard is busy
	done := make(chan struct{})
	go func() {
		for i := 0; i < 10; i++ {
			c.Observe("192.0.2.93", "www.example.com", nil)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a non-blocking Observe waited for a busy lock")
	}
	sh.mu.Unlock()
	if c.Dropped() != 10 {
		t.Errorf("dropped = %d, want 10", c.Dropped())
	}
	c.Observe("192.0.2.93", "www.example.com", nil)
	if c.Dropped() != 10 || c.Stats().Devices != 1 {
		t.Errorf("an idle shard must accept again: %+v", c.Stats())
	}
	if c.Stats().Dropped != 10 {
		t.Error("Stats reports the drop count")
	}
}

func TestConcurrentUseIsSafe(t *testing.T) {
	l := newLab(t, func(o *Options) { o.NonBlocking = false })
	var ids, ipsList []string
	for i := 0; i < 20; i++ {
		id, ip := l.device([]string{"Sonos", "Reolink Innovation", "Vizio", ""}[i%4], i%4 == 3)
		ids = append(ids, id)
		ipsList = append(ipsList, ip)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	names := []string{"ius.hik-connect.com", "update.sonos.com", "www.netflix.com", "x.example.com", "a.b.example.org"}
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(g)))
			for i := 0; i < 4000; i++ {
				l.c.Observe(ipsList[rng.Intn(len(ipsList))], names[rng.Intn(len(names))], []net.IP{net.ParseIP("198.51.100.4")})
			}
		}(g)
	}
	for g := 0; g < 2; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					l.c.Apply(l.reg)
					l.c.Suggestions()
					l.c.Stats()
					l.c.Prune()
					for _, id := range ids {
						l.c.Classify(id)
						l.c.Retained(id)
					}
					l.clk.Advance(time.Minute)
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			l.c.ObserveDevice(ids[i%len(ids)], "Sonos", []string{"_sonos._tcp"}, false)
			l.c.ObserveNames(ids[i%len(ids)], []string{"thing"}, nil)
			l.c.SetASN(fakeASN)
			l.c.SetResolver(func(ip string) string { id, _ := l.reg.ScopesFor(ip); return id })
			if i%50 == 0 {
				_ = l.reg.SetType(ids[0], "tv")
				_ = l.reg.SetType(ids[0], "auto")
			}
		}
	}()
	time.Sleep(100 * time.Millisecond)
	// Let the observers finish, then stop the appliers.
	var done atomic.Bool
	go func() { time.Sleep(50 * time.Millisecond); done.Store(true) }()
	for !done.Load() {
		runtime.Gosched()
	}
	close(stop)
	wg.Wait()
}

func TestASNLookupsAreBoundedDedupedAndFiltered(t *testing.T) {
	var calls atomic.Int32
	c, _ := newClassifier(t, func(o *Options) {
		o.ASN = func(a netip.Addr) (ASNInfo, bool) {
			calls.Add(1)
			switch a.String() {
			case "198.51.100.1", "198.51.100.2":
				return ASNInfo{2906, "Netflix Streaming Services Inc."}, true
			case "198.51.100.3":
				return ASNInfo{0, "bad"}, true // an answer with no AS number
			case "198.51.100.4":
				return ASNInfo{1 << 40, "too big"}, true
			case "198.51.100.5":
				return ASNInfo{64999, "Example Org With A Keyword netflix"}, true // an unknown AS, matched by organization
			case "198.51.100.6":
				return ASNInfo{64998, "Nobody"}, true // known to the database, unknown to the rules
			}
			return ASNInfo{}, false
		}
	})
	c.SetResolver(func(string) string { return "a" })
	c.ObserveDevice("a", "", nil, false)
	// Six answers: only the first three are looked at, and the two Netflix addresses are one network.
	c.Observe("192.0.2.94", "www.example.com", ips("198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.5", "198.51.100.6"))
	if calls.Load() != 3 {
		t.Errorf("looked up %d answers, want at most %d", calls.Load(), maxAnswersSeen)
	}
	ret, _ := c.Retained("a")
	if len(ret.ASNs) != 1 || ret.ASNs[0] != 2906 {
		t.Errorf("ASNs = %v", ret.ASNs)
	}
	c.Observe("192.0.2.94", "www.example.com", []net.IP{nil, net.ParseIP("198.51.100.4"), net.ParseIP("198.51.100.5"), net.ParseIP("198.51.100.6"), net.ParseIP("198.51.100.9")})
	ret, _ = c.Retained("a")
	if len(ret.ASNs) != 2 { // 2906, then the organization-keyword match (the 4th and 5th answers are never looked at)
		t.Errorf("ASNs = %v", ret.ASNs)
	}
	c.Observe("192.0.2.94", "www.example.com", ips("198.51.100.6"))
	if ret, _ = c.Retained("a"); len(ret.ASNs) != 3 {
		t.Errorf("an AS the database knows but the rules do not is still tracked: %v", ret.ASNs)
	}
	e := c.st.shardFor("a").m["a"]
	if e.asn[mustIdx(c, devices.TypeTV)] == 0 {
		t.Error("the organization keyword should have contributed a hint")
	}
	// Without a database the family is silent.
	c.SetASN(nil)
	before := len(ret.ASNs)
	c.Observe("192.0.2.94", "www.example.com", ips("198.51.100.1"))
	if r, _ := c.Retained("a"); len(r.ASNs) != before {
		t.Error("no ASN function, no ASN evidence")
	}
}

func TestASNSetIsCappedAndCreditLimited(t *testing.T) {
	c, _ := newClassifier(t, func(o *Options) {
		o.MaxASNs = 2
		o.ASN = func(a netip.Addr) (ASNInfo, bool) {
			b := a.As4()
			return ASNInfo{uint(64500 + int(b[3])), "Example Net"}, true
		}
	})
	c.SetResolver(func(string) string { return "a" })
	for i := 1; i <= 50; i++ {
		c.Observe("192.0.2.95", "www.example.com", ips(fmt.Sprintf("198.51.100.%d", i)))
	}
	if ret, _ := c.Retained("a"); len(ret.ASNs) != 2 {
		t.Errorf("ASN set should stay capped at 2: %v", ret.ASNs)
	}
	// An ASN that has become established is not displaced by one-off newcomers.
	c2, _ := newClassifier(t, func(o *Options) {
		o.MaxASNs = 1
		o.ASN = func(a netip.Addr) (ASNInfo, bool) { return ASNInfo{uint(64500 + int(a.As4()[3])), "Example Net"}, true }
	})
	c2.SetResolver(func(string) string { return "a" })
	for i := 0; i < 5; i++ {
		c2.Observe("192.0.2.95", "www.example.com", ips("198.51.100.1"))
	}
	c2.Observe("192.0.2.95", "www.example.com", ips("198.51.100.2"))
	if ret, _ := c2.Retained("a"); len(ret.ASNs) != 1 || ret.ASNs[0] != 64501 {
		t.Errorf("an established ASN was displaced: %v", ret.ASNs)
	}
}

func TestDomainCreditIsCappedPerDomain(t *testing.T) {
	c, _ := newClassifier(t)
	c.SetResolver(func(string) string { return "a" })
	look(c, "192.0.2.96", "ius.hik-connect.com", "203.0.113.10", 5)
	r5 := c.Classify("a").Score(devices.TypeCamera)
	look(c, "192.0.2.96", "ius.hik-connect.com", "203.0.113.10", 5000)
	r5000 := c.Classify("a").Score(devices.TypeCamera)
	if r5000 != r5 {
		t.Errorf("a chatty domain must not count past its credit: %.3f -> %.3f", r5, r5000)
	}
}

func TestObserveDeviceAndNamesNormalizeAndBound(t *testing.T) {
	c, _ := newClassifier(t)
	var svcs []string
	for i := 0; i < 40; i++ {
		svcs = append(svcs, fmt.Sprintf("_svc%d._tcp.local", i))
	}
	svcs = append(svcs, "._IPP._tcp.local", "_ipp._udp", "", "  ")
	c.ObserveDevice("d", "  Brother Industries ", svcs, false)
	ret, _ := c.Retained("d")
	if len(ret.Services) != maxServices || ret.Vendor != "Brother Industries" {
		t.Errorf("services/vendor = %v / %q", ret.Services, ret.Vendor)
	}
	c.ObserveDevice("d", "Brother Industries", []string{"._IPP._tcp.local", "_ipp._udp", "_ipp"}, false)
	ret, _ = c.Retained("d")
	if len(ret.Services) != 1 || ret.Services[0] != "_ipp" {
		t.Errorf("services should be lower-cased, de-duplicated first labels: %v", ret.Services)
	}
	if r := c.Classify("d"); r.Type != devices.TypePrinter {
		t.Errorf("_ipp should make a printer: %s", describe(r))
	}
	// Empty keys are ignored.
	c.ObserveDevice("", "Sonos", nil, false)
	c.ObserveNames("", []string{"camera"}, nil)
	if c.Stats().Devices != 1 {
		t.Error("an empty key must not create a device")
	}
	// Names: only a bounded number are used, and a name can say what the device is.
	var many []string
	for i := 0; i < 30; i++ {
		many = append(many, "", fmt.Sprintf("plain-name-%d", i))
	}
	many = append(many, "front-door-camera")
	c.ObserveNames("n", many, nil)
	if r := c.Classify("n"); r.Type != devices.TypeUnknown {
		t.Errorf("only the first %d names are considered (blanks skipped): %s", maxNames, describe(r))
	}
	c.ObserveNames("n", []string{" Hall Camera "}, []string{"model x"})
	r := c.Classify("n")
	mustType(t, r.Type, devices.TypeCamera, describe(r))
	if !strings.Contains(strings.Join(r.Reasons, "|"), `Its name or model contains "camera"`) {
		t.Errorf("reasons = %v", r.Reasons)
	}
}

func mustIdx(c *Classifier, t devices.DeviceType) int { return c.rs.classIdx[t] }
