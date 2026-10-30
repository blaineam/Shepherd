// SPDX-License-Identifier: AGPL-3.0-or-later

package dnsengine

// Filtering is what a public resolver blocks on its own.
type Filtering string

const (
	FilterNone    Filtering = "none"
	FilterMalware Filtering = "malware"
	FilterAds     Filtering = "ads"
	FilterFamily  Filtering = "family"
)

// Preset describes a well-known public resolver for the portal's picker. Every
// field was checked against the live service; see presets_test.go for the
// structural checks that run offline.
type Preset struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Provider    string    `json:"provider"`
	Description string    `json:"description"`
	IPv4        []string  `json:"ipv4,omitempty"`
	IPv6        []string  `json:"ipv6,omitempty"`
	DoH         string    `json:"doh,omitempty"`
	DoT         string    `json:"dot,omitempty"` // host only
	Filtering   Filtering `json:"filtering"`
	Privacy     string    `json:"privacy"`
}

// Upstreams returns the preset as pool addresses: plain IPs ("ip"), DoH
// ("doh") or DoT ("dot"). It returns nil when the preset has no such form.
func (p Preset) Upstreams(form string) []string {
	switch form {
	case "ip":
		return append(append([]string(nil), p.IPv4...), p.IPv6...)
	case "doh":
		if p.DoH != "" {
			return []string{p.DoH}
		}
	case "dot":
		if p.DoT != "" {
			return []string{"tls://" + p.DoT}
		}
	}
	return nil
}

// Presets returns the catalog of verified public resolvers.
func Presets() []Preset {
	return []Preset{
		{
			ID: "cloudflare", Name: "Cloudflare", Provider: "Cloudflare",
			Description: "Fast general-purpose resolver, no filtering.",
			IPv4:        []string{"1.1.1.1", "1.0.0.1"}, IPv6: []string{"2606:4700:4700::1111", "2606:4700:4700::1001"}, // leakcheck:allow public resolver addresses
			DoH: "https://cloudflare-dns.com/dns-query", DoT: "one.one.one.one", Filtering: FilterNone,
			Privacy: "Publishes a policy of not selling data and keeping logs only briefly; see Cloudflare's resolver privacy policy.",
		},
		{
			ID: "cloudflare-malware", Name: "Cloudflare (malware blocking)", Provider: "Cloudflare",
			Description: "Cloudflare with known malware and phishing domains blocked.",
			IPv4:        []string{"1.1.1.2", "1.0.0.2"}, IPv6: []string{"2606:4700:4700::1112", "2606:4700:4700::1002"}, // leakcheck:allow public resolver addresses
			DoH: "https://security.cloudflare-dns.com/dns-query", DoT: "security.cloudflare-dns.com", Filtering: FilterMalware,
			Privacy: "Same privacy policy as Cloudflare 1.1.1.1.",
		},
		{
			ID: "cloudflare-family", Name: "Cloudflare (family)", Provider: "Cloudflare",
			Description: "Cloudflare with malware and adult content blocked.",
			IPv4:        []string{"1.1.1.3", "1.0.0.3"}, IPv6: []string{"2606:4700:4700::1113", "2606:4700:4700::1003"}, // leakcheck:allow public resolver addresses
			DoH: "https://family.cloudflare-dns.com/dns-query", DoT: "family.cloudflare-dns.com", Filtering: FilterFamily,
			Privacy: "Same privacy policy as Cloudflare 1.1.1.1.",
		},
		{
			ID: "quad9", Name: "Quad9 (malware blocking)", Provider: "Quad9",
			Description: "Non-profit resolver that blocks known malicious domains and validates DNSSEC.",
			IPv4:        []string{"9.9.9.9", "149.112.112.112"}, IPv6: []string{"2620:fe::fe", "2620:fe::9"}, // leakcheck:allow public resolver addresses
			DoH: "https://dns.quad9.net/dns-query", DoT: "dns.quad9.net", Filtering: FilterMalware,
			Privacy: "Swiss non-profit; states that it does not record client IP addresses.",
		},
		{
			ID: "quad9-unfiltered", Name: "Quad9 (unfiltered)", Provider: "Quad9",
			Description: "Quad9 without threat blocking and without DNSSEC validation.",
			IPv4:        []string{"9.9.9.10", "149.112.112.10"}, IPv6: []string{"2620:fe::10", "2620:fe::fe:10"}, // leakcheck:allow public resolver addresses
			DoH: "https://dns10.quad9.net/dns-query", DoT: "dns10.quad9.net", Filtering: FilterNone,
			Privacy: "Swiss non-profit; states that it does not record client IP addresses.",
		},
		{
			ID: "google", Name: "Google Public DNS", Provider: "Google",
			Description: "Large, reliable general-purpose resolver, no filtering.",
			IPv4:        []string{"8.8.8.8", "8.8.4.4"}, IPv6: []string{"2001:4860:4860::8888", "2001:4860:4860::8844"}, // leakcheck:allow public resolver addresses
			DoH: "https://dns.google/dns-query", DoT: "dns.google", Filtering: FilterNone,
			Privacy: "Logs are kept temporarily and, for a limited set of fields, permanently; see Google's policy.",
		},
		{
			ID: "adguard", Name: "AdGuard DNS (ads and trackers)", Provider: "AdGuard",
			Description: "Blocks ads, trackers and known malicious domains.",
			IPv4:        []string{"94.140.14.14", "94.140.15.15"}, IPv6: []string{"2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"}, // leakcheck:allow public resolver addresses
			DoH: "https://dns.adguard-dns.com/dns-query", DoT: "dns.adguard-dns.com", Filtering: FilterAds,
			Privacy: "States that it keeps only aggregate statistics and does not store client IP addresses.",
		},
		{
			ID: "adguard-unfiltered", Name: "AdGuard DNS (non-filtering)", Provider: "AdGuard",
			Description: "AdGuard's resolver with all blocking turned off.",
			IPv4:        []string{"94.140.14.140", "94.140.14.141"}, IPv6: []string{"2a10:50c0::1:ff", "2a10:50c0::2:ff"}, // leakcheck:allow public resolver addresses
			DoH: "https://unfiltered.adguard-dns.com/dns-query", DoT: "unfiltered.adguard-dns.com", Filtering: FilterNone,
			Privacy: "States that it keeps only aggregate statistics and does not store client IP addresses.",
		},
		{
			ID: "mullvad", Name: "Mullvad DNS", Provider: "Mullvad",
			Description: "No-logging resolver from the VPN provider. Encrypted only: its plain DNS address refuses queries.",
			DoH:         "https://dns.mullvad.net/dns-query", DoT: "dns.mullvad.net", Filtering: FilterNone,
			Privacy: "States a no-logging policy; encrypted transports only.",
		},
	}
}

// PresetByID returns the preset with the given id.
func PresetByID(id string) (Preset, bool) {
	for _, p := range Presets() {
		if p.ID == id {
			return p, true
		}
	}
	return Preset{}, false
}
