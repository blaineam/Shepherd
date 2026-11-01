// SPDX-License-Identifier: AGPL-3.0-or-later

// Package vulnfeed builds Shepherd's vulnerability signature feed
// (feeds/vulnscan.json, consumed by internal/vulnscan's FeedUpdater) from
// two public, keyless sources: the NVD's CVE API and CISA's Known Exploited
// Vulnerabilities catalog. cmd/vulnfeed is the command the daily workflow
// runs; everything here is pure enough to test with fixtures.
//
// The feed can only name products internal/vulnscan can actually
// fingerprint from a banner or an HTTP Server header (vulnscan.KnownProducts),
// so the product table below is the whole scope of what the feed covers;
// its test pins it to that list.
package vulnfeed

// Product is one fingerprintable product and the CPE match strings the NVD
// files its CVEs under. Several CPEs cover vendor renames (nginx moved from
// nginx:nginx to f5:nginx) and the odd project-name convention.
type Product struct {
	// Name is the product name a vulnscan feed signature uses.
	Name string
	// Label is how the product is written in a finding's name.
	Label string
	// CPEs are "cpe:2.3:a:<vendor>:<product>" prefixes, no trailing colon.
	CPEs []string
}

// Products is every product the feed is built for.
var Products = []Product{
	{Name: "openssh", Label: "OpenSSH", CPEs: []string{"cpe:2.3:a:openbsd:openssh"}},
	{Name: "dropbear", Label: "Dropbear SSH", CPEs: []string{"cpe:2.3:a:dropbear_ssh_project:dropbear_ssh", "cpe:2.3:a:matt_johnston:dropbear_ssh_server"}},
	{Name: "vsftpd", Label: "vsftpd", CPEs: []string{"cpe:2.3:a:vsftpd_project:vsftpd", "cpe:2.3:a:beasts:vsftpd"}},
	{Name: "proftpd", Label: "ProFTPD", CPEs: []string{"cpe:2.3:a:proftpd:proftpd"}},
	{Name: "exim", Label: "Exim", CPEs: []string{"cpe:2.3:a:exim:exim"}},
	{Name: "apache", Label: "Apache httpd", CPEs: []string{"cpe:2.3:a:apache:http_server"}},
	{Name: "nginx", Label: "nginx", CPEs: []string{"cpe:2.3:a:f5:nginx", "cpe:2.3:a:nginx:nginx"}},
	{Name: "lighttpd", Label: "lighttpd", CPEs: []string{"cpe:2.3:a:lighttpd:lighttpd"}},
	{Name: "openssl", Label: "OpenSSL", CPEs: []string{"cpe:2.3:a:openssl:openssl"}},
	{Name: "php", Label: "PHP", CPEs: []string{"cpe:2.3:a:php:php"}},
	{Name: "boa", Label: "Boa web server", CPEs: []string{"cpe:2.3:a:boa:boa"}},
	{Name: "mini_httpd", Label: "mini_httpd", CPEs: []string{"cpe:2.3:a:acme:mini_httpd"}},
	{Name: "goahead", Label: "GoAhead web server", CPEs: []string{"cpe:2.3:a:embedthis:goahead"}},
	{Name: "microsoft-iis", Label: "Microsoft IIS", CPEs: []string{"cpe:2.3:a:microsoft:internet_information_services"}},
}
