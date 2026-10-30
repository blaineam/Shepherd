// SPDX-License-Identifier: AGPL-3.0-or-later

package classify

import "strings"

// registrable returns the registrable domain of a lower-case host name: the
// public suffix plus one label ("a.b.example.com" gives "example.com",
// "x.example.co.uk" gives "example.co.uk"). It is a deliberately small
// approximation of the public suffix list, enough to aggregate lookups by
// the organization behind them without a dependency: a table of common
// two-label country suffixes and one of cloud and hosting suffixes where the
// customer's label, not the provider's, is the unit worth keeping. It
// returns "" for a name with no registrable part (a single label). The
// result is a sub-slice of host and allocates nothing.
func registrable(host string) string {
	i := strings.LastIndexByte(host, '.')
	if i <= 0 {
		return ""
	}
	// Walk label boundaries from the right, remembering where each starts.
	var starts [8]int // starts[k] = index where the (k+1)-th label from the right begins
	n := 0
	starts[n] = i + 1
	n++
	end := i
	for n < len(starts) {
		j := strings.LastIndexByte(host[:end], '.')
		starts[n] = j + 1
		n++
		if j < 0 {
			break
		}
		end = j
	}
	// labelsFromRight(k) is the name made of the last k labels.
	from := func(k int) string {
		if k > n {
			return ""
		}
		return host[starts[k-1]:]
	}
	two := from(2)
	if two == "" {
		return ""
	}
	// A private suffix (cloud/hosting) takes one more label: bucket.s3.amazonaws.com
	// becomes s3.amazonaws.com, never the customer's bucket name.
	for k := min(3, n); k >= 2; k-- {
		if _, ok := privateSuffixes[from(k)]; ok {
			if k+1 <= n {
				return from(k + 1)
			}
			return ""
		}
	}
	if _, ok := multiLabelSuffixes[two]; ok {
		if n >= 3 {
			return from(3)
		}
		return ""
	}
	return two
}

// multiLabelSuffixes are common public suffixes with two labels.
var multiLabelSuffixes = toSet(
	"co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "net.uk",
	"com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz", "net.nz",
	"co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "co.kr", "or.kr", "ne.kr",
	"com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "com.hk", "com.tw", "com.sg",
	"com.my", "com.ph", "com.vn", "com.br", "net.br", "org.br", "com.mx", "com.ar",
	"com.co", "com.pe", "com.tr", "co.in", "net.in", "org.in", "co.za", "co.il",
	"com.ua", "co.id", "or.id", "co.th", "in.th", "com.eg", "com.sa", "com.pk",
)

// privateSuffixes are cloud and hosting suffixes under which every customer
// has their own label.
var privateSuffixes = toSet(
	"amazonaws.com", "cloudfront.net", "elb.amazonaws.com", "azurewebsites.net",
	"blob.core.windows.net", "cloudapp.azure.com", "cloudapp.net", "trafficmanager.net",
	"appspot.com", "web.app", "firebaseapp.com", "herokuapp.com", "github.io", "gitlab.io",
	"pages.dev", "workers.dev", "netlify.app", "vercel.app", "ngrok.io", "ngrok-free.app",
	"edgekey.net", "akamaiedge.net", "akamaihd.net", "fastly.net", "azureedge.net",
	"googleusercontent.com", "r2.dev", "myshopify.com", "wpengine.com", "dyndns.org", "duckdns.org",
)

func toSet(items ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(items))
	for _, s := range items {
		m[s] = struct{}{}
	}
	return m
}
