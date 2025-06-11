// Package webspam provides a web-request URL handler to generate some
// attack specific error pages with known CVE/CWE references.
package webspam

import (
	"fmt"
	"net/http"
	"strings"
)

// CVEs is an evolving list of popular webspam attack requests.
var CVEs = map[string]string{
	"/cgi-bin/authLogin.cgi":                "CVE-2017-6361",
	"/_profiler/phpinfo":                    "CVE-2017-9841", // https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-016a
	"/config.json":                          "CVE-2019-6340",
	"/cgi-bin/luci/;stok=/locale":           "CVE-2023-1389",
	"/dana-na/auth/url_default/welcome.cgi": "CVE-2019-11510",
	"/wp-admin/admin-ajax.php":              "CVE-2024-2879",
	"/dns-query":                            "CVE-2024-12705",
}

// CVEPrefixes list some common  attempt requests.
var CVEPrefixes = map[string]string{
	"/.aws/":                   "CWE-200",
	"/.env.":                   "CWE-200",
	"/actuator/gateway/routes": "CVE-2022-22947",
	"/owa/":                    "CVE-2022-24637",
	"/public/index.php":        "CVE-2020-23376",
	"/wp-content/plugins/":     "CVE-2024-27956",
	"/dana-":                   "CVE-2021-22893",
}

// CWE200Suffixes list some common CWE-200 attempt requests.
var CWE200Suffixes = []string{
	"/.env",
	"/.git/config",
	"/.svn/entries",
	"/.aws/",
}

// CVE returns a known string token that can explain what the
// requester is attempting to do.
func CVE(path string) string {
	s, hit := CVEs[path]
	if hit {
		return s
	}
	for p, s := range CVEPrefixes {
		if strings.HasPrefix(path, p) {
			return s
		}
	}
	for _, s := range CWE200Suffixes {
		if strings.HasSuffix(path, s) {
			return "CWE-200"
		}
	}
	return ""
}

// SaySpam sets a dissatisfied response.
func SaySpam(w http.ResponseWriter, s string) {
	w.Header().Set("Retry-After", "82847")
	if s == "" {
		http.Error(w, "429 stop that", http.StatusTooManyRequests)
		return
	}
	http.Error(w, fmt.Sprint("429 spam detected (", s, ")"), http.StatusTooManyRequests)
}

// ErrorCVE is a handy way to intercept some common attack vectors.
func ErrorCVE(w http.ResponseWriter, r *http.Request) bool {
	if s := CVE(r.URL.Path); s != "" {
		SaySpam(w, s)
		return true
	}
	return false
}
