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
	"/cgi-bin/luci/;stok=/locale": "CVE-2023-1389",
	"/cgi-bin/authLogin.cgi":      "CVE-2017-6361",
	"/config.json":                "CVE-2019-6340",
}

// CVEPrefixes list some common  attempt requests.
var CVEPrefixes = map[string]string{
	"/.aws/":                   "CWE-200",
	"/actuator/gateway/routes": "CVE-2022-22947",
	"/owa/":                    "CVE-2022-24637",
	"/public/index.php":        "CVE-2020-23376",
	"/wp-content/plugins/":     "CVE-2024-27956",
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

// ErrorCVE is a handy way to intercept some common attack vectors.
func ErrorCVE(w http.ResponseWriter, r *http.Request) bool {
	s := CVE(r.URL.Path)
	if s != "" {
		http.Error(w, fmt.Sprint("404 page not found (", s, ")"), http.StatusNotFound)
		return true
	}
	return false
}
