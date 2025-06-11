package webspam

import (
	"bytes"
	"net/http"
	"net/url"
	"testing"
)

func TestCVE(t *testing.T) {
	ses := map[string]string{
		"/.git/config":                "CWE-200",
		"/blah/blah/.svn/entries":     "CWE-200",
		"/static../.git/config":       "CWE-200",
		"/site/.env":                  "CWE-200",
		"/":                           "",
		"/cgi-bin/luci/;stok=/locale": "CVE-2023-1389",
	}
	for p, want := range ses {
		if got := CVE(p); got != want {
			t.Errorf("%q -> got=%q, want=%q", p, got, want)
		}
	}
}

type testHeader struct {
	kv   map[string][]string
	b    bytes.Buffer
	code int
}

func (t *testHeader) Header() http.Header {
	if t.kv == nil {
		t.kv = make(map[string][]string)
	}
	return http.Header(t.kv)
}

func (t *testHeader) Write(d []byte) (int, error) {
	return t.b.Write(d)
}

func (t *testHeader) WriteHeader(code int) {
	t.code = code
}

func TestError(t *testing.T) {
	ses := map[string]string{
		"/site/.env":                  "429 spam detected (CWE-200)\n",
		"/cgi-bin/luci/;stok=/locale": "429 spam detected (CVE-2023-1389)\n",
	}
	for p, want := range ses {
		w := &testHeader{}
		r := &http.Request{}
		var err error
		r.URL, err = url.Parse("https://zappem.net" + p)
		if err != nil {
			t.Fatalf("bad test vector path %q: %v", p, err)
		}
		if spam := ErrorCVE(w, r); spam {
			if w.code != http.StatusTooManyRequests {
				t.Errorf("status code: got=%d want=%d", w.code, http.StatusTooManyRequests)
			}
			if got := w.b.String(); got != want {
				t.Errorf("response got=%q, want=%q", got, want)
			}
		} else if want != "" {
			t.Errorf("failed to find %q as spam: want=%q", p, want)
		}
	}
}
