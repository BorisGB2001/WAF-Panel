package analytics

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const sample = `10.0.22.15 | - | 30/Oct/2026:20:00:57 +0300 | "im.example.com" | "GET /plugins/playbooks/api/v0/runs?page=0&team_id=pb1941cgo78qjjbuencdawwtew HTTP/1.1" | 200 | 93 | "-" | "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.7339.249 Electron/38.7.2 Safari/537.36 Mattermost/6.0.4"`

func TestParseAccess(t *testing.T) {
	a, err := ParseAccess(sample)
	if err != nil {
		t.Fatal(err)
	}
	if a.IP != "10.0.22.15" || a.Host != "im.example.com" || a.Method != "GET" || a.Path != "/plugins/playbooks/api/v0/runs" ||
		a.Status != 200 || a.Bytes != 93 || a.Referer != "" || a.Time.Hour() != 20 || a.Time.Format("-0700") != "+0300" {
		t.Fatalf("%+v", a)
	}
	// A separator inside the user agent and a garbage request line.
	a, err = ParseAccess(`203.0.113.9 | - | 30/Oct/2026:20:00:57 +0300 | "x.example.com" | "\x16\x03\x01" | 400 | 150 | "https://ref.example.org/a?b" | "odd | agent"`)
	if err != nil || a.UA != "odd | agent" || a.Method != "-" || a.Status != 400 || a.Referer != "https://ref.example.org/a?b" {
		t.Fatalf("%+v %v", a, err)
	}
	for _, bad := range []string{"", "garbage", `1.2.3.4 - - [30/Oct/2026:20:00:57 +0300] "GET / HTTP/1.1" 200 1`} {
		if _, err := ParseAccess(bad); err == nil {
			t.Errorf("parsed %q", bad)
		}
	}
}

func TestParseError(t *testing.T) {
	e, ok := ParseError(`2026/10/30 16:25:06 [error] 68#0: *406639 upstream timed out (110: Connection timed out) while reading response header from upstream, client: 10.0.22.15, server: im.example.com, request: "GET /api/v4/x HTTP/1.1", upstream: "https://10.0.0.12:443/api/v4/x", host: "im.example.com"`)
	if !ok || e.Kind != "timeout" || e.Server != "im.example.com" || e.Upstream != "10.0.0.12:443" || e.Client != "10.0.22.15" {
		t.Fatalf("%+v %v", e, ok)
	}
	if _, ok := ParseError(`2026/10/30 16:25:06 [warn] 68#0: *1 an upstream response is buffered to a temporary file`); ok {
		t.Fatal("warnings are not upstream errors")
	}
}

func TestParseUA(t *testing.T) {
	for ua, want := range map[string]Client{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.7339.249 Electron/38.7.2 Safari/537.36 Mattermost/6.0.4": {OS: "Windows 10/11", Client: "Mattermost Desktop 6.0"},
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15":                                 {OS: "macOS", Client: "Safari 18"},
		"Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0":                                                                                {OS: "Linux", Client: "Firefox 131"},
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0":                         {OS: "Windows 10/11", Client: "Edge 130"},
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)":                                                                              {OS: "Other OS", Client: "Other browser", Bot: "Googlebot"},
		"curl/8.5.0": {OS: "Other OS", Client: "curl"},
		"":           {OS: "Unknown", Client: "No User-Agent"},
	} {
		if got := ParseUA(ua); got != want {
			t.Errorf("%q: %+v, want %+v", ua, got, want)
		}
	}
	if Family("Chrome 140") != "Chrome" || Family("Mattermost Desktop 6.0") != "Mattermost Desktop" || Family("curl") != "curl" {
		t.Error("Family")
	}
}

func TestNormalizePath(t *testing.T) {
	for in, want := range map[string]string{
		"/api/v4/users/rs8dhio4d7da7k9kish8hwdpka/status": "/api/v4/users/:id/status",
		"/api/v4/notifications":                           "/api/v4/notifications",
		"/static/files/9ea8998d9c0389f02c43.png":          "/static/files/:id.png",
		"/orders/12345":                                   "/orders/:id",
		"/x/550e8400-e29b-41d4-a716-446655440000":         "/x/:id",
		"/a/b/c/d/e/f/g/h":                                "/a/b/c/d/e/f/…",
		"*":                                               "(invalid)",
	} {
		if got := NormalizePath(in); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}

func TestHLL(t *testing.T) {
	var a, b HLL
	for i := 0; i < 50000; i++ {
		a.Add(fmt.Sprint("10.0.", i))
		if i%2 == 0 {
			b.Add(fmt.Sprint("10.0.", i)) // overlaps a
		}
		b.Add(fmt.Sprint("192.168.", i))
	}
	a.Merge(&b)
	if n := a.Count(); n < 97000 || n > 103000 {
		t.Fatalf("estimate %d for 100000", n)
	}
	var small HLL
	for i := 0; i < 10; i++ {
		small.Add("same")
		small.Add(fmt.Sprint(i))
	}
	if n := small.Count(); n != 11 {
		t.Fatalf("small set: %d", n)
	}
}

func logLine(t time.Time, ip, path string, status int) string {
	return fmt.Sprintf(`%s | - | %s | "shop.example.com" | "GET %s HTTP/1.1" | %d | 100 | "https://www.google.com/" | "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"`+"\n",
		ip, t.Format("02/Jan/2006:15:04:05 -0700"), path, status)
}

func TestCollectorAndStore(t *testing.T) {
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	os.MkdirAll(logs, 0o755)
	now := time.Now()
	old := now.AddDate(0, 0, -4)
	// A rotated file from four days ago and the current one.
	os.WriteFile(filepath.Join(logs, "accesslog_4_20261027_19_23"), []byte(logLine(old, "198.51.100.1", "/old", 200)), 0o644)
	cur := filepath.Join(logs, "accesslog_4")
	os.WriteFile(cur, []byte(logLine(now, "198.51.100.2", "/a/1", 200)+logLine(now, "198.51.100.3", "/a/2", 502)+"partial"), 0o644)
	errLog := filepath.Join(logs, "error.log")
	os.WriteFile(errLog, []byte(now.Format("2006/01/02 15:04:05")+` [error] 1#0: *1 upstream timed out (110), client: 1.2.3.4, server: shop.example.com, request: "GET / HTTP/1.1", upstream: "http://10.0.0.5:80/", host: "shop.example.com"`+"\n"), 0o644)

	st := &Store{Dir: filepath.Join(dir, "data"), Retention: 90 * 24 * time.Hour}
	c := &Collector{AccessDir: logs, ErrorLog: errLog, Store: st, Backfill: true, Log: slog.New(slog.DiscardHandler),
		SiteOf: func(s string) string {
			if s == "shop.example.com" {
				return "4"
			}
			return ""
		}}
	c.loadCursors()
	c.backfill()
	c.pass()
	if s := c.Status(); s.Lines != 3 || s.ErrLines != 1 || len(s.Sites) != 1 {
		t.Fatalf("status %+v", s)
	}
	q := st.Query(nil, now.Add(-24*time.Hour), now.Add(time.Hour))
	if q.N != 2 || q.E5 != 1 || q.Paths["GET /a/:id"].N != 2 || q.UpErr["timeout"] != 1 || q.Referrers["www.google.com"] != 2 || q.UniqIPs.Count() != 2 {
		t.Fatalf("24h: %+v", q)
	}
	if q.Countries[Private+"|"] != 0 || q.Countries[Unknown+"|"] != 2 {
		t.Fatalf("countries without a database: %v", q.Countries)
	}

	// Rotation: the rest of the old file, then the new one.
	f, _ := os.OpenFile(cur, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(" line is ignored\n")
	f.WriteString(logLine(now, "198.51.100.4", "/b", 404))
	f.Close()
	os.Rename(cur, filepath.Join(logs, "accesslog_4_20261030_20_00"))
	os.WriteFile(cur, []byte(logLine(now, "198.51.100.5", "/c", 200)), 0o644)
	c.pass()
	q = st.Query([]string{"4"}, now.Add(-24*time.Hour), now.Add(time.Hour))
	if q.N != 4 || q.E4 != 1 || c.Status().Skipped != 1 {
		t.Fatalf("after rotation: n=%d e4=%d skipped=%d", q.N, q.E4, c.Status().Skipped)
	}

	// 30 days include the backfilled day; a restart keeps everything.
	if err := st.Flush(); err != nil {
		t.Fatal(err)
	}
	c.saveCursors()
	st2 := &Store{Dir: st.Dir, Retention: st.Retention}
	if err := st2.Load(); err != nil {
		t.Fatal(err)
	}
	q = st2.Query(nil, now.AddDate(0, 0, -30), now.Add(time.Hour))
	if q.N != 5 || q.Paths["GET /old"] == nil || len(q.Series) < 2 {
		t.Fatalf("30d after restart: n=%d paths=%v series=%d", q.N, q.Paths, len(q.Series))
	}
	c2 := &Collector{AccessDir: logs, Store: st2, Log: c.Log}
	if !c2.loadCursors() {
		t.Fatal("cursors not saved")
	}
	c2.pass()
	if c2.Status().Lines != 0 {
		t.Fatal("lines read twice after a restart")
	}
}
