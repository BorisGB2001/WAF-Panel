package web

import (
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"wafpanel/internal/config"
	"wafpanel/internal/history"
	"wafpanel/internal/safeline"
	"wafpanel/internal/stats"
)

type ruleSink struct{ got []config.Rule }

func (r *ruleSink) SetRules(rs []config.Rule) { r.got = rs }

func fakeSafeLine(t *testing.T) (*httptest.Server, string) {
	return tlsWithCA(t, readOnlySafeLine())
}

func tlsWithCA(t *testing.T, h http.Handler) (*httptest.Server, string) {
	srv := httptest.NewTLSServer(h)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	return srv, ca
}

func readOnlySafeLine() http.Handler {
	now := time.Now().Unix()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/open/health":
			w.Write([]byte(`{"status":"ok"}`))
		case r.URL.Path == "/api/open/records":
			w.Write([]byte(`{"err":null,"data":{"total":1,"data":[{"event_id":"ev1","src_ip":"198.51.100.7","host":"shop.example.ru","url_path":"/q?id=1'or 1=1","attack_type":0,"action":1,"risk_level":3,"timestamp":` + itoa(now) + `}]}}`))
		case r.URL.Path == "/api/open/record/ev1":
			w.Write([]byte(`{"err":null,"data":{"event_id":"ev1","src_ip":"198.51.100.7","host":"shop.example.ru","url_path":"/q","attack_type":"0","action":"1","timestamp":"` + itoa(now) + `","payload":"1'or 1=1","req_header":"GET /q HTTP/1.1\r\nHost: shop.example.ru"}}`))
		case r.URL.Path == "/api/stat/advance/access":
			w.Write([]byte(`{"err":null,"data":{"access":23491,"session":2503,"ip":3,"pv":461}}`))
		case r.URL.Path == "/api/stat/advance/error_status_code" && r.URL.Query().Get("upstream") == "true":
			w.Write([]byte(`{"err":null,"data":{"error_4xx":0,"error_5xx":1155}}`))
		case r.URL.Path == "/api/stat/advance/trend/access":
			w.Write([]byte(`{"err":null,"data":[{"time":1793286000,"count":10},{"time":1793289600,"count":20}]}`))
		case r.URL.Path == "/api/stat/qps":
			w.Write([]byte(`{"err":null,"data":{"nodes":[{"0.0.0.0:0":18,"time":"17:33:00"},{"0.0.0.0:0":11,"time":"17:33:05"}]}}`))
		case r.URL.Path == "/api/open/site":
			w.Write([]byte(`{"err":null,"data":{"data":[{"id":4,"server_names":["shop.example.ru"],"upstreams":["https://10.0.0.1"],"is_enabled":true,"mode":2,"title":"Shop"}]}}`))
		default:
			http.NotFound(w, r)
		}
	})
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func newTestServer(t *testing.T) (*httptest.Server, *Server, *ruleSink) {
	return newTestServerWith(t, readOnlySafeLine())
}

func newTestServerWith(t *testing.T, h http.Handler) (*httptest.Server, *Server, *ruleSink) {
	sl, ca := tlsWithCA(t, h)
	t.Cleanup(sl.Close)
	dir := t.TempDir()
	cfg := &config.Config{
		Instances: []config.Instance{{ID: "prod", Name: "Prod", BaseURL: sl.URL, Token: "x", CAFile: ca, Timeout: config.Duration(5 * time.Second)}},
		Channels:  []config.Channel{{Name: "tg", Type: "telegram", Telegram: &config.Telegram{ChatID: "1"}}},
		Web:       config.Web{DataDir: dir, SessionTTL: config.Duration(time.Hour)},
	}
	c, err := safeline.New(cfg.Instances[0])
	if err != nil {
		t.Fatal(err)
	}
	hist, _ := history.Open(filepath.Join(dir, "h.jsonl"), 100)
	sink := &ruleSink{}
	s := &Server{Cfg: cfg, Clients: []*safeline.Client{c}, Stats: stats.New(), History: hist, Rules: sink,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Version: "test", RuleFile: filepath.Join(dir, "rules.yaml")}
	if err := s.Open(nil); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewTLSServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts, s, sink
}

// browser is a separate client with its own cookies; ts.Client() returns
// the same shared client every time.
func browser(ts *httptest.Server) *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Transport:     ts.Client().Transport,
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func body(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return string(b)
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func login(t *testing.T, ts *httptest.Server, c *http.Client, user, pw string) {
	t.Helper()
	resp, err := c.PostForm(ts.URL+"/login", url.Values{"username": {user}, "password": {pw}, "next": {"/"}})
	if err != nil {
		t.Fatal(err)
	}
	body(t, resp)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login %s: status %d", user, resp.StatusCode)
	}
}

func get(t *testing.T, ts *httptest.Server, c *http.Client, path string) (int, string) {
	t.Helper()
	resp, err := c.Get(ts.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, body(t, resp)
}

func TestPanel(t *testing.T) {
	ts, s, sink := newTestServer(t)
	c := browser(ts)

	if code, _ := get(t, ts, c, "/"); code != http.StatusSeeOther {
		t.Fatalf("anonymous dashboard: %d", code)
	}
	resp, _ := c.PostForm(ts.URL+"/login", url.Values{"username": {"admin"}, "password": {"wrong-password"}})
	if body(t, resp); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", resp.StatusCode)
	}
	pw, _ := os.ReadFile(filepath.Join(s.Cfg.Web.DataDir, "initial-admin-password"))
	login(t, ts, c, "admin", strings.TrimSpace(string(pw)))

	for path, want := range map[string]string{
		"/":                 "Attacks in 24 h",
		"/attacks":          "198.51.100.7",
		"/attacks/prod/ev1": "1&#39;or 1=1",
		"/alerts":           "No alerts yet",
		"/rules":            "Rule editor",
		"/channels":         "chat_id 1",
		"/users":            "admin",
		"/audit":            "login.failed",
		"/account":          "Change password",
		"/attacks.csv":      "ev1",
		"/stats":            "23491",
		"/stats/qps":        "17:33:05",
	} {
		code, b := get(t, ts, c, path)
		if code != http.StatusOK || !strings.Contains(b, want) {
			t.Errorf("%s: status %d, %q not found", path, code, want)
		}
	}
	_, page := get(t, ts, c, "/rules")
	csrf := csrfRe.FindStringSubmatch(page)[1]

	// Missing CSRF token.
	resp, _ = c.PostForm(ts.URL+"/rules", url.Values{"yaml": {"[]"}})
	if body(t, resp); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("rules without csrf: %d", resp.StatusCode)
	}
	// Unknown channel is rejected and nothing is applied.
	resp, _ = c.PostForm(ts.URL+"/rules", url.Values{"csrf": {csrf}, "yaml": {"- name: x\n  channels: [nope]\n"}})
	if b := body(t, resp); resp.StatusCode != http.StatusBadRequest || !strings.Contains(b, "unknown channel") || sink.got != nil {
		t.Fatalf("bad rules: %d", resp.StatusCode)
	}
	resp, _ = c.PostForm(ts.URL+"/rules", url.Values{"csrf": {csrf}, "yaml": {"- name: burst\n  threshold: 5\n  window: 1m\n  channels: [tg]\n"}})
	if body(t, resp); resp.StatusCode != http.StatusSeeOther || len(sink.got) != 1 || sink.got[0].Cooldown.D() != time.Minute {
		t.Fatalf("save rules: %d %+v", resp.StatusCode, sink.got)
	}
	if b, _ := os.ReadFile(s.RuleFile); !strings.Contains(string(b), "burst") {
		t.Fatal("rules file not written")
	}

	// A viewer reads but cannot change anything.
	resp, _ = c.PostForm(ts.URL+"/users", url.Values{"csrf": {csrf}, "name": {"viewer1"}, "role": {"viewer"}, "password": {"viewer-password-1"}})
	if b := body(t, resp); !strings.Contains(b, "User viewer1 created") {
		t.Fatalf("add user: %d", resp.StatusCode)
	}
	v := browser(ts)
	login(t, ts, v, "viewer1", "viewer-password-1")
	if code, _ := get(t, ts, v, "/attacks"); code != http.StatusOK {
		t.Fatalf("viewer attacks: %d", code)
	}
	if code, _ := get(t, ts, v, "/users"); code != http.StatusForbidden {
		t.Fatalf("viewer users: %d", code)
	}
	_, vp := get(t, ts, v, "/rules")
	if strings.Contains(vp, "Rule editor") {
		t.Fatal("viewer sees the rule editor")
	}
	vcsrf := csrfRe.FindStringSubmatch(vp)[1]
	resp, _ = v.PostForm(ts.URL+"/rules", url.Values{"csrf": {vcsrf}, "yaml": {"[]"}})
	if body(t, resp); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer saved rules: %d", resp.StatusCode)
	}

	// Changing the role ends the viewer's sessions.
	resp, _ = c.PostForm(ts.URL+"/users/viewer1/role", url.Values{"csrf": {csrf}, "role": {"admin"}})
	if b := body(t, resp); !strings.Contains(b, "Role of viewer1 changed") {
		t.Fatalf("role change: %d %s", resp.StatusCode, b[:min(len(b), 300)])
	}
	if code, _ := get(t, ts, v, "/attacks"); code != http.StatusSeeOther {
		t.Fatalf("old session still valid after role change: %d", code)
	}
}

func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{"/attacks?ip=1": "/attacks?ip=1", "//evil.com": "/", "https://evil.com": "/", "/\\evil": "/"} {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q", in, got)
		}
	}
}

func TestCertLoader(t *testing.T) {
	cert, key, err := selfSigned(filepath.Join(t.TempDir(), "tls"))
	if err != nil {
		t.Fatal(err)
	}
	cl := &certLoader{cert: cert, key: key}
	c1, err := cl.get(nil)
	if err != nil || c1 == nil {
		t.Fatalf("load: %v", err)
	}
	// A broken file after a successful load keeps serving the old certificate.
	os.WriteFile(cert, []byte("broken"), 0o644)
	cl.checked = time.Time{}
	if c2, err := cl.get(nil); err != nil || c2 != c1 {
		t.Fatalf("broken renewal replaced the certificate: %v", err)
	}
}

func TestLanguageSwitch(t *testing.T) {
	ts, s, _ := newTestServer(t)
	c := browser(ts)
	pw, _ := os.ReadFile(filepath.Join(s.Cfg.Web.DataDir, "initial-admin-password"))
	login(t, ts, c, "admin", strings.TrimSpace(string(pw)))
	if _, b := get(t, ts, c, "/attacks"); !strings.Contains(b, "Attack log") || !strings.Contains(b, `lang="en"`) {
		t.Fatal("English is not the default")
	}
	if code, _ := get(t, ts, c, "/lang/ru?next=/attacks"); code != http.StatusSeeOther {
		t.Fatalf("switch: %d", code)
	}
	if _, b := get(t, ts, c, "/attacks"); !strings.Contains(b, "Журнал атак") || !strings.Contains(b, "SQL-инъекция") {
		t.Fatal("Russian not applied")
	}
	if code, _ := get(t, ts, c, "/lang/de"); code != http.StatusNotFound {
		t.Fatal("unknown language accepted")
	}
	if _, loc := get(t, ts, c, "/lang/en?next=//evil.example"); strings.Contains(loc, "evil") {
		t.Fatal("open redirect")
	}
}

func TestThemeSwitch(t *testing.T) {
	ts, s, _ := newTestServer(t)
	c := browser(ts)
	pw, _ := os.ReadFile(filepath.Join(s.Cfg.Web.DataDir, "initial-admin-password"))
	login(t, ts, c, "admin", strings.TrimSpace(string(pw)))
	// The switches come back to the page they were used on, without its flash.
	_, b := get(t, ts, c, "/attacks?period=7d&ok=done")
	if strings.Contains(b, "data-theme=") || !strings.Contains(b, `href="/theme/dark?next=%2Fattacks%3Fperiod%3D7d"`) ||
		!strings.Contains(b, `href="/lang/ru?next=%2Fattacks%3Fperiod%3D7d"`) {
		t.Fatal("system theme by default, switches return to this page")
	}
	for theme, want := range map[string]string{"dark": `data-theme="dark"`, "light": `data-theme="light"`, "system": ""} {
		resp, err := c.Get(ts.URL + "/theme/" + theme + "?next=/attacks")
		if err != nil {
			t.Fatal(err)
		}
		body(t, resp)
		if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusSeeOther || loc != "/attacks" {
			t.Fatalf("%s: %d %s", theme, resp.StatusCode, loc)
		}
		_, b := get(t, ts, c, "/attacks")
		if (want == "" && strings.Contains(b, "data-theme=")) || (want != "" && !strings.Contains(b, want)) {
			t.Errorf("%s not applied", theme)
		}
	}
	if code, _ := get(t, ts, c, "/theme/pink"); code != http.StatusNotFound {
		t.Fatal("unknown theme accepted")
	}
}
