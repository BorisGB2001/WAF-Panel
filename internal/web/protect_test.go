package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"wafpanel/internal/autoban"
	"wafpanel/internal/blocklist"
	"wafpanel/internal/safeline"
)

func TestProtection(t *testing.T) {
	fake := &statefulSafeLine{}
	ts, s, _ := newTestServerWith(t, fake)
	var err error
	if s.Autoban, err = autoban.Open(filepath.Join(s.Cfg.Web.DataDir, "autoban.json")); err != nil {
		t.Fatal(err)
	}
	c := browser(ts)
	pw, _ := os.ReadFile(filepath.Join(s.Cfg.Web.DataDir, "initial-admin-password"))
	login(t, ts, c, "admin", strings.TrimSpace(string(pw)))
	_, page := get(t, ts, c, "/waf")
	csrf := csrfRe.FindStringSubmatch(page)[1]
	post := func(path string, v url.Values) (int, string) {
		v.Set("csrf", csrf)
		resp, err := c.PostForm(ts.URL+path, v)
		if err != nil {
			t.Fatal(err)
		}
		loc := resp.Header.Get("Location")
		body(t, resp)
		return resp.StatusCode, loc
	}
	group := func(comment string) []string {
		for _, g := range fake.groups {
			if g.Comment == comment {
				return g.IPs
			}
		}
		return nil
	}

	// The allow list: its own group and allow rule; allowed addresses
	// cannot be blocked, and allowing a blocked address lifts the block.
	if code, _ := post("/waf/prod/allow", url.Values{"ip": {"198.51.100.20"}, "reason": {"office"}}); code != http.StatusSeeOther {
		t.Fatalf("allow: %d", code)
	}
	if !slices.Contains(group(blocklist.AllowComment), "198.51.100.20") || !slices.ContainsFunc(fake.policies, func(p safeline.Policy) bool { return p.Action == 0 && p.Name == blocklist.AllowPolicyName }) {
		t.Fatalf("allow list in SafeLine: %+v %+v", fake.groups, fake.policies)
	}
	if code, _ := post("/waf/prod/block", url.Values{"ip": {"198.51.100.20"}, "reason": {"x"}, "ttl": {"1h"}}); code != http.StatusBadRequest {
		t.Fatalf("blocked an allowed address: %d", code)
	}
	post("/waf/prod/block", url.Values{"ip": {"198.51.100.21"}, "reason": {"x"}, "ttl": {"1h"}})
	if !slices.Contains(group(blocklist.GroupComment), "198.51.100.21") {
		t.Fatal("not blocked")
	}
	post("/waf/prod/allow", url.Values{"ip": {"198.51.100.21"}, "reason": {"partner"}})
	if slices.Contains(group(blocklist.GroupComment), "198.51.100.21") || !slices.Contains(group(blocklist.AllowComment), "198.51.100.21") {
		t.Fatal("moving to the allow list kept the block")
	}
	post("/waf/prod/allow/remove", url.Values{"ip": {"198.51.100.21"}})
	if slices.Contains(group(blocklist.AllowComment), "198.51.100.21") {
		t.Fatal("not removed from the allow list")
	}

	// A private address is blocked by hand only when confirmed, never by
	// one click.
	if code, _ := post("/waf/prod/block", url.Values{"ip": {"10.1.2.3"}, "reason": {"x"}, "ttl": {"1h"}}); code != http.StatusBadRequest {
		t.Fatalf("private block without confirmation: %d", code)
	}
	if code, _ := post("/waf/prod/block", url.Values{"ip": {"10.1.2.3"}, "reason": {"x"}, "ttl": {"1h"}, "private": {"1"}}); code != http.StatusSeeOther {
		t.Fatalf("confirmed private block: %d", code)
	}
	if _, loc := post("/waf/prod/ban", url.Values{"ip": {"10.1.2.4"}, "ttl": {"0"}, "back": {"/attacks"}}); !strings.Contains(loc, "err=") {
		t.Fatalf("one-click ban of a private address: %s", loc)
	}
	if _, loc := post("/waf/prod/ban", url.Values{"ip": {"203.0.113.30"}, "ttl": {"0"}, "back": {"/attacks?period=7d"}}); !strings.HasPrefix(loc, "/attacks?period=7d&ok=") {
		t.Fatalf("one-click ban: %s", loc)
	}
	if m, _ := s.blocklist(s.Clients[0]).Meta("203.0.113.30"); !m.Expires.IsZero() || m.Reason != "one-click block" {
		t.Fatalf("one-click ban meta: %+v", m)
	}
	post("/waf/prod/expiry", url.Values{"ip": {"203.0.113.30"}, "ttl": {"7d"}})
	if m, _ := s.blocklist(s.Clients[0]).Meta("203.0.113.30"); m.Expires.IsZero() {
		t.Fatal("term not changed")
	}

	// Pages.
	for path, want := range map[string]string{
		"/ip/198.51.100.7":         "Latest attacks",
		"/ip/203.0.113.30":         "one-click block",
		"/analysis?period=24h":     "Top attackers",
		"/massban?by=type&value=0": "1 request(s) from 1 address(es)",
		"/autoban":                 "From SafeLine",
		"/traps?path=/backup.zip":  `value="/backup.zip"`,
		"/attacks":                 `action="/waf/prod/ban"`,
		"/waf":                     "Allow list",
	} {
		if code, page := get(t, ts, c, path); code != 200 || !strings.Contains(page, want) {
			t.Errorf("%s: %d, no %q", path, code, want)
		}
	}
	for q, want := range map[string]string{"198.51.100.7": "/ip/198.51.100.7", "/login": "/attacks?period=7d&url=%2Flogin", "shop.example.ru": "/attacks?period=7d&host=shop.example.ru"} {
		resp, _ := c.Get(ts.URL + "/search?q=" + url.QueryEscape(q))
		body(t, resp)
		if loc := resp.Header.Get("Location"); loc != want {
			t.Errorf("search %q: %s", q, loc)
		}
	}

	// Ban by attack.
	if code, _ := post("/massban", url.Values{"by": {"type"}, "value": {"0"}, "period": {"24h"}, "ip": {"198.51.100.7"}, "ttl": {"24h"}, "reason": {"sqli"}}); code != http.StatusSeeOther {
		t.Fatalf("mass ban: %d", code)
	}
	if m, _ := s.blocklist(s.Clients[0]).Meta("198.51.100.7"); m.Source != "massban" || m.Rule != "type SQL Injection" {
		t.Fatalf("mass ban meta: %+v", m)
	}

	// Traps: the defaults come with SafeLine rules that only record.
	post("/traps/defaults", url.Values{})
	traps := s.Autoban.Traps()
	if len(traps) != len(autoban.DefaultTraps) || traps[0].Policies["prod"] == 0 {
		t.Fatalf("default traps: %+v", traps)
	}
	rule := func(id int) *safeline.Policy {
		for i := range fake.policies {
			if fake.policies[i].ID == id {
				return &fake.policies[i]
			}
		}
		return nil
	}
	p := rule(traps[0].Policies["prod"])
	if p == nil || !p.Monitor || p.Action != 1 || p.Pattern[0][0].K != "uri_no_query" || p.Pattern[0][0].Op != "has" {
		t.Fatalf("trap rule: %+v", p)
	}
	post("/traps/1/dry_run", url.Values{"on": {"0"}})
	if p := rule(traps[0].Policies["prod"]); p.Monitor {
		t.Fatal("trap rule still in dry run")
	}
	post("/traps/1/delete", url.Values{})
	if rule(traps[0].Policies["prod"]) != nil || len(s.Autoban.Traps()) != len(autoban.DefaultTraps)-1 {
		t.Fatal("trap or its rule not deleted")
	}

	// Auto-ban decisions: applied, skipped for private addresses, only
	// recorded in dry run.
	ctx := context.Background()
	s.applyDecision(ctx, autoban.Decision{Instance: "prod", IP: "203.0.113.40", Kind: "threshold", Rule: "20 denied requests in 10m", Reason: "test", Duration: time.Hour, At: time.Now()})
	s.applyDecision(ctx, autoban.Decision{Instance: "prod", IP: "10.0.0.15", Kind: "threshold", At: time.Now()})
	s.applyDecision(ctx, autoban.Decision{Instance: "prod", IP: "203.0.113.41", Kind: "access", DryRun: true, At: time.Now()})
	got := map[string]string{}
	for _, d := range s.Autoban.Decisions() {
		got[d.IP] = d.Result
	}
	if got["203.0.113.40"] != "blocked" || got["10.0.0.15"] != "skipped: private network" || got["203.0.113.41"] != "would block" {
		t.Fatalf("decisions: %v", got)
	}
	if m, _ := s.blocklist(s.Clients[0]).Meta("203.0.113.40"); m.Source != "autoban" || m.By != "auto-ban" {
		t.Fatalf("auto-ban meta: %+v", m)
	}
	if slices.Contains(group(blocklist.GroupComment), "203.0.113.41") {
		t.Fatal("dry run blocked")
	}

	_, audit := get(t, ts, c, "/audit")
	for _, want := range []string{"waf.allow", "waf.massban", "trap.create", "trap.delete", "waf.block.autoban", "waf.block.term"} {
		if !strings.Contains(audit, want) {
			t.Errorf("audit has no %s", want)
		}
	}
}

func TestAllowFrom(t *testing.T) {
	ts, s, _ := newTestServer(t)
	s.Cfg.Web.AllowNets = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	h := httptest.NewTLSServer(s.Handler())
	defer h.Close()
	resp, err := h.Client().Get(h.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	if body(t, resp); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("outside allow_from: %d", resp.StatusCode)
	}
	s.Cfg.Web.AllowNets = append(s.Cfg.Web.AllowNets, netip.MustParsePrefix("127.0.0.0/8"))
	h2 := httptest.NewTLSServer(s.Handler())
	defer h2.Close()
	resp, _ = h2.Client().Get(h2.URL + "/login")
	if body(t, resp); resp.StatusCode != http.StatusOK {
		t.Fatalf("inside allow_from: %d", resp.StatusCode)
	}
	_ = ts
}
