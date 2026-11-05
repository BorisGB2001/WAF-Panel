package autoban

import (
	"path/filepath"
	"testing"
	"time"
)

func open(t *testing.T) *Engine {
	e, err := Open(filepath.Join(t.TempDir(), "autoban.json"))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestThresholdAndEscalation(t *testing.T) {
	e := open(t)
	s := e.Settings()
	s.Enabled, s.Threshold = true, 3
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	e.SetSettings(s)
	now := time.Now()
	hit := func(at time.Time) *Decision {
		return e.Process(Hit{Instance: "prod", IP: "203.0.113.5", Host: "shop.example.com", Path: "/x", Denied: true, Type: 0, Risk: 1, Time: at})
	}
	if hit(now) != nil || hit(now.Add(time.Second)) != nil {
		t.Fatal("decided too early")
	}
	// Passed records do not count.
	if e.Process(Hit{IP: "203.0.113.5", Time: now}) != nil {
		t.Fatal("a passed record counted")
	}
	d := hit(now.Add(2 * time.Second))
	if d == nil || d.Kind != "threshold" || d.Offence != 1 || d.Duration != 24*time.Hour || !d.DryRun || d.Instance != "prod" {
		t.Fatalf("%+v", d)
	}
	d.Result = "blocked"
	e.Record(*d)
	for i := range 2 {
		hit(now.Add(time.Duration(10+i) * time.Second))
	}
	if d := hit(now.Add(15 * time.Second)); d == nil || d.Offence != 2 || d.Duration != 7*24*time.Hour {
		t.Fatalf("second offence: %+v", d)
	}
	// Old hits fall out of the window.
	e.Process(Hit{IP: "198.51.100.1", Denied: true, Time: now.Add(-time.Hour)})
	e.Process(Hit{IP: "198.51.100.1", Denied: true, Time: now.Add(-time.Hour)})
	if d := e.Process(Hit{IP: "198.51.100.1", Denied: true, Time: now}); d != nil {
		t.Fatalf("window ignored: %+v", d)
	}
}

func TestInstant(t *testing.T) {
	e := open(t)
	s := e.Settings()
	s.Enabled = true
	e.SetSettings(s)
	if d := e.Process(Hit{IP: "203.0.113.9", Denied: true, Type: 7, Risk: 1, Time: time.Now()}); d != nil {
		t.Fatal("low risk blocked at once")
	}
	if d := e.Process(Hit{IP: "203.0.113.9", Denied: true, Type: 7, Risk: 3, Time: time.Now(), EventID: "e1"}); d == nil || d.Kind != "instant" || len(d.Samples) != 1 {
		t.Fatalf("%+v", d)
	}
}

func TestTraps(t *testing.T) {
	e := open(t)
	if _, err := e.AddTrap(Trap{Path: "/", Match: "prefix"}); err == nil {
		t.Fatal("home page accepted as a trap")
	}
	tr, err := e.AddTrap(Trap{Path: "/.env", Match: "part", Enabled: true, Duration: 0})
	if err != nil || tr.ID != 1 {
		t.Fatal(tr, err)
	}
	if _, err := e.AddTrap(Trap{Path: "/.env", Match: "part"}); err == nil {
		t.Fatal("duplicate trap")
	}
	// A trap fires with the auto-ban off and on a passed request.
	d := e.Process(Hit{Instance: "prod", IP: "203.0.113.7", Host: "a.example.com", Path: "/app/.env.bak", Time: time.Now()})
	if d == nil || d.Kind != "trap" || d.Trap != 1 || d.DryRun || d.Duration != 0 {
		t.Fatalf("%+v", d)
	}
	// Once an hour per address and trap, from the access logs too.
	if d := e.Access(Request{IP: "203.0.113.7", Site: "a.example.com", Path: "/.env", Time: time.Now()}); d != nil {
		t.Fatal("repeated within the hour")
	}
	if tr, _ := e.Trap(1); tr.Hits != 2 {
		t.Fatalf("hits %d", tr.Hits)
	}
	e.UpdateTrap(1, func(t *Trap) { t.Enabled = false })
	if d := e.Process(Hit{IP: "203.0.113.8", Path: "/.env", Time: time.Now()}); d != nil {
		t.Fatal("disabled trap fired")
	}
	site := Trap{Site: "b.example.com", Path: "/admin", Match: "prefix", Enabled: true}
	if !site.Matches("B.example.com", "/Admin/x?y") || site.Matches("a.example.com", "/admin") {
		t.Fatal("site trap")
	}
	// The state survives a restart.
	e2, _ := Open(e.File)
	if len(e2.Traps()) != 1 || e2.st.NextTrap != 2 {
		t.Fatal("traps not saved")
	}
}

func TestAccess(t *testing.T) {
	e := open(t)
	s := e.Settings()
	s.AccessEnabled, s.NotFound, s.Logins = true, 5, 3
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	e.SetSettings(s)
	now := time.Now()
	req := func(ip, method, path string, status int, bot bool) *Decision {
		return e.Access(Request{Instance: "prod", Site: "shop.example.com", IP: ip, Method: method, Path: path, Status: status, GoodBot: bot, Time: now})
	}
	for range 10 {
		if d := req("203.0.113.1", "GET", "/img/x.png", 404, false); d != nil {
			t.Fatal("missing images count")
		}
		if d := req("66.249.66.1", "GET", "/old-page", 404, true); d != nil {
			t.Fatal("search engine banned")
		}
	}
	var d *Decision
	for i := range 5 {
		d = req("203.0.113.2", "GET", "/backup"+string(rune('a'+i)), 404, false)
	}
	if d == nil || d.Kind != "access" || !d.DryRun || d.Source() != "access" {
		t.Fatalf("404: %+v", d)
	}
	req("203.0.113.3", "POST", "/wp-login.php", 200, false)
	req("203.0.113.3", "POST", "/wp-login.php", 200, false)
	if d := req("203.0.113.3", "POST", "/wp-login.php", 200, false); d == nil || d.Rule != "3 login attempts in 5m0s" {
		t.Fatalf("login: %+v", d)
	}
	// Old lines from a backfill never decide.
	if d := e.Access(Request{IP: "203.0.113.4", Path: "/x", Status: 404, Time: now.Add(-time.Hour)}); d != nil {
		t.Fatal("old line decided")
	}
}
