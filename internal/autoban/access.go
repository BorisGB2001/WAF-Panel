package autoban

import (
	"fmt"
	"path"
	"slices"
	"strings"
	"time"
)

// Access-log rules catch what the WAF does not see, from tengine's access
// logs: scanners probing for files (404 on pages), password guessing on
// login pages, floods. They are switched on and tried in dry run apart
// from the WAF rules, and share their escalation and durations.

// Request is one access log line.
type Request struct {
	Instance string
	Site     string // host name
	IP       string
	Method   string
	Path     string
	Status   int
	// GoodBot is a known search engine; banning one hurts the sites more
	// than its 404s.
	GoodBot bool
	Time    time.Time
}

// accessWin is what one address did within the access window.
type accessWin struct {
	notFound, logins, rate []time.Time
	last                   time.Time
}

// trim drops the times before cut.
func trim(ts []time.Time, cut time.Time) []time.Time {
	i := 0
	for i < len(ts) && ts[i].Before(cut) {
		i++
	}
	return ts[i:]
}

func (s *Settings) loginPage(p string) bool {
	p = strings.ToLower(p)
	return slices.ContainsFunc(s.LoginPaths, func(l string) bool { return strings.HasPrefix(p, strings.ToLower(l)) })
}

var assetExt = map[string]bool{".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true, ".svg": true,
	".ico": true, ".css": true, ".js": true, ".map": true, ".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
	".mp4": true, ".webm": true, ".mp3": true}

// IsAsset reports whether a path is an image, style, script or font: a
// missing one is a broken page, not a scanner.
func IsAsset(p string) bool { return assetExt[strings.ToLower(path.Ext(p))] }

// Access feeds one access log line; it returns a decision when the address
// crossed a line. Traps are checked too, so a trap also catches requests
// SafeLine did not record. Lines older than the window (a log read from
// its start) count towards nothing.
func (e *Engine) Access(r Request) *Decision {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.st.Settings
	if r.IP == "" || time.Since(r.Time) > max(s.AccessWindow, 10*time.Minute) {
		return nil
	}
	now := r.Time
	if d := e.trap(r.Instance, r.IP, r.Site, r.Method, r.Path, "", now); d != nil {
		return d
	}
	if !s.AccessEnabled || r.GoodBot || time.Since(r.Time) > s.AccessWindow {
		return nil
	}
	if last, ok := e.accessSeen[r.IP]; ok && now.Sub(last) < s.AccessWindow {
		return nil // decided on this address lately; dry run would repeat itself
	}
	w := e.access[r.IP]
	if w == nil {
		w = &accessWin{}
		e.access[r.IP] = w
	}
	w.last = now
	cut := now.Add(-s.AccessWindow)
	w.notFound, w.logins, w.rate = trim(w.notFound, cut), trim(w.logins, cut), trim(w.rate, now.Add(-time.Minute))
	if s.NotFound > 0 && r.Status == 404 && !IsAsset(r.Path) {
		w.notFound = append(w.notFound, now)
	}
	if s.Logins > 0 && r.Method == "POST" && s.loginPage(r.Path) {
		w.logins = append(w.logins, now)
	}
	if s.Rate > 0 {
		w.rate = append(w.rate, now)
	}
	var d Decision
	switch {
	case s.Logins > 0 && len(w.logins) >= s.Logins:
		d.Rule = fmt.Sprintf("%d login attempts in %s", s.Logins, s.AccessWindow)
		d.Reason = fmt.Sprintf("%d login attempts in %s, last POST %s", len(w.logins), s.AccessWindow, r.Path)
	case s.NotFound > 0 && len(w.notFound) >= s.NotFound:
		d.Rule = fmt.Sprintf("%d pages not found in %s", s.NotFound, s.AccessWindow)
		d.Reason = fmt.Sprintf("%d pages not found (404) in %s, last %s", len(w.notFound), s.AccessWindow, r.Path)
	case s.Rate > 0 && len(w.rate) >= s.Rate:
		d.Rule = fmt.Sprintf("%d requests a minute", s.Rate)
		d.Reason = fmt.Sprintf("%d requests in a minute, last %s %s", len(w.rate), r.Method, r.Path)
	default:
		e.gcAccess(now, s.AccessWindow)
		return nil
	}
	delete(e.access, r.IP)
	e.accessSeen[r.IP] = now
	n := e.offence(r.IP, now)
	d.Kind, d.Instance, d.IP, d.Site, d.At, d.Offence, d.Duration, d.DryRun = "access", r.Instance, r.IP, r.Site, now, n, duration(s, n), s.AccessDryRun
	d.Reason += " on " + r.Site
	return &d
}

// gcAccess drops addresses that went quiet, once there are many.
func (e *Engine) gcAccess(now time.Time, window time.Duration) {
	if len(e.access) < 20000 && len(e.accessSeen) < 20000 {
		return
	}
	for ip, w := range e.access {
		if now.Sub(w.last) > window {
			delete(e.access, ip)
		}
	}
	for ip, at := range e.accessSeen {
		if now.Sub(at) > window {
			delete(e.accessSeen, ip)
		}
	}
}
