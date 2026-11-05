// Package autoban decides which addresses to block without a person: those
// that keep attacking (too many denied requests within a window, or one
// request of a dangerous attack type), those that fall into a trap path,
// and, from tengine's access logs, those that hit many missing pages, keep
// posting to login pages or flood a site. Every new offence of the same
// address blocks it for longer (a day, a week, then for good). Each kind
// of rule has its own dry run, in which it only records whom it would
// block. The caller applies the decisions; the engine never talks to
// SafeLine.
package autoban

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"wafpanel/internal/auth"
	"wafpanel/internal/i18n"
)

// Settings are edited in the panel and kept with the engine's state.
type Settings struct {
	Enabled bool `json:"enabled"`
	// DryRun records decisions without blocking.
	DryRun bool `json:"dry_run"`
	// Threshold denied requests from one address within Window.
	Threshold int           `json:"threshold"`
	Window    time.Duration `json:"window"`
	// Instant attack types block on a single denied request with at least
	// InstantRisk (1 low, 2 medium, 3 high).
	Instant     []int `json:"instant"`
	InstantRisk int   `json:"instant_risk"`
	// Durations by offence: the first offence gets Durations[0], ...; the
	// last one repeats. 0 blocks until unblocked by hand.
	Durations []time.Duration `json:"durations"`
	// Memory is how long past offences count for escalation.
	Memory time.Duration `json:"memory"`

	// Access-log rules, on and in dry run apart from the WAF rules. A
	// limit of 0 turns that rule off.
	AccessEnabled bool          `json:"access_enabled"`
	AccessDryRun  bool          `json:"access_dry_run"`
	AccessWindow  time.Duration `json:"access_window"`
	NotFound      int           `json:"not_found"` // 404s on pages (not images, styles, scripts) within AccessWindow
	Logins        int           `json:"logins"`    // POSTs to LoginPaths within AccessWindow
	Rate          int           `json:"rate"`      // requests within one minute
	LoginPaths    []string      `json:"login_paths"`
}

// DefaultInstant are SafeLine's attack types that block on the first
// denied request: backdoor, deserialization, code execution and command
// injection.
var DefaultInstant = []int{5, 6, 7, 9}

// DefaultLoginPaths are the sign-in pages of common applications; a path
// matches when it starts with one of them.
var DefaultLoginPaths = []string{"/wp-login.php", "/xmlrpc.php", "/administrator/index.php", "/bitrix/admin/",
	"/user/login", "/admin/login", "/login", "/api/v4/users/login"}

func Defaults() Settings {
	return Settings{
		DryRun: true, Threshold: 20, Window: 10 * time.Minute,
		Instant: slices.Clone(DefaultInstant), InstantRisk: 2,
		Durations:    []time.Duration{24 * time.Hour, 7 * 24 * time.Hour, 0},
		Memory:       90 * 24 * time.Hour,
		AccessDryRun: true, AccessWindow: 5 * time.Minute, NotFound: 30, Logins: 10, Rate: 600,
		LoginPaths: slices.Clone(DefaultLoginPaths),
	}
}

func (s *Settings) Validate() error {
	if s.Threshold < 2 || s.Threshold > 10000 {
		return i18n.Errorf("The threshold must be between 2 and 10000")
	}
	if s.Window < time.Minute || s.Window > 24*time.Hour {
		return i18n.Errorf("The window must be between 1 minute and 24 hours")
	}
	if len(s.Durations) == 0 || len(s.Durations) > 5 {
		return i18n.Errorf("Give 1 to 5 block durations")
	}
	for _, d := range s.Durations {
		if d < 0 || (d > 0 && d < time.Minute) {
			return i18n.Errorf("A block duration must be at least 1 minute, or 0 for permanent")
		}
	}
	if s.InstantRisk < 1 || s.InstantRisk > 3 {
		return i18n.Errorf("The risk level must be 1, 2 or 3")
	}
	if s.Memory < 24*time.Hour {
		s.Memory = 90 * 24 * time.Hour
	}
	if s.AccessWindow < time.Minute || s.AccessWindow > 24*time.Hour {
		return i18n.Errorf("The access log window must be between 1 minute and 24 hours")
	}
	if s.NotFound != 0 && (s.NotFound < 5 || s.NotFound > 100000) {
		return i18n.Errorf("The 404 limit must be 0 (off) or between 5 and 100000")
	}
	if s.Logins != 0 && (s.Logins < 3 || s.Logins > 100000) {
		return i18n.Errorf("The login attempt limit must be 0 (off) or between 3 and 100000")
	}
	if s.Rate != 0 && (s.Rate < 60 || s.Rate > 1000000) {
		return i18n.Errorf("The request rate limit must be 0 (off) or between 60 and 1000000 a minute")
	}
	if len(s.LoginPaths) > 30 {
		return i18n.Errorf("Give at most 30 login pages")
	}
	for _, p := range s.LoginPaths {
		if !strings.HasPrefix(p, "/") || len(p) > 200 || strings.ContainsAny(p, " \t\"'<>") {
			return i18n.Errorf("A login page is a path starting with /: %q", p)
		}
	}
	if s.AccessEnabled && s.NotFound == 0 && s.Logins == 0 && s.Rate == 0 {
		return i18n.Errorf("The access log rules are on but every limit is 0")
	}
	return nil
}

// Hit is one attack record of SafeLine.
type Hit struct {
	Instance string
	IP       string
	Host     string
	Method   string
	Path     string
	Denied   bool
	Type     int
	Risk     int
	EventID  string
	Time     time.Time
}

// Decision is one address the engine blocked or would block.
type Decision struct {
	Instance string        `json:"instance"`
	IP       string        `json:"ip"`
	Site     string        `json:"site"`
	At       time.Time     `json:"at"`
	Offence  int           `json:"offence"` // 1 for the first
	Duration time.Duration `json:"duration"`
	Reason   string        `json:"reason"`
	DryRun   bool          `json:"dry_run"`
	// Kind is "threshold", "instant", "trap" or "access"; Rule says which
	// rule fired in words, e.g. "20 denied requests in 10m".
	Kind string `json:"kind"`
	Rule string `json:"rule"`
	Trap int    `json:"trap,omitempty"`
	// Result is "blocked", "would block", "skipped: ..." or an error.
	Result  string   `json:"result"`
	Samples []string `json:"samples,omitempty"` // event ids
}

// Source of the block the decision makes, as the blocklist keeps it.
func (d Decision) Source() string {
	switch d.Kind {
	case "trap", "access":
		return d.Kind
	}
	return "autoban"
}

// state is what survives a restart.
type state struct {
	Settings  Settings               `json:"settings"`
	Offences  map[string][]time.Time `json:"offences"`
	Decisions []Decision             `json:"decisions"`
	Traps     []Trap                 `json:"traps"`
	NextTrap  int                    `json:"next_trap"`
}

type Engine struct {
	File string

	mu     sync.Mutex
	st     state
	recent map[string][]Hit // denied hits per address within the window
	// trapSeen is when an address last fell into a trap ("id ip"): one
	// decision per address and trap an hour.
	trapSeen map[string]time.Time
	// access is what each address did lately by the access logs;
	// accessSeen is when it last got an access-log decision.
	access     map[string]*accessWin
	accessSeen map[string]time.Time
}

func Open(file string) (*Engine, error) {
	e := &Engine{File: file, recent: map[string][]Hit{}, trapSeen: map[string]time.Time{},
		access: map[string]*accessWin{}, accessSeen: map[string]time.Time{}}
	e.st = state{Settings: Defaults(), Offences: map[string][]time.Time{}, NextTrap: 1}
	b, err := os.ReadFile(file)
	if err == nil {
		if err := json.Unmarshal(b, &e.st); err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if e.st.Offences == nil {
		e.st.Offences = map[string][]time.Time{}
	}
	if e.st.NextTrap < 1 {
		e.st.NextTrap = 1
	}
	return e, nil
}

func (e *Engine) save() error {
	b, err := json.MarshalIndent(e.st, "", "  ")
	if err != nil {
		return err
	}
	return auth.WriteFileAtomic(e.File, b, 0o600)
}

func (e *Engine) Settings() Settings {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.st.Settings
}

// SetSettings replaces the settings; the windows start over.
func (e *Engine) SetSettings(s Settings) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.st.Settings = s
	clear(e.recent)
	clear(e.access)
	clear(e.accessSeen)
	return e.save()
}

// Decisions returns the latest decisions, newest first.
func (e *Engine) Decisions() []Decision {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := slices.Clone(e.st.Decisions)
	slices.Reverse(out)
	return out
}

// DecisionsFor returns the decisions about one address, newest first.
func (e *Engine) DecisionsFor(ip string) []Decision {
	return slices.DeleteFunc(e.Decisions(), func(d Decision) bool { return d.IP != ip })
}

// Offences is how many times ip was banned within the memory.
func (e *Engine) Offences(ip string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.st.Offences[ip])
}

func duration(s Settings, n int) time.Duration { return s.Durations[min(n-1, len(s.Durations)-1)] }

// Process feeds one attack record; it returns a decision when the address
// crossed a line. The caller applies it and reports back with Record.
func (e *Engine) Process(h Hit) *Decision {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.st.Settings
	now := h.Time
	if now.IsZero() {
		now = time.Now()
	}
	if h.IP == "" {
		return nil
	}
	if d := e.trap(h.Instance, h.IP, h.Host, h.Method, h.Path, h.EventID, now); d != nil {
		return d
	}
	if !s.Enabled || !h.Denied {
		return nil
	}
	var d Decision
	if slices.Contains(s.Instant, h.Type) && h.Risk >= s.InstantRisk {
		d = Decision{Kind: "instant", Rule: fmt.Sprintf("attack type %d with risk ≥ %d", h.Type, s.InstantRisk),
			Reason: fmt.Sprintf("attack type %d (risk %d) on %s%s", h.Type, h.Risk, h.Host, h.Path)}
		e.recent[h.IP] = append(e.recent[h.IP], h)
	} else {
		list := append(e.recent[h.IP], h)
		cut := now.Add(-s.Window)
		i := 0
		for i < len(list) && list[i].Time.Before(cut) {
			i++
		}
		list = list[i:]
		e.recent[h.IP] = list
		if len(list) < s.Threshold {
			e.gc(now, s.Window)
			return nil
		}
		sites := map[string]bool{}
		for _, x := range list {
			sites[x.Host] = true
		}
		d = Decision{Kind: "threshold", Rule: fmt.Sprintf("%d denied requests in %s", s.Threshold, s.Window),
			Reason: fmt.Sprintf("%d denied requests in %s on %d site(s)", len(list), s.Window, len(sites))}
	}
	for _, x := range e.recent[h.IP][max(0, len(e.recent[h.IP])-5):] {
		if x.EventID != "" {
			d.Samples = append(d.Samples, x.EventID)
		}
	}
	delete(e.recent, h.IP)
	n := e.offence(h.IP, now)
	d.Instance, d.IP, d.Site, d.At, d.Offence, d.Duration, d.DryRun = h.Instance, h.IP, h.Host, now, n, duration(s, n), s.DryRun
	return &d
}

// offence is the number the next ban of ip would get within the memory.
func (e *Engine) offence(ip string, now time.Time) int {
	mem := e.st.Settings.Memory
	past := slices.DeleteFunc(slices.Clone(e.st.Offences[ip]), func(t time.Time) bool { return now.Sub(t) > mem })
	return len(past) + 1
}

// Record keeps a decision and, when it blocked, counts the offence.
func (e *Engine) Record(d Decision) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if d.Result == "blocked" {
		past := slices.DeleteFunc(e.st.Offences[d.IP], func(t time.Time) bool { return d.At.Sub(t) > e.st.Settings.Memory })
		e.st.Offences[d.IP] = append(past, d.At)
	}
	e.st.Decisions = append(e.st.Decisions, d)
	if len(e.st.Decisions) > 500 {
		e.st.Decisions = slices.Clone(e.st.Decisions[len(e.st.Decisions)-500:])
	}
	return e.save()
}

// gc drops addresses whose window has passed, once there are many.
func (e *Engine) gc(now time.Time, window time.Duration) {
	if len(e.recent) < 10000 {
		return
	}
	for ip, list := range e.recent {
		if len(list) == 0 || now.Sub(list[len(list)-1].Time) > window {
			delete(e.recent, ip)
		}
	}
}
