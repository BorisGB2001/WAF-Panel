package autoban

import (
	"fmt"
	"slices"
	"strings"
	"time"
	"wafpanel/internal/i18n"
)

// Trap bans whoever requests a path no real visitor asks for: /.env,
// /.git/, ... The panel also keeps a deny rule in SafeLine for every trap,
// so the request gets 403 and lands in the attack log even when the WAF
// itself finds nothing in it; in dry run that rule only records.
type Trap struct {
	ID int `json:"id"`
	// Site is a host name; empty covers every site.
	Site string `json:"site,omitempty"`
	Path string `json:"path"`
	// Match is "prefix" (the path starts with Path) or "part" (Path is
	// anywhere in it).
	Match    string        `json:"match"`
	Duration time.Duration `json:"duration"` // 0 bans for good
	DryRun   bool          `json:"dry_run"`
	Enabled  bool          `json:"enabled"`
	By       string        `json:"by"`
	Created  time.Time     `json:"created"`
	// Policies are the SafeLine rule ids per instance.
	Policies map[string]int `json:"policies,omitempty"`
	Hits     int            `json:"hits"`
	Last     time.Time      `json:"last,omitzero"`
}

// Matches reports whether a request to host and path falls into t.
func (t Trap) Matches(host, path string) bool {
	if !t.Enabled || (t.Site != "" && !strings.EqualFold(t.Site, host)) {
		return false
	}
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	p, tp := strings.ToLower(path), strings.ToLower(t.Path)
	if t.Match == "part" {
		return strings.Contains(p, tp)
	}
	return strings.HasPrefix(p, tp)
}

// PolicyName is the name of the trap's rule in SafeLine.
func (t Trap) PolicyName() string { return fmt.Sprintf("WAF Panel trap #%d: %s", t.ID, t.Path) }

// DefaultTraps are paths only scanners ask for.
var DefaultTraps = []Trap{
	{Path: "/.env", Match: "part"}, {Path: "/.git/", Match: "part"}, {Path: "/.aws/", Match: "part"},
	{Path: "/phpinfo.php", Match: "part"}, {Path: "/.zshrc", Match: "part"}, {Path: "/.bashrc", Match: "part"},
}

// ValidateTrap checks a trap typed in the panel.
func ValidateTrap(t Trap) error {
	if !strings.HasPrefix(t.Path, "/") && t.Match == "prefix" {
		return i18n.Errorf("A path starts with /")
	}
	if len(t.Path) < 3 || len(t.Path) > 200 || strings.ContainsAny(t.Path, " \t\"'<>?#\\") {
		return i18n.Errorf("Give a path of 3 to 200 characters without spaces, quotes, ? or #")
	}
	if t.Path == "/" || t.Path == "/index.php" || t.Path == "/index.html" {
		return i18n.Errorf("This path is every site's home page")
	}
	if t.Match != "prefix" && t.Match != "part" {
		return i18n.Errorf("Unknown match %q", t.Match)
	}
	if t.Duration < 0 || (t.Duration > 0 && t.Duration < time.Minute) {
		return i18n.Errorf("A block duration must be at least 1 minute, or 0 for permanent")
	}
	if t.Site != "" && strings.ContainsAny(t.Site, " /\t") {
		return i18n.Errorf("A site is a host name")
	}
	return nil
}

func (e *Engine) Traps() []Trap {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.st.Traps)
}

func (e *Engine) Trap(id int) (Trap, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	i := slices.IndexFunc(e.st.Traps, func(t Trap) bool { return t.ID == id })
	if i < 0 {
		return Trap{}, false
	}
	return e.st.Traps[i], true
}

// AddTrap stores a new trap and returns it with its id.
func (e *Engine) AddTrap(t Trap) (Trap, error) {
	if err := ValidateTrap(t); err != nil {
		return t, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, x := range e.st.Traps {
		if strings.EqualFold(x.Path, t.Path) && strings.EqualFold(x.Site, t.Site) && x.Match == t.Match {
			return x, i18n.Errorf("This trap exists already: #%d", x.ID)
		}
	}
	t.ID = e.st.NextTrap
	e.st.NextTrap++
	if t.Created.IsZero() {
		t.Created = time.Now()
	}
	e.st.Traps = append(e.st.Traps, t)
	return t, e.save()
}

// UpdateTrap changes a trap with f and saves it.
func (e *Engine) UpdateTrap(id int, f func(*Trap)) (Trap, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	i := slices.IndexFunc(e.st.Traps, func(t Trap) bool { return t.ID == id })
	if i < 0 {
		return Trap{}, i18n.Errorf("No trap #%d", id)
	}
	f(&e.st.Traps[i])
	return e.st.Traps[i], e.save()
}

func (e *Engine) DeleteTrap(id int) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.st.Traps = slices.DeleteFunc(e.st.Traps, func(t Trap) bool { return t.ID == id })
	return e.save()
}

// trap returns a decision when a request fell into a trap: any request,
// denied or not, whether the auto-ban is on or not. The lock is held.
func (e *Engine) trap(instance, ip, host, method, path, eventID string, now time.Time) *Decision {
	for i := range e.st.Traps {
		t := &e.st.Traps[i]
		if !t.Matches(host, path) {
			continue
		}
		t.Hits++
		t.Last = now
		key := fmt.Sprint(t.ID, " ", ip)
		if last, ok := e.trapSeen[key]; ok && now.Sub(last) < time.Hour {
			return nil
		}
		e.trapSeen[key] = now
		if len(e.trapSeen) > 10000 {
			for k, at := range e.trapSeen {
				if now.Sub(at) > time.Hour {
					delete(e.trapSeen, k)
				}
			}
		}
		d := &Decision{Instance: instance, IP: ip, Site: host, At: now, Offence: e.offence(ip, now), Duration: t.Duration,
			DryRun: t.DryRun, Kind: "trap", Trap: t.ID, Rule: fmt.Sprintf("trap #%d %s", t.ID, t.Path),
			Reason: fmt.Sprintf("trap #%d: %s", t.ID, strings.TrimSpace(method+" "+host+path))}
		if eventID != "" {
			d.Samples = []string{eventID}
		}
		return d
	}
	return nil
}
