package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"wafpanel/internal/autoban"
	"wafpanel/internal/i18n"
	"wafpanel/internal/safeline"
)

// durationOptions are the terms offered for the auto-ban and traps.
var durationOptions = []ttlOption{
	{"1h", "1 hour", time.Hour}, {"24h", "24 hours", 24 * time.Hour}, {"7d", "7 days", 7 * 24 * time.Hour},
	{"30d", "30 days", 30 * 24 * time.Hour}, {"0", "Permanent", 0},
}

func durationKey(d time.Duration) string {
	for _, o := range durationOptions {
		if o.D == d {
			return o.Key
		}
	}
	return d.String()
}

func parseDuration(s string) (time.Duration, error) {
	for _, o := range durationOptions {
		if o.Key == s {
			return o.D, nil
		}
	}
	return 0, i18n.Errorf("Unknown duration %q", s)
}

func (s *Server) autobanPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if s.Autoban == nil {
		s.render(w, r, rc, "autoban.html", page{Title: "Auto-ban", Active: "autoban"})
		return
	}
	set := s.Autoban.Settings()
	var steps []string
	for _, d := range set.Durations {
		steps = append(steps, durationKey(d))
	}
	var types []typeOption
	for _, t := range attackTypeOptions() {
		if t.Value >= 0 {
			types = append(types, t)
		}
	}
	decisions := s.Autoban.Decisions()
	filter := r.URL.Query().Get("show")
	if filter == "blocked" {
		decisions = slices.DeleteFunc(decisions, func(d autoban.Decision) bool { return d.Result != "blocked" })
	}
	s.render(w, r, rc, "autoban.html", page{Title: "Auto-ban", Active: "autoban", Data: map[string]any{
		"S": set, "Steps": strings.Join(steps, ", "), "Types": types, "Durations": durationOptions,
		"Decisions": decisions[:min(len(decisions), 200)], "Show": filter, "Logins": strings.Join(set.LoginPaths, "\n"),
		"WindowMin": int(set.Window / time.Minute), "AccessMin": int(set.AccessWindow / time.Minute),
		"HasLogs": len(s.Analytics) > 0, "DryRunFlag": s.DryRun, "Back": r.URL.RequestURI(),
	}})
}

func (s *Server) autobanSave(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if s.Autoban == nil {
		http.NotFound(w, r)
		return
	}
	old := s.Autoban.Settings()
	set := old
	atoi := func(k string) int { n, _ := strconv.Atoi(strings.TrimSpace(r.FormValue(k))); return n }
	r.ParseForm()
	set.Enabled = r.FormValue("enabled") == "1"
	set.DryRun = r.FormValue("dry_run") == "1"
	set.Threshold = atoi("threshold")
	set.Window = time.Duration(atoi("window")) * time.Minute
	set.InstantRisk = atoi("instant_risk")
	set.Instant = nil
	for _, v := range r.PostForm["instant"] {
		if n, err := strconv.Atoi(v); err == nil {
			set.Instant = append(set.Instant, n)
		}
	}
	set.Durations = nil
	for _, k := range strings.FieldsFunc(r.FormValue("durations"), func(c rune) bool { return c == ',' || c == ' ' }) {
		d, err := parseDuration(k)
		if err != nil {
			flashRedirect(w, r, "/autoban", "", tr(r, "Block durations: %s", err))
			return
		}
		set.Durations = append(set.Durations, d)
	}
	set.AccessEnabled = r.FormValue("access_enabled") == "1"
	set.AccessDryRun = r.FormValue("access_dry_run") == "1"
	set.AccessWindow = time.Duration(atoi("access_window")) * time.Minute
	set.NotFound, set.Logins, set.Rate = atoi("not_found"), atoi("logins"), atoi("rate")
	set.LoginPaths = nil
	for _, l := range strings.Split(r.FormValue("login_paths"), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			set.LoginPaths = append(set.LoginPaths, l)
		}
	}
	if err := set.Validate(); err != nil {
		flashRedirect(w, r, "/autoban", "", errText(r, err))
		return
	}
	if err := s.Autoban.SetSettings(set); err != nil {
		flashRedirect(w, r, "/autoban", "", err.Error())
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "autoban.settings", fmt.Sprintf("waf rules: on=%v dry_run=%v threshold=%d/%s instant=%v risk≥%d durations=%v; access rules: on=%v dry_run=%v 404=%d logins=%d rate=%d/min window=%s",
		set.Enabled, set.DryRun, set.Threshold, set.Window, set.Instant, set.InstantRisk, set.Durations, set.AccessEnabled, set.AccessDryRun, set.NotFound, set.Logins, set.Rate, set.AccessWindow))
	flashRedirect(w, r, "/autoban", tr(r, "Auto-ban settings saved"), "")
}

// ---------- traps ----------

// trapSpec is the SafeLine deny rule of a trap.
func trapSpec(t autoban.Trap) safeline.PolicySpec {
	op := "prefix"
	if t.Match == "part" {
		op = "has"
	}
	and := []safeline.PolicyPattern{{K: "uri_no_query", Op: op, V: []string{t.Path}}}
	if t.Site != "" {
		and = append(and, safeline.PolicyPattern{K: "host", Op: "eq", V: []string{t.Site}})
	}
	return safeline.PolicySpec{Name: t.PolicyName(), Action: 1, Enabled: t.Enabled, Monitor: t.DryRun,
		Pattern: [][]safeline.PolicyPattern{and}}
}

// syncTrap creates or updates the trap's rule on every instance; a rule
// deleted in the console is created again.
func (s *Server) syncTrap(ctx context.Context, t autoban.Trap) (autoban.Trap, error) {
	var errs []error
	ids := map[string]int{}
	for _, c := range s.Clients {
		spec := trapSpec(t)
		ps, err := c.Policies(ctx)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", c.ID, err))
			ids[c.ID] = t.Policies[c.ID]
			continue
		}
		if id := t.Policies[c.ID]; id != 0 && slices.ContainsFunc(ps, func(p safeline.Policy) bool { return p.ID == id }) {
			ids[c.ID] = id
			if err := c.UpdatePolicy(ctx, id, spec); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", c.ID, err))
			}
			continue
		}
		spec.InsertPosition = "last"
		if err := c.CreatePolicy(ctx, spec); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", c.ID, err))
			continue
		}
		if ps, err = c.Policies(ctx); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", c.ID, err))
			continue
		}
		for _, p := range ps {
			if p.Name == spec.Name && !p.Builtin {
				ids[c.ID] = p.ID
			}
		}
	}
	t2, err := s.Autoban.UpdateTrap(t.ID, func(x *autoban.Trap) { x.Policies = ids })
	if err != nil {
		errs = append(errs, err)
	}
	return t2, errors.Join(errs...)
}

// trapSync restores the SafeLine rules of every trap.
func (s *Server) trapSync(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if s.Autoban == nil {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	var errs []string
	for _, t := range s.Autoban.Traps() {
		if _, err := s.syncTrap(ctx, t); err != nil {
			errs = append(errs, err.Error())
		}
	}
	s.audit.Log(rc.User.Name, clientIP(r), "trap.sync", fmt.Sprintf("%d trap(s)", len(s.Autoban.Traps())))
	if len(errs) > 0 {
		flashRedirect(w, r, "/traps", "", tr(r, "SafeLine rejected the change: %s", strings.Join(errs, "; ")))
		return
	}
	flashRedirect(w, r, "/traps", tr(r, "The SafeLine rules of the traps are in place"), "")
}

type trapRow struct {
	autoban.Trap
	Missing []string // instances where the SafeLine rule is missing
}

func (s *Server) trapsPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if s.Autoban == nil {
		s.render(w, r, rc, "traps.html", page{Title: "Traps", Active: "traps"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	present := map[string]map[int]bool{}
	for _, c := range s.Clients {
		present[c.ID] = map[int]bool{}
		if ps, err := c.Policies(ctx); err == nil {
			for _, p := range ps {
				present[c.ID][p.ID] = true
			}
		} else {
			present[c.ID] = nil
		}
	}
	var rows []trapRow
	for _, t := range s.Autoban.Traps() {
		row := trapRow{Trap: t}
		for _, c := range s.Clients {
			if present[c.ID] != nil && !present[c.ID][t.Policies[c.ID]] {
				row.Missing = append(row.Missing, c.Name)
			}
		}
		rows = append(rows, row)
	}
	missing := slices.ContainsFunc(rows, func(t trapRow) bool { return len(t.Missing) > 0 })
	var defaults []string
	for _, d := range autoban.DefaultTraps {
		if !slices.ContainsFunc(rows, func(t trapRow) bool { return t.Path == d.Path && t.Site == "" }) {
			defaults = append(defaults, d.Path)
		}
	}
	s.render(w, r, rc, "traps.html", page{Title: "Traps", Active: "traps", Data: map[string]any{
		"Traps": rows, "Durations": durationOptions, "Prefill": r.URL.Query().Get("path"), "Defaults": defaults, "Missing": missing,
	}})
}

func (s *Server) trapAdd(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if s.Autoban == nil {
		http.NotFound(w, r)
		return
	}
	d, err := parseDuration(r.FormValue("duration"))
	if err != nil {
		flashRedirect(w, r, "/traps", "", errText(r, err))
		return
	}
	t := autoban.Trap{Site: strings.ToLower(strings.TrimSpace(r.FormValue("site"))), Path: strings.TrimSpace(r.FormValue("path")),
		Match: r.FormValue("match"), Duration: d, DryRun: r.FormValue("dry_run") == "1", Enabled: true, By: rc.User.Name}
	t, err = s.Autoban.AddTrap(t)
	if err != nil {
		flashRedirect(w, r, "/traps?path="+url.QueryEscape(t.Path), "", errText(r, err))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	_, err = s.syncTrap(ctx, t)
	detail := fmt.Sprintf("#%d %s %s site=%q for %s dry_run=%v", t.ID, t.Match, t.Path, t.Site, durationKey(t.Duration), t.DryRun)
	s.audit.Log(rc.User.Name, clientIP(r), "trap.create", detail)
	if err != nil {
		flashRedirect(w, r, "/traps", "", tr(r, "The trap is saved, but SafeLine rejected its rule: %s", err))
		return
	}
	flashRedirect(w, r, "/traps", tr(r, "Trap #%d set on %s", t.ID, t.Path), "")
}

// trapDefaults adds the default traps that are missing, in dry run.
func (s *Server) trapDefaults(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if s.Autoban == nil {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	n := 0
	var errs []string
	for _, d := range autoban.DefaultTraps {
		d.Enabled, d.DryRun, d.Duration, d.By = true, true, 7*24*time.Hour, rc.User.Name
		t, err := s.Autoban.AddTrap(d)
		if err != nil {
			continue // exists already
		}
		n++
		if _, err := s.syncTrap(ctx, t); err != nil {
			errs = append(errs, err.Error())
		}
		s.audit.Log(rc.User.Name, clientIP(r), "trap.create", fmt.Sprintf("#%d %s %s (default, dry run)", t.ID, t.Match, t.Path))
	}
	if len(errs) > 0 {
		flashRedirect(w, r, "/traps", "", tr(r, "The traps are saved, but SafeLine rejected their rules: %s", strings.Join(errs, "; ")))
		return
	}
	flashRedirect(w, r, "/traps", tr(r, "%d default trap(s) added in dry run", n), "")
}

func (s *Server) trapChange(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if s.Autoban == nil {
		http.NotFound(w, r)
		return
	}
	id, _ := strconv.Atoi(r.PathValue("id"))
	what := r.PathValue("what")
	on := r.FormValue("on") == "1"
	t, err := s.Autoban.UpdateTrap(id, func(t *autoban.Trap) {
		switch what {
		case "enabled":
			t.Enabled = on
		case "dry_run":
			t.DryRun = on
		}
	})
	if err != nil || (what != "enabled" && what != "dry_run") {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	_, err = s.syncTrap(ctx, t)
	s.audit.Log(rc.User.Name, clientIP(r), "trap."+what, fmt.Sprintf("#%d %s: %v", t.ID, t.Path, on))
	if err != nil {
		flashRedirect(w, r, "/traps", "", tr(r, "SafeLine rejected the change: %s", err))
		return
	}
	flashRedirect(w, r, "/traps", tr(r, "Trap #%d updated", t.ID), "")
}

func (s *Server) trapDelete(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if s.Autoban == nil {
		http.NotFound(w, r)
		return
	}
	id, _ := strconv.Atoi(r.PathValue("id"))
	t, ok := s.Autoban.Trap(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	var errs []string
	for _, c := range s.Clients {
		if pid := t.Policies[c.ID]; pid != 0 {
			if err := c.DeletePolicy(ctx, pid); err != nil {
				errs = append(errs, c.ID+": "+err.Error())
			}
		}
	}
	if len(errs) > 0 {
		flashRedirect(w, r, "/traps", "", tr(r, "SafeLine rejected the change: %s", strings.Join(errs, "; ")))
		return
	}
	s.Autoban.DeleteTrap(id)
	unblocked := 0
	if r.FormValue("unblock") == "1" {
		prefix := fmt.Sprintf("trap #%d ", t.ID)
		for _, c := range s.Clients {
			st, err := s.blocklist(c).Status(ctx)
			if err != nil {
				continue
			}
			for _, e := range st.Entries {
				if e.Source == "trap" && strings.HasPrefix(e.Rule+" ", prefix) {
					if err := s.blocklist(c).Unblock(ctx, e.IP); err == nil {
						unblocked++
						s.audit.Log(rc.User.Name, clientIP(r), "waf.unblock", c.ID+" "+e.IP+": its trap was deleted")
					}
				}
			}
		}
	}
	s.audit.Log(rc.User.Name, clientIP(r), "trap.delete", fmt.Sprintf("#%d %s, %d unblocked", t.ID, t.Path, unblocked))
	flashRedirect(w, r, "/traps", tr(r, "Trap #%d deleted, %d address(es) unblocked", t.ID, unblocked), "")
}
