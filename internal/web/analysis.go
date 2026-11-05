package web

import (
	"cmp"
	"context"
	"maps"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"wafpanel/internal/safeline"
)

// analysisLimit bounds the records one analysis reads from SafeLine.
const analysisLimit = 5000

type periodOption struct {
	Key, Label string
	D          time.Duration
}

var analysisPeriods = []periodOption{{"24h", "24 hours", 24 * time.Hour}, {"7d", "7 days", 7 * 24 * time.Hour}, {"30d", "30 days", 30 * 24 * time.Hour}}

// validPeriod returns a check of a period key against a list.
func validPeriod(list []periodOption) func(string) bool {
	return func(k string) bool { return slices.ContainsFunc(list, func(p periodOption) bool { return p.Key == k }) }
}

type analysisCache struct {
	at time.Time
	v  *analysisView
}

type ipRow struct {
	IP      string
	N       int
	Denied  int
	Paths   int
	Sites   int
	Types   []string
	Last    time.Time
	Blocked bool
	Why     string // why it cannot be blocked
}

type groupRow struct {
	Key     string // rule id or path
	Label   string
	Host    string
	Path    string
	Type    int
	N       int
	IPs     int
	Focused int  // addresses that touched few paths: ordinary visitors
	Scanner bool // the requests look like a scanner's
	Sample  string
}

type analysisView struct {
	Read      int
	Total     int64
	Err       string
	IPs       []ipRow
	Rules     []groupRow
	Paths     []groupRow
	Countries []kv
	Types     []kv
	FP        []groupRow
}

// scannerRe marks paths only scanners request.
var scannerRe = regexp.MustCompile(`(?i)(\.env|\.git|\.aws|\.ssh|phpinfo|wp-admin|wp-login|xmlrpc|\.php\d?$|/cgi-bin/|\.asp|/actuator|/solr|/vendor/phpunit|/\.well-known/security|/boaform|/HNAP1|/config\.json)`)

func (s *Server) analysisPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	c := s.client(r.URL.Query().Get("instance"))
	if c == nil {
		c = s.Clients[0]
	}
	period := s.period(w, r, "analysis", "7d", validPeriod(analysisPeriods))
	var d time.Duration
	for _, p := range analysisPeriods {
		if p.Key == period {
			d = p.D
		}
	}
	key := c.ID + " " + period
	s.mu.Lock()
	if s.analysis == nil {
		s.analysis = map[string]*analysisCache{}
	}
	cached := s.analysis[key]
	s.mu.Unlock()
	var v *analysisView
	if cached != nil && time.Since(cached.at) < 3*time.Minute && r.URL.Query().Get("fresh") == "" {
		v = cached.v
	} else {
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		v = s.analyze(ctx, c, time.Now().Add(-d))
		cancel()
		s.mu.Lock()
		s.analysis[key] = &analysisCache{at: time.Now(), v: v}
		s.mu.Unlock()
	}
	p := page{Title: "Analysis", Active: "analysis"}
	if v.Err != "" {
		p.Error = "SafeLine: " + v.Err
	}
	p.Data = map[string]any{"V": v, "Instance": c, "Instances": s.Clients, "Period": period, "Periods": analysisPeriods,
		"Back": r.URL.RequestURI()}
	s.render(w, r, rc, "analysis.html", p)
}

func (s *Server) analyze(ctx context.Context, c *safeline.Client, since time.Time) *analysisView {
	v := &analysisView{}
	rows, total, err := fetchRecords(ctx, c, safeline.RecordFilter{Start: since}, analysisLimit)
	if err != nil {
		v.Err = err.Error()
	}
	v.Read, v.Total = len(rows), total

	type ipAgg struct {
		row   ipRow
		paths map[string]bool
		sites map[string]bool
		types map[string]bool
	}
	ips := map[string]*ipAgg{}
	countries, types := map[string]int{}, map[string]int{}
	for _, x := range rows {
		a := ips[x.SrcIP]
		if a == nil {
			a = &ipAgg{row: ipRow{IP: x.SrcIP}, paths: map[string]bool{}, sites: map[string]bool{}, types: map[string]bool{}}
			ips[x.SrcIP] = a
		}
		a.row.N++
		if x.Denied() {
			a.row.Denied++
		}
		a.paths[x.Host+x.URLPath] = true
		a.sites[x.Host] = true
		a.types[safeline.AttackTypeCode(x.AttackType)] = true
		if x.Time.After(a.row.Last) {
			a.row.Last = x.Time
		}
		cn := x.Country
		if cn == "" {
			if p := s.Geo.Lookup(x.SrcIP); p.Name != "" {
				cn = p.Name
			}
		}
		if cn != "" {
			countries[cn]++
		}
		types[safeline.AttackTypeCode(x.AttackType)]++
	}
	blocked := map[string]bool{}
	if st, err := s.blocklist(c).Status(ctx); err == nil {
		for _, e := range st.Entries {
			blocked[e.IP] = true
		}
	}
	for _, a := range ips {
		a.row.Paths, a.row.Sites = len(a.paths), len(a.sites)
		a.row.Types = slices.Sorted(maps.Keys(a.types))
		a.row.Blocked = blocked[a.row.IP]
		v.IPs = append(v.IPs, a.row)
	}
	slices.SortFunc(v.IPs, func(a, b ipRow) int { return cmp.Or(cmp.Compare(b.N, a.N), strings.Compare(a.IP, b.IP)) })
	v.IPs = v.IPs[:min(len(v.IPs), 30)]
	for i := range v.IPs {
		v.IPs[i].Why = s.whyNot(ctx, c, v.IPs[i].IP, true)
	}
	v.Countries, v.Types = top(countries, 12), top(types, 12)

	// Groups by rule and by path, and possible false positives: the same
	// rule on the same site and path hit by many focused addresses, which
	// touched at most three paths in the period. A scanner tries hundreds
	// of URLs and drops out; a form the WAF breaks is hit by every
	// visitor who uses it.
	type agg struct {
		row     groupRow
		ips     map[string]bool
		focused map[string]bool
	}
	group := func(m map[string]*agg, key string, x safeline.Record, label string) {
		g := m[key]
		if g == nil {
			g = &agg{row: groupRow{Key: key, Label: label, Host: x.Host, Path: x.URLPath, Type: x.AttackType, Sample: x.EventID}, ips: map[string]bool{}, focused: map[string]bool{}}
			m[key] = g
		}
		g.row.N++
		g.ips[x.SrcIP] = true
		if len(ips[x.SrcIP].paths) <= 3 {
			g.focused[x.SrcIP] = true
		}
	}
	rules, paths, fps := map[string]*agg{}, map[string]*agg{}, map[string]*agg{}
	for _, x := range rows {
		rule := x.RuleID
		label := rule
		if x.PolicyName != "" {
			label = x.PolicyName
		}
		if rule == "" {
			rule = "type:" + safeline.AttackTypeCode(x.AttackType)
			label = safeline.AttackTypeCode(x.AttackType)
		}
		group(rules, rule, x, label)
		group(paths, x.Host+x.URLPath, x, x.URLPath)
		group(fps, x.Host+" "+rule+" "+x.URLPath, x, label)
	}
	list := func(m map[string]*agg, n int, keep func(*agg) bool, by func(groupRow) int) []groupRow {
		var out []groupRow
		for _, g := range m {
			if keep != nil && !keep(g) {
				continue
			}
			g.row.IPs, g.row.Focused = len(g.ips), len(g.focused)
			_, notIP := netip.ParseAddr(strings.Split(g.row.Host, ":")[0])
			g.row.Scanner = scannerRe.MatchString(g.row.Path) || notIP == nil || g.row.Type == 21
			out = append(out, g.row)
		}
		slices.SortFunc(out, func(a, b groupRow) int { return cmp.Or(cmp.Compare(by(b), by(a)), strings.Compare(a.Key, b.Key)) })
		return out[:min(len(out), n)]
	}
	byN := func(g groupRow) int { return g.N }
	v.Rules = list(rules, 15, nil, byN)
	v.Paths = list(paths, 20, nil, byN)
	v.FP = list(fps, 15, func(g *agg) bool { return len(g.focused) >= 3 },
		func(g groupRow) int { return g.Focused })
	return v
}

// period is the period a page shows: the query, else the reader's last
// choice on that page, else def. A valid choice is remembered for a year.
func (s *Server) period(w http.ResponseWriter, r *http.Request, name, def string, valid func(string) bool) string {
	cookie := "wafpanel_period_" + name
	if p := r.URL.Query().Get("period"); p != "" && valid(p) {
		http.SetCookie(w, &http.Cookie{Name: cookie, Value: p, Path: "/", MaxAge: 365 * 24 * 3600,
			HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode})
		return p
	}
	if c, err := r.Cookie(cookie); err == nil && valid(c.Value) {
		return c.Value
	}
	return def
}
