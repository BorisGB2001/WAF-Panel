package web

import (
	"cmp"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"wafpanel/internal/blocklist"
	"wafpanel/internal/i18n"
	"wafpanel/internal/safeline"
)

// massQuery is what a mass ban targets: every address that did the same
// thing (an attack type, a path or a rule) in a period.
type massQuery struct {
	Instance string
	By       string // "type", "path" or "rule"
	Value    string
	Host     string
	Period   string
}

func (q massQuery) label() string {
	switch q.By {
	case "type":
		t, _ := strconv.Atoi(q.Value)
		return safeline.AttackTypeCode(t)
	}
	return q.Value
}

type massRow struct {
	IP      string
	N       int
	Denied  int
	Paths   int
	Last    time.Time
	Skip    string // why it will not be blocked
	Blocked bool
}

func (s *Server) parseMass(r *http.Request) (massQuery, *safeline.Client, error) {
	q := massQuery{Instance: r.FormValue("instance"), By: r.FormValue("by"), Value: strings.TrimSpace(r.FormValue("value")),
		Host: strings.TrimSpace(r.FormValue("host")), Period: r.FormValue("period")}
	c := s.client(q.Instance)
	if c == nil {
		c = s.Clients[0]
		q.Instance = c.ID
	}
	if !validPeriod(analysisPeriods)(q.Period) {
		q.Period = "24h"
	}
	switch q.By {
	case "type":
		if _, err := strconv.Atoi(q.Value); err != nil {
			return q, c, i18n.Errorf("Unknown attack type")
		}
	case "path", "rule":
		if q.Value == "" {
			return q, c, i18n.Errorf("Nothing to match")
		}
	default:
		return q, c, i18n.Errorf("Unknown target")
	}
	return q, c, nil
}

// massRows reads the matching records and groups them by address.
func (s *Server) massRows(ctx context.Context, c *safeline.Client, q massQuery) ([]massRow, int, bool, error) {
	var d time.Duration
	for _, p := range analysisPeriods {
		if p.Key == q.Period {
			d = p.D
		}
	}
	f := safeline.RecordFilter{Start: time.Now().Add(-d), Host: q.Host}
	switch q.By {
	case "type":
		t, _ := strconv.Atoi(q.Value)
		f.AttackTypes = []int{t}
	case "path":
		f.URL = q.Value
	}
	rows, total, err := fetchRecords(ctx, c, f, analysisLimit)
	byIP := map[string]*massRow{}
	paths := map[string]map[string]bool{}
	n := 0
	for _, x := range rows {
		switch {
		case q.By == "path" && x.URLPath != q.Value,
			q.By == "rule" && x.RuleID != q.Value && x.PolicyName != q.Value,
			q.Host != "" && !strings.EqualFold(x.Host, q.Host):
			continue
		}
		n++
		m := byIP[x.SrcIP]
		if m == nil {
			m = &massRow{IP: x.SrcIP}
			byIP[x.SrcIP] = m
			paths[x.SrcIP] = map[string]bool{}
		}
		m.N++
		if x.Denied() {
			m.Denied++
		}
		paths[x.SrcIP][x.URLPath] = true
		if x.Time.After(m.Last) {
			m.Last = x.Time
		}
	}
	var out []massRow
	for ip, m := range byIP {
		m.Paths = len(paths[ip])
		if ok, err := s.blocklist(c).Covers(ctx, ip); err == nil && ok {
			m.Blocked = true
		} else if why := s.whyNot(ctx, c, ip, true); why != "" {
			m.Skip = why
		}
		out = append(out, *m)
	}
	slices.SortFunc(out, func(a, b massRow) int { return cmp.Or(cmp.Compare(b.N, a.N), strings.Compare(a.IP, b.IP)) })
	return out, n, int64(len(rows)) < total, err
}

func (s *Server) massBanPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	q, c, err := s.parseMass(r)
	p := page{Title: "Ban everyone who did this", Active: "attacks"}
	if err != nil {
		p.Error = errText(r, err)
		s.render(w, r, rc, "massban.html", p)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	rows, n, partial, err := s.massRows(ctx, c, q)
	if err != nil {
		p.Error = "SafeLine: " + err.Error()
	}
	// The list looks like ordinary visitors when most addresses were let
	// through or touched one page once: banning them would hurt real users.
	single, passed, todo := 0, 0, 0
	for _, x := range rows {
		if x.N == 1 {
			single++
		}
		if x.Denied == 0 {
			passed++
		}
		if x.Skip == "" && !x.Blocked {
			todo++
		}
	}
	visitors := len(rows) >= 5 && (passed*2 > len(rows) || single*3 > len(rows)*2)
	p.Data = map[string]any{"Q": q, "Label": q.label(), "Instance": c, "Rows": rows, "N": n, "Partial": partial,
		"Todo": todo, "Visitors": visitors, "TTLs": blockTTLs, "Periods": analysisPeriods}
	s.render(w, r, rc, "massban.html", p)
}

func (s *Server) massBan(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	q, c, err := s.parseMass(r)
	back := "/massban?" + url.Values{"instance": {q.Instance}, "by": {q.By}, "value": {q.Value}, "host": {q.Host}, "period": {q.Period}}.Encode()
	if err != nil {
		flashRedirect(w, r, back, "", errText(r, err))
		return
	}
	r.ParseForm()
	ips := r.PostForm["ip"]
	if len(ips) == 0 {
		flashRedirect(w, r, back, "", tr(r, "Choose at least one address"))
		return
	}
	idx := slices.IndexFunc(blockTTLs, func(t ttlOption) bool { return t.Key == r.FormValue("ttl") })
	if idx < 0 {
		flashRedirect(w, r, back, "", tr(r, "Unknown block duration"))
		return
	}
	reason := strings.TrimSpace(r.FormValue("reason"))
	if reason == "" {
		flashRedirect(w, r, back, "", tr(r, "Give a reason for the block — it goes to the audit log"))
		return
	}
	var clean []string
	for _, ip := range ips {
		if p, err := prefixOf(ip); err == nil && p.IsSingleIP() && !isPrivate(ip) {
			clean = append(clean, p.Addr().String())
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	rule := fmt.Sprintf("%s %s", q.By, q.label())
	n, skipped, err := s.banMany(ctx, c, clean, blocklist.Meta{By: rc.User.Name, Reason: reason, Source: "massban", Rule: rule}, blockTTLs[idx].D)
	detail := fmt.Sprintf("%s %d address(es) for %s by %s: %s", c.ID, n, blockTTLs[idx].Label, rule, reason)
	if err != nil {
		s.audit.Log(rc.User.Name, clientIP(r), "waf.massban.failed", detail+" — "+err.Error())
		flashRedirect(w, r, back, "", tr(r, "SafeLine rejected the block: %s", err))
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "waf.massban", detail+" ["+strings.Join(clean, " ")+"]")
	msg := tr(r, "Blocked %d address(es)", n)
	if len(skipped) > 0 {
		msg += " · " + tr(r, "%d skipped", len(skipped))
	}
	flashRedirect(w, r, "/waf?instance="+url.QueryEscape(c.ID)+"#block", msg, "")
}
