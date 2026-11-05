package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"wafpanel/internal/analytics"
	"wafpanel/internal/autoban"
	"wafpanel/internal/blocklist"
	"wafpanel/internal/safeline"
)

// fetchRecords reads up to limit matching records, newest first, 100 a page.
func fetchRecords(ctx context.Context, c *safeline.Client, f safeline.RecordFilter, limit int) ([]safeline.Record, int64, error) {
	var out []safeline.Record
	var total int64
	f.Size = 100
	for f.Page = 1; len(out) < limit; f.Page++ {
		rows, t, err := c.SearchRecords(ctx, f)
		if err != nil {
			return out, total, err
		}
		total = t
		out = append(out, rows...)
		if len(rows) < f.Size || int64(len(out)) >= total {
			break
		}
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, total, nil
}

// ipInstance is what one SafeLine instance knows about an address.
type ipInstance struct {
	Instance *safeline.Client
	Err      string
	Total    int64
	Denied   int
	Read     int
	Partial  bool // more records than were read
	First    time.Time
	Last     time.Time
	Types    []kv
	Hosts    []kv
	Paths    []kv
	Rows     []safeline.Record

	Blocked    bool
	Block      blocklist.Meta
	BlockKnown bool
	Allowed    bool
	Allow      blocklist.Meta
	AllowKnown bool
	WhyNot     string
}

// search sends a typed address to its page, anything else to the attack log.
func (s *Server) search(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	switch {
	case q == "":
		http.Redirect(w, r, "/attacks", http.StatusSeeOther)
	case isAddr(q):
		http.Redirect(w, r, "/ip/"+url.PathEscape(q), http.StatusSeeOther)
	case strings.HasPrefix(q, "/"):
		http.Redirect(w, r, "/attacks?period=7d&url="+url.QueryEscape(q), http.StatusSeeOther)
	default:
		http.Redirect(w, r, "/attacks?period=7d&host="+url.QueryEscape(q), http.StatusSeeOther)
	}
}

func isAddr(s string) bool {
	_, err := prefixOf(s)
	return err == nil
}

func (s *Server) ipPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	ip := r.PathValue("ip")
	p, err := prefixOf(ip)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if p.IsSingleIP() {
		ip = p.Addr().String()
	} else {
		ip = p.String()
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	since := time.Now().AddDate(0, 0, -30)
	var list []*ipInstance
	for _, c := range s.Clients {
		v := &ipInstance{Instance: c}
		list = append(list, v)
		rows, total, err := fetchRecords(ctx, c, safeline.RecordFilter{IP: ip, Start: since}, 500)
		if err != nil {
			v.Err = err.Error()
		}
		v.Total, v.Read, v.Partial = total, len(rows), int64(len(rows)) < total
		types, hosts, paths := map[string]int{}, map[string]int{}, map[string]int{}
		for _, x := range rows {
			if x.Denied() {
				v.Denied++
			}
			types[safeline.AttackTypeCode(x.AttackType)]++
			hosts[x.Host]++
			paths[x.URLPath]++
			if v.First.IsZero() || x.Time.Before(v.First) {
				v.First = x.Time
			}
			if x.Time.After(v.Last) {
				v.Last = x.Time
			}
		}
		v.Types, v.Hosts, v.Paths = top(types, 8), top(hosts, 8), top(paths, 10)
		v.Rows = rows[:min(len(rows), 30)]
		if ok, err := s.blocklist(c).Covers(ctx, ip); err == nil {
			v.Blocked = ok
			v.Block, v.BlockKnown = s.blocklist(c).Meta(ip)
		}
		if ok, err := s.allowlist(c).Covers(ctx, ip); err == nil {
			v.Allowed = ok
			v.Allow, v.AllowKnown = s.allowlist(c).Meta(ip)
		}
		v.WhyNot = s.whyNot(ctx, c, ip, false)
	}

	// Traffic from the access logs, 30 days.
	type trafficRow struct {
		Instance string
		analytics.Stat
		Share string
	}
	var traffic []trafficRow
	for _, c := range s.Clients {
		col := s.Analytics[c.ID]
		if col == nil {
			continue
		}
		q := col.Store.Query(nil, since, time.Now().Add(time.Minute))
		if st := q.IPs[ip]; st != nil {
			traffic = append(traffic, trafficRow{Instance: c.Name, Stat: *st, Share: rate(st.N, q.N)})
		}
	}
	var decisions []autoban.Decision
	offences := 0
	if s.Autoban != nil {
		decisions = s.Autoban.DecisionsFor(ip)
		offences = s.Autoban.Offences(ip)
	}
	place := s.Geo.Lookup(strings.SplitN(ip, "/", 2)[0])
	s.render(w, r, rc, "ip.html", page{Title: "Address", Active: "attacks", Data: map[string]any{
		"IP": ip, "Place": place, "Flag": flag(place.Country), "Private": isPrivate(ip), "Instances": list,
		"Traffic": traffic, "Decisions": decisions, "Offences": offences, "TTLs": blockTTLs, "MyIP": clientIP(r),
		"Proxy": isPrivate(ip) && s.Analytics != nil && s.dominantIP(ip),
	}})
}

// dominantIP reports whether ip carries most of a site's traffic: a front
// proxy that hides the visitors.
func (s *Server) dominantIP(ip string) bool {
	for _, col := range s.Analytics {
		q := col.Store.Query(nil, time.Now().Add(-24*time.Hour), time.Now())
		if st := q.IPs[ip]; st != nil && q.N > 0 && st.N*100/q.N >= 50 {
			return true
		}
	}
	return false
}

// allowAdd puts an address on the allow list and lifts its block.
func (s *Server) allowAdd(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	c := s.client(r.PathValue("instance"))
	if c == nil {
		http.NotFound(w, r)
		return
	}
	back := backTo(r, "/waf?instance="+url.QueryEscape(c.ID)+"#allow")
	p, err := prefixOf(strings.TrimSpace(r.FormValue("ip")))
	if err != nil {
		flashRedirect(w, r, back, "", tr(r, "%q is neither an IP address nor a subnet", r.FormValue("ip")))
		return
	}
	if a := p.Addr(); (a.Is4() && p.Bits() < 16) || (a.Is6() && p.Bits() < 48) {
		flashRedirect(w, r, back, "", tr(r, "The subnet is too wide: at most /16 for IPv4 and /48 for IPv6"))
		return
	}
	ip := p.String()
	if p.IsSingleIP() {
		ip = p.Addr().String()
	}
	reason := strings.TrimSpace(r.FormValue("reason"))
	if reason == "" {
		flashRedirect(w, r, back, "", tr(r, "Give a reason — it goes to the audit log"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := s.allowlist(c).BlockMany(ctx, []string{ip}, blocklist.Meta{By: rc.User.Name, Reason: reason, Source: "manual"}, 0); err != nil {
		s.audit.Log(rc.User.Name, clientIP(r), "waf.allow.failed", c.ID+" "+ip+" — "+err.Error())
		flashRedirect(w, r, back, "", tr(r, "SafeLine rejected the change: %s", err))
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "waf.allow", fmt.Sprintf("%s %s: %s", c.ID, ip, reason))
	msg := tr(r, "%s is on the allow list", ip)
	if ok, _ := s.blocklist(c).Covers(ctx, ip); ok {
		if err := s.blocklist(c).Unblock(ctx, ip); err == nil {
			s.audit.Log(rc.User.Name, clientIP(r), "waf.unblock", c.ID+" "+ip+": moved to the allow list")
			msg = tr(r, "%s is on the allow list and no longer blocked", ip)
		}
	}
	flashRedirect(w, r, back, msg, "")
}

func (s *Server) allowRemove(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	c := s.client(r.PathValue("instance"))
	if c == nil {
		http.NotFound(w, r)
		return
	}
	back := backTo(r, "/waf?instance="+url.QueryEscape(c.ID)+"#allow")
	ip := r.FormValue("ip")
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := s.allowlist(c).Unblock(ctx, ip); err != nil {
		flashRedirect(w, r, back, "", tr(r, "SafeLine rejected the change: %s", err))
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "waf.allow.remove", c.ID+" "+ip)
	flashRedirect(w, r, back, tr(r, "%s is off the allow list", ip), "")
}

// blockExpiry changes the term of a block.
func (s *Server) blockExpiry(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	c := s.client(r.PathValue("instance"))
	if c == nil {
		http.NotFound(w, r)
		return
	}
	back := backTo(r, "/waf?instance="+url.QueryEscape(c.ID)+"#block")
	ip := r.FormValue("ip")
	idx := slices.IndexFunc(blockTTLs, func(t ttlOption) bool { return t.Key == r.FormValue("ttl") })
	if idx < 0 {
		flashRedirect(w, r, back, "", tr(r, "Unknown block duration"))
		return
	}
	if err := s.blocklist(c).SetExpiry(ip, blockTTLs[idx].D); err != nil {
		flashRedirect(w, r, back, "", err.Error())
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "waf.block.term", fmt.Sprintf("%s %s: %s from now", c.ID, ip, blockTTLs[idx].Label))
	flashRedirect(w, r, back, tr(r, "The block of %s now lasts %s from now", ip, tr(r, blockTTLs[idx].Label)), "")
}

// backTo is the page a form came from when it says so, else def.
func backTo(r *http.Request, def string) string {
	if b := r.FormValue("back"); strings.HasPrefix(b, "/") && !strings.HasPrefix(b, "//") {
		return b
	}
	return def
}
