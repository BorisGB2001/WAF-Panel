package web

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"wafpanel/internal/auth"
	"wafpanel/internal/config"
	"wafpanel/internal/rules"
	"wafpanel/internal/safeline"
)

func urlQuery(s string) string { return url.QueryEscape(s) }

// ---------- login ----------

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, nil, "login.html", page{Title: "Sign in", Data: map[string]string{"Next": safeNext(r.URL.Query().Get("next"))}})
}

func (s *Server) loginPost(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		http.Error(w, "cross-site request", http.StatusForbidden)
		return
	}
	name := strings.TrimSpace(strings.ToLower(r.FormValue("username")))
	ip := clientIP(r)
	next := safeNext(r.FormValue("next"))
	fail := func(msg string) {
		w.WriteHeader(http.StatusUnauthorized)
		s.render(w, r, nil, "login.html", page{Title: "Sign in", Error: msg, Data: map[string]string{"Next": next, "Username": name}})
	}
	if s.throttle.Blocked("ip:"+ip, "user:"+name) {
		s.audit.Log(name, ip, "login.blocked", "")
		fail(tr(r, "Too many failed attempts. Wait 15 minutes."))
		return
	}
	u, err := s.users.Authenticate(name, r.FormValue("password"))
	if err != nil {
		s.throttle.Fail("ip:"+ip, "user:"+name)
		s.audit.Log(name, ip, "login.failed", "")
		fail(tr(r, "Wrong username or password."))
		return
	}
	s.throttle.Reset("user:" + name)
	s.setSession(w, *u)
	s.audit.Log(u.Name, ip, "login", "")
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// safeNext allows only local paths after login.
func safeNext(n string) string {
	if !strings.HasPrefix(n, "/") || strings.HasPrefix(n, "//") || strings.HasPrefix(n, "/\\") {
		return "/"
	}
	return n
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	clearSession(w)
	s.audit.Log(rc.User.Name, clientIP(r), "logout", "")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---------- attacks ----------

type attackQuery struct {
	Instance string
	IP       string
	Host     string
	URL      string
	Type     string
	Action   string
	Period   string
	Page     int
}

var periods = []struct{ Key, Label string }{
	{"1h", "1 hour"}, {"24h", "24 hours"}, {"7d", "7 days"}, {"30d", "30 days"}, {"all", "All time"},
}

func (s *Server) parseAttackQuery(r *http.Request) (attackQuery, safeline.RecordFilter, *safeline.Client) {
	q := r.URL.Query()
	aq := attackQuery{
		Instance: q.Get("instance"), IP: strings.TrimSpace(q.Get("ip")), Host: strings.TrimSpace(q.Get("host")),
		URL: strings.TrimSpace(q.Get("url")), Type: q.Get("type"), Action: q.Get("action"), Period: q.Get("period"),
	}
	aq.Page, _ = strconv.Atoi(q.Get("page"))
	aq.Page = max(aq.Page, 1)
	if aq.Period == "" {
		aq.Period = "24h"
	}
	c := s.client(aq.Instance)
	if c == nil {
		c = s.Clients[0]
		aq.Instance = c.ID
	}
	f := safeline.RecordFilter{IP: aq.IP, Host: aq.Host, URL: aq.URL, Page: aq.Page, Size: 50}
	if t, err := strconv.Atoi(aq.Type); err == nil && aq.Type != "" {
		f.AttackTypes = []int{t}
	}
	if aq.Action == "deny" || aq.Action == "pass" {
		f.Action = aq.Action
	}
	switch aq.Period {
	case "1h":
		f.Start = time.Now().Add(-time.Hour)
	case "24h":
		f.Start = time.Now().Add(-24 * time.Hour)
	case "7d":
		f.Start = time.Now().AddDate(0, 0, -7)
	case "30d":
		f.Start = time.Now().AddDate(0, 0, -30)
	}
	return aq, f, c
}

func (aq attackQuery) URLWith(page int) string {
	v := url.Values{}
	for k, x := range map[string]string{"instance": aq.Instance, "ip": aq.IP, "host": aq.Host, "url": aq.URL, "type": aq.Type, "action": aq.Action, "period": aq.Period} {
		if x != "" {
			v.Set(k, x)
		}
	}
	if page > 1 {
		v.Set("page", strconv.Itoa(page))
	}
	return v.Encode()
}

type typeOption struct {
	Value int
	Label string
}

func attackTypeOptions() []typeOption {
	var out []typeOption
	for t := -4; t <= 64; t++ {
		name := safeline.AttackTypeName(t)
		if !strings.HasPrefix(name, "Type ") {
			out = append(out, typeOption{t, name})
		}
	}
	slices.SortFunc(out, func(a, b typeOption) int { return strings.Compare(a.Label, b.Label) })
	return out
}

func (s *Server) attacks(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	aq, f, c := s.parseAttackQuery(r)
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	rows, total, err := c.SearchRecords(ctx, f)
	p := page{Title: "Attack log", Active: "attacks"}
	if err != nil {
		p.Error = "SafeLine: " + err.Error()
	}
	pages := int((total + int64(f.Size) - 1) / int64(f.Size))
	p.Data = map[string]any{
		"Q": aq, "Rows": rows, "Total": total, "Pages": pages, "Instances": s.Clients,
		"Types": attackTypeOptions(), "Periods": periods,
		"Prev": aq.URLWith(aq.Page - 1), "Next": aq.URLWith(aq.Page + 1), "CSV": aq.URLWith(0),
	}
	s.render(w, r, rc, "attacks.html", p)
}

const csvMax = 10000

func (s *Server) attacksCSV(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	aq, f, c := s.parseAttackQuery(r)
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	var buf bytes.Buffer
	buf.WriteString("\uFEFF") // Excel opens UTF-8 CSV correctly with a BOM
	cw := csv.NewWriter(&buf)
	cw.Comma = ';'
	cw.Write([]string{"time", "instance", "event_id", "src_ip", "host", "url", "attack_type", "action", "risk_level", "rule_id", "country"})
	n := 0
	f.Size = 100
	for f.Page = 1; n < csvMax; f.Page++ {
		rows, _, err := c.SearchRecords(ctx, f)
		if err != nil {
			http.Error(w, "SafeLine: "+err.Error(), http.StatusBadGateway)
			return
		}
		for _, x := range rows {
			cw.Write([]string{x.Time.Local().Format(time.DateTime), c.ID, x.EventID, x.SrcIP, x.Host, x.URLPath,
				safeline.AttackTypeCode(x.AttackType), x.ActionName(), strconv.Itoa(x.RiskLevel), x.RuleID, x.Country})
			n++
		}
		if len(rows) < f.Size {
			break
		}
	}
	cw.Flush()
	s.audit.Log(rc.User.Name, clientIP(r), "attacks.export", fmt.Sprintf("%d rows, %s", n, aq.URLWith(0)))
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="waf-attacks-%s.csv"`, time.Now().Format("20060102-1504")))
	w.Write(buf.Bytes())
}

func (s *Server) attackDetail(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	c := s.client(r.PathValue("instance"))
	if c == nil {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	rec, err := c.RecordDetail(ctx, r.PathValue("event"))
	p := page{Title: "Attack", Active: "attacks"}
	if err != nil {
		p.Error = "SafeLine: " + err.Error()
	}
	// Detail fields come as strings or numbers depending on the field.
	str := func(k string) string {
		switch v := rec.Raw[k].(type) {
		case string:
			return v
		case float64:
			if v == 0 {
				return ""
			}
			return strconv.FormatFloat(v, 'f', -1, 64)
		case nil:
			return ""
		default:
			return fmt.Sprint(v)
		}
	}
	scheme := "https"
	if strings.HasPrefix(str("website"), "http://") {
		scheme = "http"
	}
	req := str("req_header")
	if b := str("req_body"); b != "" {
		req += "\n\n" + cutBody(b)
	}
	rsp := str("rsp_header")
	if b := str("rsp_body"); b != "" {
		rsp += "\n\n" + cutBody(b)
	}
	p.Data = map[string]any{
		"Instance": c, "R": rec, "Scheme": scheme,
		"ReqHTML": httpHighlight(req, str("payload")), "RspHTML": httpHighlight(rsp, ""), "ReqRaw": req,
		"Payload": str("payload"), "Location": str("location"),
		"Status": str("status_code"), "SrcPort": str("src_port"), "DstIP": str("dst_ip"), "Module": str("module"),
	}
	s.render(w, r, rc, "attack.html", p)
}

func cutBody(s string) string {
	const n = 32 << 10
	if len(s) > n {
		return s[:n] + "\n… (truncated)"
	}
	return s
}

// ---------- alerts ----------

func (s *Server) alerts(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	s.render(w, r, rc, "alerts.html", page{Title: "Alerts", Active: "alerts", Data: s.History.Recent(300)})
}

// ---------- rules ----------

func (s *Server) rulesPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	rs := s.currentRules()
	text, _ := yaml.Marshal(rs)
	s.renderRules(w, r, rc, rs, string(text), "")
}

func (s *Server) renderRules(w http.ResponseWriter, r *http.Request, rc *reqCtx, rs []config.Rule, text, errMsg string) {
	s.render(w, r, rc, "rules.html", page{Title: "Alert rules", Active: "rules", Error: errMsg, Data: map[string]any{
		"Rules": rs, "YAML": text, "Channels": s.Cfg.Channels, "Types": attackTypeOptions(),
	}})
}

func (s *Server) rulesSave(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	text := r.FormValue("yaml")
	var rs []config.Rule
	dec := yaml.NewDecoder(strings.NewReader(text))
	dec.KnownFields(true)
	if err := dec.Decode(&rs); err != nil && err.Error() != "EOF" {
		w.WriteHeader(http.StatusBadRequest)
		s.renderRules(w, r, rc, s.currentRules(), text, tr(r, "YAML error: %s", err))
		return
	}
	if err := s.Cfg.ValidateRules(rs); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		s.renderRules(w, r, rc, s.currentRules(), text, tr(r, "Rule error: %s", err))
		return
	}
	out, _ := yaml.Marshal(rs)
	header := fmt.Sprintf("# wafpanel alert rules. Changed in the panel by %s at %s\n", rc.User.Name, time.Now().Format("2006-01-02 15:04"))
	if err := auth.WriteFileAtomic(s.RuleFile, append([]byte(header), out...), 0o600); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		s.renderRules(w, r, rc, s.currentRules(), text, tr(r, "Could not save: %s", err))
		return
	}
	s.mu.Lock()
	old := s.rules
	s.rules = rs
	s.mu.Unlock()
	s.Rules.SetRules(rs)
	s.audit.Log(rc.User.Name, clientIP(r), "rules.save", ruleDiff(old, rs))
	flashRedirect(w, r, "/rules", tr(r, "Saved and applied: %d rules", len(rs)), "")
}

func ruleDiff(old, now []config.Rule) string {
	names := func(rs []config.Rule) []string {
		var n []string
		for _, r := range rs {
			n = append(n, r.Name)
		}
		return n
	}
	return fmt.Sprintf("was: %s; now: %s", strings.Join(names(old), ", "), strings.Join(names(now), ", "))
}

// ---------- channels ----------

type channelView struct {
	Name, Type, Target string
	Sent, Failed       int64
}

func (s *Server) channelsPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	_, counters, _ := s.Stats.Snapshot()
	var list []channelView
	for _, ch := range s.Cfg.Channels {
		v := channelView{Name: ch.Name, Type: ch.Type,
			Sent:   counters[fmt.Sprintf("alerts_sent_total{channel=%q}", ch.Name)],
			Failed: counters[fmt.Sprintf("alerts_failed_total{channel=%q}", ch.Name)]}
		switch ch.Type {
		case "telegram":
			v.Target = "chat_id " + ch.Telegram.ChatID
		case "email":
			v.Target = strings.Join(ch.Email.To, ", ") + " via " + ch.Email.Host
		case "webhook":
			if u, err := url.Parse(ch.Webhook.URL); err == nil {
				v.Target = u.Scheme + "://" + u.Host + " (" + ch.Webhook.Format + ")"
			}
		}
		list = append(list, v)
	}
	var siem []map[string]any
	for _, t := range s.Cfg.SIEM {
		siem = append(siem, map[string]any{
			"Name": t.Name, "Target": t.Network + "://" + t.Address, "Format": t.Format + ", header " + t.Header,
			"Sent":    counters[fmt.Sprintf("siem_sent_total{target=%q}", t.Name)],
			"Dropped": counters[fmt.Sprintf("siem_dropped_total{target=%q}", t.Name)],
		})
	}
	s.render(w, r, rc, "channels.html", page{Title: "Channels & SIEM", Active: "channels", Data: map[string]any{"Channels": list, "SIEM": siem}})
}

func (s *Server) channelTest(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	name := r.PathValue("name")
	snd := s.Senders[name]
	if snd == nil {
		http.NotFound(w, r)
		return
	}
	now := time.Now()
	ev := safeline.Event{Instance: s.Clients[0].ID, InstanceName: s.Clients[0].Name, Record: safeline.Record{
		EventID: "panel-test", SrcIP: "203.0.113.10", Host: "example.com", URLPath: "/test?from=wafpanel",
		AttackType: 0, Action: safeline.ActionDeny, Time: now,
	}}
	a := rules.Alert{Rule: "panel test (" + rc.User.Name + ")", Severity: "info", GroupBy: "src_ip", GroupKey: ev.SrcIP,
		Count: 1, First: now, Last: now, Denied: 1, Hosts: []string{ev.Host}, Types: []int{0}, Samples: []safeline.Event{ev}}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	err := snd.Send(ctx, a)
	detail := "ok"
	if err != nil {
		detail = err.Error()
	}
	s.audit.Log(rc.User.Name, clientIP(r), "channel.test", name+": "+detail)
	if err != nil {
		flashRedirect(w, r, "/channels", "", tr(r, "Channel %s: %s", name, err))
		return
	}
	flashRedirect(w, r, "/channels", tr(r, "Test alert sent to %s", name), "")
}

// ---------- users ----------

func (s *Server) usersPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	s.renderUsers(w, r, rc, "", "")
}

func (s *Server) renderUsers(w http.ResponseWriter, r *http.Request, rc *reqCtx, flash, errMsg string) {
	s.render(w, r, rc, "users.html", page{Title: "Users", Active: "users", Flash: flash, Error: errMsg, Data: s.users.List()})
}

func (s *Server) userAdd(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	name := strings.TrimSpace(strings.ToLower(r.FormValue("name")))
	role := r.FormValue("role")
	pw := r.FormValue("password")
	generated := pw == ""
	if generated {
		pw = auth.RandomPassword()
	}
	if err := s.users.Add(name, pw, role); err != nil {
		s.renderUsers(w, r, rc, "", errText(r, err))
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "user.add", name+" ("+role+")")
	msg := tr(r, "User %s created.", name)
	if generated {
		// Shown once in this response and never stored in plain text.
		msg += " " + tr(r, "Password: %s — pass it to the user, it is not shown again.", pw)
	}
	s.renderUsers(w, r, rc, msg, "")
}

func (s *Server) userRole(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	name := r.PathValue("name")
	role := r.FormValue("role")
	if err := s.users.SetRole(name, role); err != nil {
		s.renderUsers(w, r, rc, "", errText(r, err))
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "user.role", name+" → "+role)
	s.renderUsers(w, r, rc, tr(r, "Role of %s changed to %s", name, role), "")
}

func (s *Server) userPassword(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	name := r.PathValue("name")
	pw := auth.RandomPassword()
	if err := s.users.SetPassword(name, pw); err != nil {
		s.renderUsers(w, r, rc, "", errText(r, err))
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "user.password_reset", name)
	if name == rc.User.Name {
		s.setSession(w, mustUser(s.users, name))
	}
	s.renderUsers(w, r, rc, tr(r, "New password for %s: %s — it is not shown again.", name, pw), "")
}

func (s *Server) userDelete(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	name := r.PathValue("name")
	if name == rc.User.Name {
		s.renderUsers(w, r, rc, "", tr(r, "You cannot delete yourself"))
		return
	}
	if err := s.users.Delete(name); err != nil {
		s.renderUsers(w, r, rc, "", errText(r, err))
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "user.delete", name)
	s.renderUsers(w, r, rc, tr(r, "User %s deleted", name), "")
}

func mustUser(u *auth.Users, name string) auth.User {
	x, _ := u.Get(name)
	return x
}

// ---------- account ----------

func (s *Server) accountPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	s.render(w, r, rc, "account.html", page{Title: "My account", Active: "account"})
}

func (s *Server) accountPassword(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	fail := func(msg string) {
		w.WriteHeader(http.StatusBadRequest)
		s.render(w, r, rc, "account.html", page{Title: "My account", Active: "account", Error: msg})
	}
	if _, err := s.users.Authenticate(rc.User.Name, r.FormValue("current")); err != nil {
		s.audit.Log(rc.User.Name, clientIP(r), "account.password_failed", "")
		fail(tr(r, "The current password is wrong"))
		return
	}
	if r.FormValue("new") != r.FormValue("repeat") {
		fail(tr(r, "The new passwords do not match"))
		return
	}
	if err := s.users.SetPassword(rc.User.Name, r.FormValue("new")); err != nil {
		fail(errText(r, err))
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "account.password", "")
	s.setSession(w, mustUser(s.users, rc.User.Name))
	if rc.User.Name == "admin" {
		// The bootstrap password is useless now; don't leave it lying around.
		os.Remove(s.Cfg.Web.DataDir + "/initial-admin-password")
	}
	flashRedirect(w, r, "/account", tr(r, "Password changed. Your other sessions have ended."), "")
}

// ---------- audit ----------

func (s *Server) auditPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	s.render(w, r, rc, "audit.html", page{Title: "Audit", Active: "audit", Data: s.audit.Recent()})
}
