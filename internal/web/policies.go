package web

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"wafpanel/internal/i18n"
	"wafpanel/internal/safeline"
)

// Labels of policy targets and operators, as the SafeLine console names them.
var (
	policyKeyLabels = map[string]string{
		"src_ip": "Source IP", "website": "Application", "uri": "URL", "uri_no_query": "URL path", "host": "Host",
		"get_param": "GET parameter", "post_param": "POST parameter", "req_header": "Request header",
		"req_body": "Request body", "res_body": "Response body", "req_raw_header": "Full request headers",
		"res_raw_header": "Full response headers", "method": "Method", "ja4": "JA4 fingerprint",
	}
	policyOpLabels = map[string]string{
		"eq": "equals", "not_eq": "does not equal", "match": "matches the wildcard", "cidr": "is in the subnet",
		"not_cidr": "is not in the subnet", "in": "is in the IP group", "not_in": "is not in the IP group",
		"has": "contains", "not_has": "does not contain", "prefix": "starts with", "re": "matches the regex",
		"exist": "exists", "not_exist": "does not exist", "geo_eq": "is in the location",
		"geo_not_eq": "is not in the location", "ja4_in": "is in the fingerprint database",
	}
	policyPositions = []struct{ Key, Label string }{
		{"", "Keep its place"}, {"first", "Move to the top"}, {"last", "Move to the bottom"},
	}
)

// policyNames resolves the ids SafeLine keeps in conditions to readable names.
type policyNames struct {
	groups []safeline.IPGroup
	sites  []safeline.Site
}

func (n policyNames) group(id string) string {
	for _, g := range n.groups {
		if strconv.Itoa(g.ID) == id {
			return g.Comment
		}
	}
	return "#" + id
}

func (n policyNames) site(id string) string {
	for _, s := range n.sites {
		if strconv.Itoa(s.ID) == id {
			if len(s.ServerNames) > 0 {
				return s.ServerNames[0]
			}
			return s.Title
		}
	}
	return "#" + id
}

// values shows a condition's values with groups and sites by name.
func (n policyNames) values(p safeline.PolicyPattern) []string {
	out := make([]string, len(p.V))
	for i, v := range p.V {
		switch {
		case p.K == "src_ip" && (p.Op == "in" || p.Op == "not_in"):
			out[i] = n.group(v)
		case p.K == "website":
			out[i] = n.site(v)
		default:
			out[i] = v
		}
	}
	return out
}

// condView is one condition as the list and the editor show it.
type condView struct {
	K, Sub, Op string
	V          []string
}

func (c condView) KeyLabel() string { return policyKeyLabels[c.K] }
func (c condView) OpLabel() string  { return policyOpLabels[c.Op] }
func (c condView) Lines() string    { return strings.Join(c.V, "\n") }

type policyRow struct {
	safeline.Policy
	Pos     int
	Groups  [][]condView
	Managed bool // the panel's own blocklist rule
}

// Editable reports whether the panel's editor can represent the rule.
func (p policyRow) Editable() bool {
	if p.Builtin || p.Managed {
		return false
	}
	for _, and := range p.Pattern {
		for _, c := range and {
			if !safeline.PolicyValidOp(c.K, c.Op) {
				return false
			}
		}
	}
	return true
}

func (s *Server) policyRows(ctx context.Context, c *safeline.Client) ([]policyRow, policyNames, error) {
	ps, err := c.Policies(ctx)
	if err != nil {
		return nil, policyNames{}, err
	}
	var n policyNames
	n.groups, _ = c.IPGroups(ctx)
	n.sites, _ = c.Sites(ctx)
	managed := 0
	if st, err := s.blocklist(c).Status(ctx); err == nil {
		managed = st.PolicyID
	}
	rows := make([]policyRow, len(ps))
	for i, p := range ps {
		rows[i] = policyRow{Policy: p, Pos: i + 1, Managed: p.ID == managed && managed != 0}
		for _, and := range p.Pattern {
			var g []condView
			for _, x := range and {
				g = append(g, condView{K: x.K, Sub: x.SubK, Op: x.Op, V: n.values(x)})
			}
			rows[i].Groups = append(rows[i].Groups, g)
		}
	}
	return rows, n, nil
}

func (s *Server) policiesPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	c := s.instanceFrom(r)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	p := page{Title: "Allow & Deny", Active: "policies"}
	rows, _, err := s.policyRows(ctx, c)
	if err != nil {
		p.Error = "SafeLine: " + err.Error()
	}
	var enabled, allow, deny int
	for _, x := range rows {
		if x.IsEnabled {
			enabled++
			if x.Action == 0 {
				allow++
			} else {
				deny++
			}
		}
	}
	p.Data = map[string]any{"Instance": c, "Instances": s.Clients, "Rows": rows,
		"Enabled": enabled, "Allow": allow, "Deny": deny}
	s.render(w, r, rc, "policies.html", p)
}

// policyForm is the editor as typed, kept to re-render it after an error.
type policyForm struct {
	Name                  string
	Action                int
	Enabled, Log, Monitor bool
	Position, Reason      string
	Groups                [][]condView
}

func policyFormFrom(p policyRow) policyForm {
	return policyForm{Name: p.Name, Action: p.Action, Enabled: p.IsEnabled, Log: p.Log, Monitor: p.Monitor, Groups: p.Groups}
}

func policyFormFromRequest(r *http.Request) policyForm {
	r.ParseForm()
	f := policyForm{Name: strings.TrimSpace(r.FormValue("name")), Enabled: r.FormValue("enabled") == "on",
		Log: r.FormValue("log") == "on", Monitor: r.FormValue("monitor") == "on",
		Position: r.FormValue("position"), Reason: strings.TrimSpace(r.FormValue("reason"))}
	if r.FormValue("action") == "1" {
		f.Action = 1
	}
	gs, ks, subs, ops, vs := r.Form["g"], r.Form["k"], r.Form["sub"], r.Form["op"], r.Form["v"]
	idx := map[string]int{}
	for i := range ks {
		if i >= len(gs) || i >= len(subs) || i >= len(ops) || i >= len(vs) || strings.TrimSpace(ks[i]) == "" {
			continue
		}
		g, ok := idx[gs[i]]
		if !ok {
			g = len(f.Groups)
			idx[gs[i]] = g
			f.Groups = append(f.Groups, nil)
		}
		f.Groups[g] = append(f.Groups[g], condView{K: ks[i], Sub: strings.TrimSpace(subs[i]), Op: ops[i], V: splitLines(vs[i])})
	}
	return f
}

var (
	methodRe   = regexp.MustCompile(`^[A-Z]{3,16}$`)
	ipMatchRe  = regexp.MustCompile(`^[0-9a-fA-F.:*]+$`)
	headerName = regexp.MustCompile(`^[!#$%&'*+.^_|~0-9A-Za-z-]{1,128}$`)
)

// spec checks the form and turns names back into the ids SafeLine stores.
func (f policyForm) spec(n policyNames) (safeline.PolicySpec, error) {
	s := safeline.PolicySpec{Name: f.Name, Action: f.Action, Enabled: f.Enabled, Log: f.Log, Monitor: f.Monitor,
		InsertPosition: f.Position}
	if s.Name == "" || len(s.Name) > 128 {
		return s, i18n.Errorf("Give the rule a name (up to 128 characters)")
	}
	if !slices.Contains([]string{"", "first", "last"}, s.InsertPosition) {
		s.InsertPosition = ""
	}
	for _, g := range f.Groups {
		var and []safeline.PolicyPattern
		for _, c := range g {
			p, err := c.pattern(n)
			if err != nil {
				return s, err
			}
			and = append(and, p)
		}
		if len(and) > 0 {
			s.Pattern = append(s.Pattern, and)
		}
	}
	if len(s.Pattern) == 0 {
		return s, i18n.Errorf("Add at least one condition")
	}
	return s, nil
}

func (c condView) pattern(n policyNames) (safeline.PolicyPattern, error) {
	p := safeline.PolicyPattern{K: c.K, Op: c.Op, V: []string{}}
	what := policyKeyLabels[c.K]
	if !safeline.PolicyValidOp(c.K, c.Op) {
		return p, i18n.Errorf("%s: this operator is not available here", what)
	}
	if safeline.PolicyNeedsName(c.K) {
		if !headerName.MatchString(c.Sub) {
			return p, i18n.Errorf("%s: give the header or parameter name", what)
		}
		p.SubK = c.Sub
	}
	if safeline.PolicyNoValue(c.Op) {
		return p, nil
	}
	if len(c.V) == 0 {
		return p, i18n.Errorf("%s: give at least one value", what)
	}
	for _, v := range c.V {
		if len(v) > 4096 {
			return p, i18n.Errorf("%s: a value is longer than 4096 characters", what)
		}
		switch {
		case c.K == "src_ip" && (c.Op == "eq" || c.Op == "not_eq"):
			a, err := netip.ParseAddr(v)
			if err != nil {
				return p, i18n.Errorf("%s: %q is not an IP address", what, v)
			}
			if c.Op == "eq" && a.IsUnspecified() {
				return p, i18n.Errorf("%s: %q is not an IP address", what, v)
			}
			v = a.String()
		case c.K == "src_ip" && (c.Op == "cidr" || c.Op == "not_cidr"):
			pr, err := netip.ParsePrefix(v)
			if err != nil {
				return p, i18n.Errorf("%s: %q is not a subnet like 203.0.113.0/24", what, v)
			}
			v = pr.Masked().String()
		case c.K == "src_ip" && c.Op == "match":
			if !ipMatchRe.MatchString(v) || !strings.Contains(v, "*") {
				return p, i18n.Errorf("%s: %q is not a wildcard like 203.0.113.*", what, v)
			}
		case c.K == "src_ip": // in, not_in
			id := ""
			for _, g := range n.groups {
				if strconv.Itoa(g.ID) == v || strings.EqualFold(g.Comment, v) {
					id = strconv.Itoa(g.ID)
					break
				}
			}
			if id == "" {
				return p, i18n.Errorf("%s: there is no IP group %q", what, v)
			}
			v = id
		case c.K == "website":
			id := ""
			for _, s := range n.sites {
				if strconv.Itoa(s.ID) == v || slices.Contains(s.ServerNames, strings.ToLower(v)) || (s.Comment != "" && strings.EqualFold(s.Comment, v)) {
					id = strconv.Itoa(s.ID)
					break
				}
			}
			if id == "" {
				return p, i18n.Errorf("%s: there is no application %q", what, v)
			}
			v = id
		case c.K == "method":
			v = strings.ToUpper(v)
			if !methodRe.MatchString(v) {
				return p, i18n.Errorf("%s: %q is not an HTTP method", what, v)
			}
		case c.K == "host" && c.Op != "re":
			v = strings.ToLower(v)
		}
		if c.Op == "re" {
			if _, err := regexp.Compile(v); err != nil {
				return p, i18n.Errorf("%s: the regex %q is not valid", what, v)
			}
		}
		if !slices.Contains(p.V, v) {
			p.V = append(p.V, v)
		}
	}
	return p, nil
}

// blocksAddress reports whether an enabled deny rule surely matches ip: some
// group of conditions consists of source IP checks only and all of them hold.
func blocksAddress(s safeline.PolicySpec, ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil || s.Action != 1 || !s.Enabled || s.Monitor {
		return false
	}
	for _, and := range s.Pattern {
		all := true
		for _, c := range and {
			if !ipCondHolds(c, a) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

func ipCondHolds(c safeline.PolicyPattern, a netip.Addr) bool {
	if c.K != "src_ip" {
		return false
	}
	anyOf := func(f func(string) bool) bool { return slices.ContainsFunc(c.V, f) }
	eq := func(v string) bool { b, err := netip.ParseAddr(v); return err == nil && b == a }
	in := func(v string) bool { p, err := netip.ParsePrefix(v); return err == nil && p.Contains(a) }
	match := func(v string) bool {
		re, err := regexp.Compile("^" + strings.ReplaceAll(regexp.QuoteMeta(v), `\*`, `[0-9a-fA-F:.]*`) + "$")
		return err == nil && re.MatchString(a.String())
	}
	switch c.Op {
	case "eq":
		return anyOf(eq)
	case "not_eq":
		return !anyOf(eq)
	case "cidr":
		return anyOf(in)
	case "not_cidr":
		return !anyOf(in)
	case "match":
		return anyOf(match)
	}
	return false
}

func (s *Server) renderPolicyForm(w http.ResponseWriter, r *http.Request, rc *reqCtx, c *safeline.Client, id int, f policyForm, errMsg string) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	groups, _ := c.IPGroups(ctx)
	sites, _ := c.Sites(ctx)
	title := tr(r, "New rule")
	if id != 0 {
		title = tr(r, "Rule #%d", id)
	}
	if errMsg != "" {
		w.WriteHeader(http.StatusBadRequest)
	}
	if len(f.Groups) == 0 {
		f.Groups = [][]condView{{{K: "src_ip", Op: "eq"}}}
	}
	type opt struct{ Key, Label, Keys string }
	ops := make([]opt, 0, len(policyOpLabels))
	for _, op := range []string{"eq", "not_eq", "has", "not_has", "prefix", "re", "match", "cidr", "not_cidr", "in", "not_in", "exist", "not_exist"} {
		var keys []string
		for _, k := range safeline.PolicyKeys {
			if safeline.PolicyValidOp(k, op) {
				keys = append(keys, k)
			}
		}
		ops = append(ops, opt{op, policyOpLabels[op], strings.Join(keys, " ")})
	}
	keys := make([]opt, len(safeline.PolicyKeys))
	for i, k := range safeline.PolicyKeys {
		named := ""
		if safeline.PolicyNeedsName(k) {
			named = "name"
		}
		keys[i] = opt{k, policyKeyLabels[k], named}
	}
	s.render(w, r, rc, "policy_form.html", page{Title: title, Active: "policies", Error: errMsg, Data: map[string]any{
		"Instance": c, "ID": id, "F": f, "Keys": keys, "Ops": ops, "Positions": policyPositions,
		"IPGroups": groups, "Sites": sites, "MyIP": clientIP(r),
	}})
}

// findPolicy loads the rule and refuses ones the editor must not touch.
func (s *Server) findPolicy(ctx context.Context, r *http.Request, c *safeline.Client) (policyRow, policyNames, error) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	rows, n, err := s.policyRows(ctx, c)
	if err != nil {
		return policyRow{}, n, err
	}
	i := slices.IndexFunc(rows, func(p policyRow) bool { return p.ID == id })
	if i < 0 {
		return policyRow{}, n, i18n.Errorf("Rule not found")
	}
	return rows[i], n, nil
}

func (s *Server) policyNew(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	s.renderPolicyForm(w, r, rc, s.instanceFrom(r), 0, policyForm{Action: 1, Enabled: true, Position: "first"}, "")
}

func (s *Server) policyEdit(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	c := s.instanceFrom(r)
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	p, _, err := s.findPolicy(ctx, r, c)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if !p.Editable() {
		flashRedirect(w, r, "/policies?instance="+url.QueryEscape(c.ID), "", tr(r, "This rule is edited elsewhere: built-in rules and rules with location or fingerprint conditions in the SafeLine console, the blocklist rule on the WAF control page"))
		return
	}
	s.renderPolicyForm(w, r, rc, c, p.ID, policyFormFrom(p), "")
}

func (s *Server) policySave(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	c := s.instanceFrom(r)
	id, _ := strconv.Atoi(r.PathValue("id"))
	f := policyFormFromRequest(r)
	if f.Reason == "" {
		s.renderPolicyForm(w, r, rc, c, id, f, tr(r, "Give a reason for the change — it goes to the audit log"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	var n policyNames
	if id != 0 {
		p, names, err := s.findPolicy(ctx, r, c)
		if err != nil {
			s.renderPolicyForm(w, r, rc, c, id, f, errText(r, err))
			return
		}
		if !p.Editable() {
			s.renderPolicyForm(w, r, rc, c, id, f, tr(r, "This rule cannot be edited in the panel"))
			return
		}
		n = names
	} else {
		n.groups, _ = c.IPGroups(ctx)
		n.sites, _ = c.Sites(ctx)
	}
	spec, err := f.spec(n)
	if err != nil {
		s.renderPolicyForm(w, r, rc, c, id, f, errText(r, err))
		return
	}
	if blocksAddress(spec, clientIP(r)) {
		s.renderPolicyForm(w, r, rc, c, id, f, tr(r, "This rule would block your own address %s", clientIP(r)))
		return
	}
	action, verb := "policy.create", "Rule %q created"
	if id != 0 {
		action, verb = "policy.update", "Rule %q updated"
		err = c.UpdatePolicy(ctx, id, spec)
	} else {
		err = c.CreatePolicy(ctx, spec)
	}
	detail := fmt.Sprintf("%s #%d %q %s%s: %s", c.ID, id, spec.Name, map[int]string{0: "allow", 1: "deny"}[spec.Action],
		map[bool]string{true: "", false: " (disabled)"}[spec.Enabled], f.Reason)
	if err != nil {
		s.audit.Log(rc.User.Name, clientIP(r), action+".failed", detail+" — "+err.Error())
		s.renderPolicyForm(w, r, rc, c, id, f, tr(r, "SafeLine rejected the change: %s", errText(r, err)))
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), action, detail+" — "+policyText(spec.Pattern))
	flashRedirect(w, r, "/policies?instance="+url.QueryEscape(c.ID), tr(r, verb, spec.Name), "")
}

// splitLines splits values one per line: a regex or a body fragment may
// well contain commas.
func splitLines(s string) []string {
	var out []string
	for _, f := range strings.Split(strings.ReplaceAll(s, "\r", ""), "\n") {
		if f = strings.TrimSpace(f); f != "" && !slices.Contains(out, f) {
			out = append(out, f)
		}
	}
	return out
}

// policyText is the conditions in one line for the audit log.
func policyText(pt [][]safeline.PolicyPattern) string {
	return safeline.Policy{Pattern: pt}.Conditions()
}

func (s *Server) policyEnabled(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	c := s.instanceFrom(r)
	back := "/policies?instance=" + url.QueryEscape(c.ID)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	p, _, err := s.findPolicy(ctx, r, c)
	if err != nil {
		flashRedirect(w, r, back, "", errText(r, err))
		return
	}
	reason := strings.TrimSpace(r.FormValue("reason"))
	on := r.FormValue("enabled") == "1"
	switch {
	case p.Managed:
		flashRedirect(w, r, back, "", tr(r, "The blocklist rule is managed on the WAF control page"))
		return
	case reason == "":
		flashRedirect(w, r, back, "", tr(r, "Give a reason — it goes to the audit log"))
		return
	}
	if on && !p.Builtin {
		spec := safeline.PolicySpec{Action: p.Action, Enabled: true, Monitor: p.Monitor, Pattern: p.Pattern}
		if blocksAddress(spec, clientIP(r)) {
			flashRedirect(w, r, back, "", tr(r, "This rule would block your own address %s", clientIP(r)))
			return
		}
	}
	state, msg := "disabled", tr(r, "Rule %q disabled", p.Name)
	if on {
		state, msg = "enabled", tr(r, "Rule %q enabled", p.Name)
	}
	detail := fmt.Sprintf("%s #%d %q %s: %s", c.ID, p.ID, p.Name, state, reason)
	if err := c.SetPolicyEnabled(ctx, p.ID, on); err != nil {
		s.audit.Log(rc.User.Name, clientIP(r), "policy.enabled.failed", detail+" — "+err.Error())
		flashRedirect(w, r, back, "", tr(r, "SafeLine rejected the change: %s", errText(r, err)))
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "policy.enabled", detail)
	flashRedirect(w, r, back, msg, "")
}

func (s *Server) policyDelete(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	c := s.instanceFrom(r)
	back := "/policies?instance=" + url.QueryEscape(c.ID)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	p, _, err := s.findPolicy(ctx, r, c)
	if err != nil {
		flashRedirect(w, r, back, "", errText(r, err))
		return
	}
	reason := strings.TrimSpace(r.FormValue("reason"))
	switch {
	case p.Builtin:
		flashRedirect(w, r, back, "", tr(r, "Built-in rules cannot be deleted, only disabled"))
		return
	case p.Managed:
		flashRedirect(w, r, back, "", tr(r, "The blocklist rule is managed on the WAF control page"))
		return
	case reason == "":
		flashRedirect(w, r, back, "", tr(r, "Give a reason — it goes to the audit log"))
		return
	case r.FormValue("confirm") != p.Name:
		flashRedirect(w, r, back, "", tr(r, "To confirm, type the rule name: %s", p.Name))
		return
	}
	detail := fmt.Sprintf("%s #%d %q (%s): %s", c.ID, p.ID, p.Name, p.Conditions(), reason)
	if err := c.DeletePolicy(ctx, p.ID); err != nil {
		s.audit.Log(rc.User.Name, clientIP(r), "policy.delete.failed", detail+" — "+err.Error())
		flashRedirect(w, r, back, "", tr(r, "SafeLine rejected the change: %s", errText(r, err)))
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "policy.delete", detail)
	flashRedirect(w, r, back, tr(r, "Rule %q deleted", p.Name), "")
}
