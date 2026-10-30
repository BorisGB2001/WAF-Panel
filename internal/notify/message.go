// Package notify delivers alerts to Telegram, email and webhooks.
package notify

import (
	"fmt"
	"strings"
	"time"

	"wafpanel/internal/i18n"
	"wafpanel/internal/rules"
	"wafpanel/internal/safeline"
)

// Lang is the language of alert texts (config "language"), English by default.
var Lang = i18n.EN

func t(s string, args ...any) string { return i18n.T(Lang, s, args...) }

var severityIcon = map[string]string{"info": "ℹ️", "warning": "⚠️", "critical": "🚨"}

// Subject is a one-line summary used as the email subject and message title.
func Subject(a rules.Alert) string {
	inst := ""
	if len(a.Samples) > 0 {
		inst = a.Samples[0].InstanceName
	}
	what := typeNames(a.Types)
	if a.Count == 1 {
		return fmt.Sprintf("[WAF %s] %s", inst, what)
	}
	return fmt.Sprintf("[WAF %s] %s — ", inst, what) + t("%d events in %s", a.Count, a.Window)
}

// Text is the plain text body shared by every channel.
func Text(a rules.Alert) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\n\n", severityIcon[a.Severity], Subject(a))
	b.WriteString(t("Rule: %s (%s)", a.Rule, a.Severity) + "\n")
	if len(a.Samples) > 0 {
		s := a.Samples[len(a.Samples)-1]
		switch a.GroupBy {
		case "src_ip":
			b.WriteString(t("Source: %s", s.SrcIP+geo(s.Record)) + "\n")
		case "host":
			b.WriteString(t("Site: %s", s.Host) + "\n")
		}
	}
	if len(a.Hosts) > 0 {
		b.WriteString(t("Sites: %s", strings.Join(limit(a.Hosts, 5), ", ")) + "\n")
	}
	b.WriteString(t("Types: %s", typeNames(a.Types)) + "\n")
	b.WriteString(t("Blocked: %d, passed: %d", a.Denied, a.Passed) + "\n")
	if a.Count > 1 {
		b.WriteString(t("Period: %s — %s", a.First.Local().Format(time.DateTime), a.Last.Local().Format(time.TimeOnly)) + "\n")
	} else {
		b.WriteString(t("Time: %s", a.Last.Local().Format(time.DateTime)) + "\n")
	}
	b.WriteString("\n" + t("Latest events:") + "\n")
	for _, s := range a.Samples {
		fmt.Fprintf(&b, "• %s %s %s%s [%s] %s id=%s\n",
			s.Time.Local().Format(time.TimeOnly), s.SrcIP, s.Host, cut(s.URLPath, 80),
			t(safeline.AttackTypeName(s.AttackType)), t(s.ActionName()), s.EventID)
	}
	return b.String()
}

func geo(r safeline.Record) string {
	parts := []string{}
	for _, p := range []string{r.Country, r.City} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

func typeNames(ts []int) string {
	names := make([]string, 0, len(ts))
	for _, typ := range ts {
		names = append(names, t(safeline.AttackTypeName(typ)))
	}
	return strings.Join(limit(names, 4), ", ")
}

func limit(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(s[:n:n], t("and %d more", len(s)-n))
}

func cut(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
