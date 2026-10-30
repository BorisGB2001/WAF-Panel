// Package siem forwards every WAF event to a SIEM over syslog.
package siem

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"wafpanel/internal/safeline"
)

// CEF formats an event in ArcSight Common Event Format (rev. 25).
func CEF(ev safeline.Event) string {
	sev := 5
	if ev.Denied() {
		sev = 8
	}
	var ext []string
	add := func(k, v string) {
		if v != "" {
			ext = append(ext, k+"="+cefExt(v))
		}
	}
	add("rt", strconv.FormatInt(ev.Time.UnixMilli(), 10))
	add("src", ev.SrcIP)
	add("dhost", ev.Host)
	if ev.DstPort != 0 {
		add("dpt", strconv.Itoa(ev.DstPort))
	}
	add("request", ev.URLPath)
	add("requestMethod", ev.Method)
	add("act", ev.ActionName())
	add("cat", safeline.AttackTypeCode(ev.AttackType))
	add("externalId", ev.EventID)
	add("deviceExternalId", ev.Instance)
	add("msg", ev.Reason)
	add("cs1Label", "policy")
	add("cs1", ev.PolicyName)
	add("cs2Label", "ruleId")
	add("cs2", ev.RuleID)
	add("cs3Label", "ja4")
	add("cs3", ev.JA4)
	add("cs4Label", "country")
	add("cs4", ev.Country)
	add("cs5Label", "city")
	add("cs5", ev.City)
	add("cs6Label", "socketIp")
	add("cs6", ev.SocketIP)
	add("cn1Label", "riskLevel")
	add("cn1", strconv.Itoa(ev.RiskLevel))

	return fmt.Sprintf("CEF:0|Chaitin|SafeLine|9|%d|%s|%d|%s",
		ev.AttackType, cefHeader(safeline.AttackTypeCode(ev.AttackType)), sev, strings.Join(ext, " "))
}

var (
	cefHeaderEsc = strings.NewReplacer(`\`, `\\`, `|`, `\|`, "\n", " ", "\r", " ")
	cefExtEsc    = strings.NewReplacer(`\`, `\\`, `=`, `\=`, "\n", `\n`, "\r", `\r`)
)

func cefHeader(s string) string { return cefHeaderEsc.Replace(s) }
func cefExt(s string) string    { return cefExtEsc.Replace(s) }

// JSONEvent is the "json" SIEM format: normalized fields plus the raw record.
type JSONEvent struct {
	Time time.Time `json:"@timestamp"`
	// Product marks the event for SIEM rules, e.g. a Wazuh field match.
	Product        string         `json:"product"`
	Instance       string         `json:"instance"`
	InstanceName   string         `json:"instance_name"`
	EventID        string         `json:"event_id"`
	SrcIP          string         `json:"src_ip"`
	SocketIP       string         `json:"socket_ip,omitempty"`
	Host           string         `json:"host"`
	DstPort        int            `json:"dst_port,omitempty"`
	URL            string         `json:"url"`
	Method         string         `json:"method,omitempty"`
	Action         string         `json:"action"`
	AttackType     int            `json:"attack_type"`
	AttackTypeName string         `json:"attack_type_name"`
	RiskLevel      int            `json:"risk_level"`
	Policy         string         `json:"policy,omitempty"`
	RuleID         string         `json:"rule_id,omitempty"`
	Country        string         `json:"country,omitempty"`
	Province       string         `json:"province,omitempty"`
	City           string         `json:"city,omitempty"`
	JA4            string         `json:"ja4,omitempty"`
	Raw            map[string]any `json:"raw,omitempty"`
}

// JSON formats an event; withRaw adds the whole SafeLine record.
func JSON(ev safeline.Event, withRaw bool) string {
	var raw map[string]any
	if withRaw {
		raw = ev.Raw
	}
	b, _ := json.Marshal(JSONEvent{
		Time: ev.Time, Product: "safeline", Instance: ev.Instance, InstanceName: ev.InstanceName,
		EventID: ev.EventID, SrcIP: ev.SrcIP, SocketIP: ev.SocketIP, Host: ev.Host,
		DstPort: ev.DstPort, URL: ev.URLPath, Method: ev.Method, Action: ev.ActionName(),
		AttackType: ev.AttackType, AttackTypeName: safeline.AttackTypeCode(ev.AttackType),
		RiskLevel: ev.RiskLevel, Policy: ev.PolicyName, RuleID: ev.RuleID,
		Country: ev.Country, Province: ev.Province, City: ev.City, JA4: ev.JA4, Raw: raw,
	})
	return string(b)
}
