package safeline

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

const (
	ActionPass = 0
	ActionDeny = 1
)

// Record is one detection log entry of /api/open/records.
//
// Fields are taken loosely (number or string) because the CE API is not
// versioned and the same field changed type between releases. Raw keeps the
// whole entry for the JSON SIEM format.
type Record struct {
	EventID    string
	SiteUUID   string
	Website    string
	SrcIP      string
	SocketIP   string
	Protocol   int
	Method     string
	Host       string
	URLPath    string
	DstPort    int
	Country    string
	Province   string
	City       string
	AttackType int
	RiskLevel  int
	Action     int
	RuleID     string
	PolicyName string
	Reason     string
	Payload    string
	JA4        string
	Time       time.Time

	Raw map[string]any
}

// Event is a record tagged with the instance it came from.
type Event struct {
	Instance     string
	InstanceName string
	Record
}

func (r Record) Denied() bool { return r.Action == ActionDeny }

func (r Record) ActionName() string {
	if r.Denied() {
		return "deny"
	}
	return "pass"
}

func parseRecord(raw json.RawMessage) (Record, error) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return Record{}, fmt.Errorf("record: %w", err)
	}
	r := Record{
		EventID:    str(m, "event_id"),
		SiteUUID:   str(m, "site_uuid"),
		Website:    str(m, "website"),
		SrcIP:      str(m, "src_ip"),
		SocketIP:   str(m, "socket_ip"),
		Protocol:   int(num(m, "protocol")),
		Method:     str(m, "method"),
		Host:       str(m, "host"),
		URLPath:    first(str(m, "url_path"), str(m, "url")),
		DstPort:    int(num(m, "dst_port")),
		Country:    str(m, "country"),
		Province:   str(m, "province"),
		City:       str(m, "city"),
		AttackType: int(num(m, "attack_type")),
		RiskLevel:  int(num(m, "risk_level")),
		Action:     int(num(m, "action")),
		RuleID:     first(str(m, "rule_id"), str(m, "short_rule_id")),
		PolicyName: str(m, "policy_name"),
		Reason:     str(m, "reason"),
		Payload:    str(m, "payload"),
		JA4:        str(m, "ja4_fingerprint"),
		Raw:        m,
	}
	if r.SrcIP == "" {
		r.SrcIP = str(m, "ip")
	}
	r.Time = unixAny(num(m, "timestamp"))
	if r.Time.IsZero() {
		r.Time = unixAny(num(m, "created_at"))
	}
	return r, nil
}

// unixAny accepts seconds or milliseconds.
func unixAny(v int64) time.Time {
	switch {
	case v <= 0:
		return time.Time{}
	case v > 1e12:
		return time.UnixMilli(v)
	default:
		return time.Unix(v, 0)
	}
}

func str(m map[string]any, k string) string {
	switch v := m[k].(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

func num(m map[string]any, k string) int64 {
	switch v := m[k].(type) {
	case float64:
		return int64(v)
	case string:
		n, _ := strconv.ParseInt(v, 10, 64)
		return n
	case bool:
		if v {
			return 1
		}
	}
	return 0
}

func first(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}
