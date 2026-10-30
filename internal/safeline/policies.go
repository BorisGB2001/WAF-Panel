package safeline

import (
	"context"
	"net/http"
	"slices"
)

// Policy targets and operators as the console of 9.4.3 offers them.
// Geo operators need a license and JA4 needs the commercial fingerprint
// database, so they are only displayed, never offered.
var (
	PolicyKeys = []string{"src_ip", "website", "uri", "uri_no_query", "host", "get_param", "post_param",
		"req_header", "req_body", "res_body", "req_raw_header", "res_raw_header", "method"}

	policyOps = map[string][]string{
		"src_ip":         {"eq", "not_eq", "match", "cidr", "not_cidr", "in", "not_in"},
		"uri":            {"eq", "not_eq", "has", "not_has", "prefix", "re"},
		"uri_no_query":   {"eq", "not_eq", "has", "not_has", "prefix", "re"},
		"host":           {"eq", "not_eq", "match", "re", "has", "not_has"},
		"get_param":      {"eq", "not_eq", "has", "not_has", "re", "exist", "not_exist"},
		"post_param":     {"eq", "not_eq", "has", "not_has", "re", "exist", "not_exist"},
		"req_header":     {"eq", "not_eq", "has", "not_has", "re", "exist", "not_exist"},
		"req_body":       {"re", "has", "not_has"},
		"res_body":       {"re", "has", "not_has"},
		"req_raw_header": {"re", "has", "not_has"},
		"res_raw_header": {"re", "has", "not_has"},
		"method":         {"eq", "not_eq"},
		"website":        {"eq", "not_eq"},
	}
)

// PolicyOps lists the operators allowed for a target.
func PolicyOps(key string) []string { return policyOps[key] }

// PolicyNeedsName reports whether the target takes a header or parameter name.
func PolicyNeedsName(key string) bool {
	return key == "get_param" || key == "post_param" || key == "req_header"
}

// PolicyNoValue reports whether the operator takes no values.
func PolicyNoValue(op string) bool { return op == "exist" || op == "not_exist" }

// PolicyValidOp reports whether the panel may write this target and operator.
func PolicyValidOp(key, op string) bool { return slices.Contains(policyOps[key], op) }

// PolicySpec is what the panel writes; SafeLine keeps the remaining fields.
type PolicySpec struct {
	Name    string
	Action  int // 0 allow, 1 deny
	Enabled bool
	Log     bool // allow rules only
	Monitor bool // deny rules only
	Pattern [][]PolicyPattern
	// InsertPosition is "first", "last" or, on an update, "" to keep the place.
	InsertPosition string
}

func (s PolicySpec) body() map[string]any {
	b := map[string]any{
		"name":            s.Name,
		"is_enabled":      s.Enabled,
		"pattern":         s.Pattern,
		"auth_source_ids": []int{},
		"action":          s.Action,
		"log":             s.Action == 0 && s.Log,
		"monitor":         s.Action == 1 && s.Monitor,
	}
	if s.InsertPosition != "" {
		b["insert_position"] = s.InsertPosition
	}
	return b
}

func (c *Client) CreatePolicy(ctx context.Context, s PolicySpec) error {
	if s.InsertPosition == "" {
		s.InsertPosition = "first"
	}
	return c.send(ctx, http.MethodPost, "/api/open/policy", s.body(), nil)
}

func (c *Client) UpdatePolicy(ctx context.Context, id int, s PolicySpec) error {
	b := s.body()
	b["id"] = id
	return c.send(ctx, http.MethodPut, "/api/open/policy", b, nil)
}

func (c *Client) DeletePolicy(ctx context.Context, id int) error {
	return c.send(ctx, http.MethodDelete, "/api/open/policy", map[string]any{"id": id}, nil)
}
