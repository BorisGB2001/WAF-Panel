package safeline

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Write access is limited to the calls below. Each one mirrors a request
// the SafeLine console itself sends.

func (c *Client) send(ctx context.Context, method, path string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	u := *c.base
	u.Path += path
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set(tokenHeader, c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "wafpanel/1")
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s %s: HTTP %d: %.300s", method, path, resp.StatusCode, raw)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	if e := strings.TrimSpace(string(env.Err)); e != "" && e != "null" && e != `""` {
		return fmt.Errorf("%s %s: %s %s", method, path, e, env.Msg)
	}
	if out != nil && len(env.Data) > 0 {
		return json.Unmarshal(env.Data, out)
	}
	return nil
}

// IPGroup is a named list of IPs and CIDRs that policies refer to.
type IPGroup struct {
	ID        int      `json:"id"`
	Reference string   `json:"reference"`
	Comment   string   `json:"comment"`
	IPs       []string `json:"ips"`
	Total     int      `json:"total"`
	Builtin   bool     `json:"builtin"`
}

func (c *Client) IPGroups(ctx context.Context) ([]IPGroup, error) {
	var data struct {
		Nodes []IPGroup `json:"nodes"`
	}
	if err := c.get(ctx, "/api/open/ipgroup", url.Values{"top": {"100000"}}, &data); err != nil {
		return nil, err
	}
	return data.Nodes, nil
}

func (c *Client) IPGroup(ctx context.Context, id int) (IPGroup, error) {
	// The detail is wrapped once more: {"data":{"data":{...}}}.
	var w struct {
		Data IPGroup `json:"data"`
	}
	err := c.get(ctx, "/api/open/ipgroup/detail", url.Values{"id": {strconv.Itoa(id)}}, &w)
	return w.Data, err
}

func (c *Client) CreateIPGroup(ctx context.Context, comment string, ips []string) error {
	return c.send(ctx, http.MethodPost, "/api/open/ipgroup", map[string]any{"reference": "", "comment": comment, "ips": ips}, nil)
}

// UpdateIPGroup replaces the whole list of the group.
func (c *Client) UpdateIPGroup(ctx context.Context, g IPGroup) error {
	if g.IPs == nil {
		g.IPs = []string{}
	}
	return c.send(ctx, http.MethodPut, "/api/open/ipgroup", map[string]any{"id": g.ID, "reference": g.Reference, "comment": g.Comment, "ips": g.IPs}, nil)
}

func (c *Client) AppendIPGroup(ctx context.Context, id int, ips []string) error {
	return c.send(ctx, http.MethodPost, "/api/open/ipgroup/append", map[string]any{"ips": ips, "ip_group_ids": []int{id}}, nil)
}

// Policy is a custom rule of the console ("Allow & Deny").
type Policy struct {
	ID        int               `json:"id"`
	Name      string            `json:"name"`
	Action    int               `json:"action"` // 0 allow, 1 deny
	IsEnabled bool              `json:"is_enabled"`
	Builtin   bool              `json:"builtin"`
	Pattern   [][]PolicyPattern `json:"pattern"`
	Log       bool              `json:"log"`
	Creator   string            `json:"creator"`
	ReqCount  int               `json:"req_count"`
}

type PolicyPattern struct {
	K    string   `json:"k"`
	Op   string   `json:"op"`
	V    []string `json:"v"`
	SubK string   `json:"sub_k"`
}

func (p Policy) ActionName() string {
	if p.Action == 1 {
		return "deny"
	}
	return "allow"
}

// Conditions renders the pattern as "a AND b OR c".
func (p Policy) Conditions() string {
	var ors []string
	for _, and := range p.Pattern {
		var parts []string
		for _, x := range and {
			parts = append(parts, fmt.Sprintf("%s %s %s", x.K, x.Op, strings.Join(x.V, ",")))
		}
		ors = append(ors, strings.Join(parts, " AND "))
	}
	return strings.Join(ors, " OR ")
}

// Policies lists every rule; the API accepts at most 100 per page.
func (c *Client) Policies(ctx context.Context) ([]Policy, error) {
	var all []Policy
	for page := 1; page <= 50; page++ {
		var data struct {
			Total int      `json:"total"`
			Data  []Policy `json:"data"`
		}
		q := url.Values{"page": {strconv.Itoa(page)}, "page_size": {"100"}, "action": {"-1"}}
		if err := c.get(ctx, "/api/open/policy", q, &data); err != nil {
			return nil, err
		}
		all = append(all, data.Data...)
		if len(data.Data) < 100 || len(all) >= data.Total {
			break
		}
	}
	return all, nil
}

// CreateDenyGroupPolicy adds an enabled, logged rule that denies every
// source IP in the group. It goes first, like a new rule in the console,
// so an explicit block wins over allow rules further down.
func (c *Client) CreateDenyGroupPolicy(ctx context.Context, name string, groupID int) error {
	return c.send(ctx, http.MethodPost, "/api/open/policy", map[string]any{
		"name":            name,
		"is_enabled":      true,
		"pattern":         [][]PolicyPattern{{{K: "src_ip", Op: "in", V: []string{strconv.Itoa(groupID)}}}},
		"auth_source_ids": []int{},
		"action":          1,
		"log":             true,
		"monitor":         false,
		"insert_position": "first",
	}, nil)
}

func (c *Client) SetPolicyEnabled(ctx context.Context, id int, enabled bool) error {
	return c.send(ctx, http.MethodPut, "/api/open/policy/switch", map[string]any{"id": id, "is_enabled": enabled}, nil)
}

// SetSiteMode switches a site between 0 defense, 1 offline and 2 dry run.
func (c *Client) SetSiteMode(ctx context.Context, siteID, mode int) error {
	if mode < 0 || mode > 2 {
		return fmt.Errorf("unknown site mode %d", mode)
	}
	return c.send(ctx, http.MethodPut, "/api/open/site/mode", map[string]any{"ids": []int{siteID}, "mode": mode}, nil)
}
