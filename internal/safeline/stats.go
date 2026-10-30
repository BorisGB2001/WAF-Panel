package safeline

import (
	"context"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// Traffic statistics, as the "Statistics → Traffic analysis" page of the
// console shows them. SafeLine CE answers for the last 24 hours only:
// "today" needs a license and longer presets are silently cut to 24 hours.

type Access struct {
	Requests int64 `json:"access"`
	Sessions int64 `json:"session"` // visitors (UV)
	IPs      int64 `json:"ip"`
	PV       int64 `json:"pv"`
}

type Intercept struct {
	Block       int64 `json:"block"`
	RateLimit   int64 `json:"rate_limit"`
	Challenge   int64 `json:"challenge"`
	AuthDefense int64 `json:"auth_defense"`
	Offline     int64 `json:"offline"`
	Blacklist   int64 `json:"blacklist"`
}

func (i Intercept) Total() int64 {
	return i.Block + i.RateLimit + i.Challenge + i.AuthDefense + i.Offline + i.Blacklist
}

type ErrorCodes struct {
	E4xx int64 `json:"error_4xx"`
	E5xx int64 `json:"error_5xx"`
}

type Point struct {
	Time  time.Time
	Count int64
}

type Count struct {
	Key   string
	Count int64
}

type Traffic struct {
	Access    Access
	Intercept Intercept
	AttackIPs int64
	// Upstream counts errors returned by the protected application,
	// WAF counts the 4xx that SafeLine produced itself (blocks).
	Upstream ErrorCodes
	WAF      ErrorCodes
	Requests []Point // per hour
	Blocked  []Point // per hour
	Geo      []Count
	GeoBlock []Count
	OS       []Count
	Browsers []Count
	Status   []Count
	Referers []Count
	Pages    []Count
	Errors   []string
}

// Traffic loads everything for the last 24 hours concurrently. A failing
// part is reported in Errors and leaves its section empty.
func (c *Client) Traffic(ctx context.Context) Traffic {
	now := time.Now()
	base := url.Values{
		"begin_time":  {strconv.FormatInt(now.Add(-24*time.Hour).Unix(), 10)},
		"end_time":    {strconv.FormatInt(now.Unix(), 10)},
		"time_preset": {"last1Day"},
	}
	q := func(extra ...string) url.Values {
		v := url.Values{}
		for k, x := range base {
			v[k] = x
		}
		for i := 0; i+1 < len(extra); i += 2 {
			v.Set(extra[i], extra[i+1])
		}
		return v
	}

	var t Traffic
	var mu sync.Mutex
	var wg sync.WaitGroup
	run := func(name string, f func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := f(); err != nil {
				mu.Lock()
				t.Errors = append(t.Errors, name+": "+err.Error())
				mu.Unlock()
			}
		}()
	}
	trend := func(path string, dst *[]Point) func() error {
		return func() error {
			var raw []struct {
				Time  int64 `json:"time"`
				Count int64 `json:"count"`
			}
			if err := c.get(ctx, path, q(), &raw); err != nil {
				return err
			}
			for _, x := range raw {
				*dst = append(*dst, Point{time.Unix(x.Time, 0), x.Count})
			}
			return nil
		}
	}
	counts := func(path, key string, dst *[]Count, extra ...string) func() error {
		return func() error {
			var raw []map[string]any
			if err := c.get(ctx, path, q(extra...), &raw); err != nil {
				return err
			}
			*dst = toCounts(raw, key)
			return nil
		}
	}

	run("access", func() error { return c.get(ctx, "/api/stat/advance/access", q(), &t.Access) })
	run("attack", func() error {
		var a struct {
			Intercept Intercept `json:"intercept"`
			AttackIP  int64     `json:"attack_ip"`
		}
		err := c.get(ctx, "/api/stat/advance/attack", q(), &a)
		t.Intercept, t.AttackIPs = a.Intercept, a.AttackIP
		return err
	})
	run("upstream errors", func() error {
		return c.get(ctx, "/api/stat/advance/error_status_code", q("upstream", "true"), &t.Upstream)
	})
	run("waf errors", func() error {
		return c.get(ctx, "/api/stat/advance/error_status_code", q("upstream", "false"), &t.WAF)
	})
	run("trend access", trend("/api/stat/advance/trend/access", &t.Requests))
	run("trend intercept", trend("/api/stat/advance/trend/intercept", &t.Blocked))
	run("geo", func() error {
		var raw []map[string]any
		if err := c.get(ctx, "/api/stat/advance/location", q("action", "0", "global", "1"), &raw); err != nil {
			return err
		}
		t.Geo = geoCounts(raw)
		return nil
	})
	run("geo blocked", func() error {
		var raw []map[string]any
		if err := c.get(ctx, "/api/stat/advance/location", q("action", "1", "global", "1"), &raw); err != nil {
			return err
		}
		t.GeoBlock = geoCounts(raw)
		return nil
	})
	run("clients", func() error {
		var raw struct {
			OS      []map[string]any `json:"OS"`
			Browser []map[string]any `json:"Browser"`
		}
		if err := c.get(ctx, "/api/stat/advance/client", q(), &raw); err != nil {
			return err
		}
		t.OS, t.Browsers = toCounts(raw.OS, "os"), toCounts(raw.Browser, "browser")
		return nil
	})
	run("status codes", counts("/api/stat/advance/status_code", "status_code", &t.Status, "upstream", "true", "page", "1", "size", "10"))
	run("referers", counts("/api/stat/advance/domain", "domain", &t.Referers, "refer", "1", "page", "1", "size", "10"))
	run("pages", counts("/api/stat/advance/page", "page", &t.Pages, "refer", "0", "page", "1", "size", "10"))
	wg.Wait()
	return t
}

func toCounts(raw []map[string]any, key string) []Count {
	var out []Count
	for _, m := range raw {
		n := num(m, "count")
		if n == 0 {
			continue
		}
		out = append(out, Count{str(m, key), n})
	}
	return out
}

func geoCounts(raw []map[string]any) []Count {
	var out []Count
	for _, m := range raw {
		k := str(m, "country")
		if p := str(m, "province"); p != "" && p != k {
			k += ", " + p
		}
		if n := num(m, "count"); n > 0 {
			out = append(out, Count{k, n})
		}
	}
	return out
}

// QPS returns requests per second for the last n five-second buckets,
// as the console's "Query Per Second" chart.
func (c *Client) QPS(ctx context.Context, n int) ([]Point, error) {
	var data struct {
		Nodes []map[string]any `json:"nodes"`
	}
	if err := c.get(ctx, "/api/stat/qps", url.Values{"count": {strconv.Itoa(n)}}, &data); err != nil {
		return nil, err
	}
	today := time.Now().Format("2006-01-02 ")
	out := make([]Point, 0, len(data.Nodes))
	for _, node := range data.Nodes {
		var sum int64
		for k := range node {
			if k != "time" {
				sum += num(node, k)
			}
		}
		ts, _ := time.ParseInLocation("2006-01-02 15:04:05", today+str(node, "time"), time.Local)
		// Buckets are five seconds wide; round up like the console does.
		out = append(out, Point{ts, (sum + 4) / 5})
	}
	return out, nil
}
