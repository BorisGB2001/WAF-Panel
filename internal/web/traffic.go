package web

import (
	"cmp"
	"context"
	"fmt"
	"html/template"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"wafpanel/internal/analytics"
	"wafpanel/internal/safeline"
)

var trafficPeriods = []struct {
	Key, Label string
	D          time.Duration
}{
	{"24h", "24 hours", 24 * time.Hour}, {"7d", "7 days", 7 * 24 * time.Hour},
	{"30d", "30 days", 30 * 24 * time.Hour}, {"90d", "90 days", 90 * 24 * time.Hour},
}

// row is one line of a top list.
type row struct {
	Key, Label, Hint string
	Flag             string
	N                int64
	Pct              int // share of the total
	W                int // bar width relative to the first row
	analytics.Stat
}

func (r row) Rate4() string { return rate(r.E4, r.N) }
func (r row) Rate5() string { return rate(r.E5, r.N) }

func rowsOf(m map[string]int64, total int64, n int, label func(string) (string, string)) []row {
	keys := slices.SortedFunc(maps.Keys(m), func(a, b string) int {
		if a == analytics.Other || b == analytics.Other { // the tail goes last
			return cmp.Compare(boolInt(a == analytics.Other), boolInt(b == analytics.Other))
		}
		return cmp.Or(cmp.Compare(m[b], m[a]), cmp.Compare(a, b))
	})
	if len(keys) > n {
		keys = keys[:n]
	}
	out := make([]row, 0, len(keys))
	for _, k := range keys {
		r := row{Key: k, Label: k, N: m[k]}
		if label != nil {
			r.Label, r.Flag = label(k)
		}
		out = append(out, r)
	}
	fill(out, total)
	return out
}

func statRows(m map[string]*analytics.Stat, total int64, n int, by func(*analytics.Stat) int64) []row {
	keys := slices.SortedFunc(maps.Keys(m), func(a, b string) int {
		return cmp.Or(cmp.Compare(by(m[b]), by(m[a])), cmp.Compare(a, b))
	})
	var out []row
	for _, k := range keys {
		if k == analytics.Other || by(m[k]) == 0 {
			continue
		}
		out = append(out, row{Key: k, Label: k, N: m[k].N, Stat: *m[k]})
		if len(out) == n {
			break
		}
	}
	fill(out, total)
	return out
}

func fill(rs []row, total int64) {
	var top int64
	for _, r := range rs {
		top = max(top, r.N)
	}
	for i := range rs {
		if total > 0 {
			rs[i].Pct = int(rs[i].N * 100 / total)
		}
		if top > 0 {
			rs[i].W = int(rs[i].N * 100 / top)
		}
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// flag turns an ISO country code into its emoji flag.
func flag(code string) string {
	if len(code) != 2 {
		return ""
	}
	var b strings.Builder
	for _, r := range strings.ToUpper(code) {
		if r < 'A' || r > 'Z' {
			return ""
		}
		b.WriteRune(0x1F1E6 + r - 'A')
	}
	return b.String()
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	v, i := float64(n), 0
	for v >= unit && i < 5 {
		v /= unit
		i++
	}
	return fmt.Sprintf("%.1f %ciB", v, "KMGTP"[i-1])
}

type trafficView struct {
	Enabled  bool
	Period   string
	Periods  any
	Site     string
	Sites    []safeline.Site
	Status   analytics.Status
	Q        *analytics.Bucket
	Uniq     int64
	Visitors int64
	Bytes    string
	Rate4    string
	Rate5    string
	BotN     int64
	BotRate  string

	Chart, ErrChart template.HTML
	OSDonut         template.HTML
	OSSlices        []slice
	ClientDonut     template.HTML
	ClientSlices    []slice

	Countries, Cities, Clients, Bots, Referrers, Hosts []row
	Statuses, Methods                                  []row
	Paths, ErrPaths, IPs                               []row
	UpKinds, Upstreams                                 []row

	NoLog      []string // sites without an access log
	HiddenIPs  bool     // clients are behind a proxy: one private address dominates
	TopIP      string
	TopIPShare int
}

// traffic builds the log-based part of the statistics page.
func (s *Server) traffic(ctx context.Context, r *http.Request, c *safeline.Client) trafficView {
	v := trafficView{Period: "24h", Periods: trafficPeriods}
	col := s.Analytics[c.ID]
	if col == nil {
		return v
	}
	v.Enabled = true
	v.Status = col.Status()
	d := 24 * time.Hour
	for _, p := range trafficPeriods {
		if p.Key == r.URL.Query().Get("period") {
			v.Period, d = p.Key, p.D
		}
	}
	sites, _ := c.Sites(ctx)
	v.Sites = sites
	var only []string
	if id := r.URL.Query().Get("site"); id != "" {
		if _, err := strconv.Atoi(id); err == nil {
			v.Site, only = id, []string{id}
		}
	}
	for _, x := range sites {
		if !slices.Contains(v.Status.Sites, strconv.Itoa(x.ID)) {
			name := x.Title
			if len(x.ServerNames) > 0 {
				name = x.ServerNames[0]
			}
			v.NoLog = append(v.NoLog, name)
		}
	}
	now := time.Now()
	q := col.Store.Query(only, now.Add(-d), now.Add(time.Minute))
	v.Q = q
	v.Uniq, v.Visitors = q.UniqIPs.Count(), q.UniqVis.Count()
	v.Bytes = humanBytes(q.Bytes)
	v.Rate4, v.Rate5 = rate(q.E4, q.N), rate(q.E5, q.N)
	for _, n := range q.Bots {
		v.BotN += n
	}
	v.BotRate = rate(v.BotN, q.N)

	// Time series.
	layout := "15:04"
	switch {
	case d > 8*24*time.Hour:
		layout = "02.01"
	case d > 24*time.Hour:
		layout = "02.01 15h"
	}
	var labels []string
	var req, e4, e5, up []float64
	for _, p := range fillSeries(q.Series, now.Add(-d), now, d > 8*24*time.Hour) {
		labels = append(labels, time.Unix(p.T, 0).Format(layout))
		req, e4, e5, up = append(req, float64(p.N)), append(e4, float64(p.E4)), append(e5, float64(p.E5)), append(up, float64(p.UpErr))
	}
	v.Chart = areaChart("traffic", labels, []series{
		{Name: tr(r, "requests"), Slot: 1, Values: req},
		{Name: "4xx", Slot: 4, Values: e4},
		{Name: "5xx", Slot: 2, Values: e5},
	})
	v.ErrChart = areaChart("uperr", labels, []series{{Name: tr(r, "upstream errors"), Slot: 2, Values: up}})

	country := func(k string) (string, string) {
		code, name, _ := strings.Cut(k, "|")
		switch code {
		case analytics.Private:
			return tr(r, "Private network"), "🏠"
		case analytics.Unknown:
			return tr(r, "Unknown"), "❔"
		case analytics.Other:
			return tr(r, "Other"), ""
		}
		if name == "" {
			name = code
		}
		return name, flag(code)
	}
	v.Countries = rowsOf(q.Countries, q.N, 12, country)
	v.Cities = rowsOf(q.Cities, q.N, 12, func(k string) (string, string) {
		code, city, _ := strings.Cut(k, "|")
		return city, flag(code)
	})
	families := map[string]int64{}
	for k, n := range q.Clients {
		families[analytics.Family(k)] += n
	}
	v.Clients = rowsOf(q.Clients, q.N, 12, nil)
	v.Bots = rowsOf(q.Bots, q.N, 10, nil)
	v.Referrers = rowsOf(q.Referrers, q.N, 12, nil)
	v.Hosts = rowsOf(q.Hosts, q.N, 10, nil)
	v.Methods = rowsOf(q.Methods, q.N, 8, nil)
	v.Statuses = rowsOf(q.Status, q.N, 12, func(k string) (string, string) { return k, "" })
	for i := range v.Statuses {
		v.Statuses[i].Hint = http.StatusText(atoi(v.Statuses[i].Key))
	}
	v.OSSlices = slicesOf(q.OS)
	v.OSDonut = donut(v.OSSlices, tr(r, "requests"))
	v.ClientSlices = slicesOf(families)
	v.ClientDonut = donut(v.ClientSlices, tr(r, "requests"))

	v.Paths = statRows(q.Paths, q.N, 25, func(s *analytics.Stat) int64 { return s.N })
	v.ErrPaths = statRows(q.Paths, q.N, 15, func(s *analytics.Stat) int64 { return s.E4 + s.E5 })
	v.IPs = statRows(q.IPs, q.N, 20, func(s *analytics.Stat) int64 { return s.N })
	for i := range v.IPs {
		p := col.Geo.Lookup(v.IPs[i].Key)
		v.IPs[i].Label, v.IPs[i].Flag = country(p.Country + "|" + p.Name)
		if p.City != "" {
			v.IPs[i].Label += ", " + p.City
		}
	}
	if len(v.IPs) > 0 && q.N > 0 {
		top := v.IPs[0]
		if share := int(top.N * 100 / q.N); share >= 80 && col.Geo.Lookup(top.Key).Country == analytics.Private {
			v.HiddenIPs, v.TopIP, v.TopIPShare = true, top.Key, share
		}
	}

	v.UpKinds = rowsOf(q.UpErr, q.UpErrN, 10, func(k string) (string, string) { return tr(r, k), "" })
	known := map[string]string{}
	for _, x := range sites {
		for _, u := range x.Upstreams {
			if pu, err := url.Parse(u); err == nil {
				name := x.Title
				if len(x.ServerNames) > 0 {
					name = x.ServerNames[0]
				}
				known[pu.Host] = name
			}
		}
	}
	v.Upstreams = rowsOf(q.UpErrUp, q.UpErrN, 10, nil)
	for i := range v.Upstreams {
		if v.Upstreams[i].Key == "unix socket" {
			v.Upstreams[i].Hint = tr(r, "SafeLine's internal error pages")
		} else if name, ok := known[v.Upstreams[i].Key]; ok {
			v.Upstreams[i].Hint = name
		} else if v.Upstreams[i].Key != analytics.Other {
			v.Upstreams[i].Hint = tr(r, "not an upstream of any current site")
		}
	}
	return v
}

func atoi(s string) int { n, _ := strconv.Atoi(s); return n }

func slicesOf(m map[string]int64) []slice {
	keys := slices.SortedFunc(maps.Keys(m), func(a, b string) int { return cmp.Or(cmp.Compare(m[b], m[a]), cmp.Compare(a, b)) })
	vals := make([]int64, len(keys))
	for i, k := range keys {
		vals[i] = m[k]
	}
	return slices6(keys, vals)
}

// fillSeries puts a point on every hour (or day) of the range, so quiet
// periods show as zero instead of being skipped by the chart.
func fillSeries(ps []analytics.Point, from, to time.Time, daily bool) []analytics.Point {
	at := map[int64]analytics.Point{}
	for _, p := range ps {
		at[p.T] = p
	}
	var out []analytics.Point
	t := from.Truncate(time.Hour).Add(time.Hour)
	if daily {
		y, m, d := from.Date()
		t = time.Date(y, m, d+1, 0, 0, 0, 0, from.Location())
	}
	for !t.After(to) {
		p := at[t.Unix()]
		p.T = t.Unix()
		out = append(out, p)
		if daily {
			t = t.AddDate(0, 0, 1)
		} else {
			t = t.Add(time.Hour)
		}
	}
	return out
}
