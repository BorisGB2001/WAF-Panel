package web

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"wafpanel/internal/safeline"
)

type bar struct {
	Label string
	Value int64
	Pct   int64
}

func bars(ps []safeline.Point, layout string) []bar {
	var peak int64
	for _, p := range ps {
		peak = max(peak, p.Count)
	}
	out := make([]bar, len(ps))
	for i, p := range ps {
		out[i] = bar{Label: p.Time.Local().Format(layout), Value: p.Count}
		if peak > 0 {
			out[i].Pct = p.Count * 100 / peak
		}
	}
	return out
}

func sumPoints(ps []safeline.Point) (sum, peak int64) {
	for _, p := range ps {
		sum += p.Count
		peak = max(peak, p.Count)
	}
	return
}

// rate formats a/b as a percentage with two decimals, like the console.
func rate(a, b int64) string {
	if b == 0 {
		return "0%"
	}
	return fmt.Sprintf("%.2f%%", float64(a)*100/float64(b))
}

func values(ps []safeline.Point) ([]string, []float64) {
	l := make([]string, len(ps))
	v := make([]float64, len(ps))
	for i, p := range ps {
		l[i], v[i] = p.Time.Local().Format("15"), float64(p.Count)
	}
	return l, v
}

type statsView struct {
	Instance  *safeline.Client
	T         safeline.Traffic
	Blocked   int64
	Rate4xx   string
	RateWAF   string
	Rate5xx   string
	QPS       []bar
	QPSNow    int64
	ReqHours  []bar
	BlkHours  []bar
	ReqPeak   int64
	BlkPeak   int64
	Intercept []safeline.Count
	At        time.Time

	ReqChart  template.HTML
	BlkChart  template.HTML
	BlkDonut  template.HTML
	BlkSlices []slice
	ReqSpark  template.HTML
}

func (s *Server) statsPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	c := s.client(r.URL.Query().Get("instance"))
	if c == nil {
		c = s.Clients[0]
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	t := c.Traffic(ctx)
	v := statsView{Instance: c, T: t, Blocked: t.Intercept.Total(), At: time.Now(),
		Rate4xx: rate(t.Upstream.E4xx, t.Access.Requests),
		RateWAF: rate(t.WAF.E4xx, t.Access.Requests),
		Rate5xx: rate(t.Upstream.E5xx, t.Access.Requests),
	}
	v.ReqHours, v.BlkHours = bars(t.Requests, "15"), bars(t.Blocked, "15")
	_, v.ReqPeak = sumPoints(t.Requests)
	_, v.BlkPeak = sumPoints(t.Blocked)
	for _, x := range []struct {
		k string
		n int64
	}{
		{"Attacks", t.Intercept.Block}, {"Rate limit", t.Intercept.RateLimit}, {"Anti-Bot", t.Intercept.Challenge},
		{"Authentication", t.Intercept.AuthDefense}, {"Offline", t.Intercept.Offline}, {"Blacklist", t.Intercept.Blacklist},
	} {
		v.Intercept = append(v.Intercept, safeline.Count{Key: x.k, Count: x.n})
	}
	labels, reqs := values(t.Requests)
	_, blks := values(t.Blocked)
	v.ReqChart = areaChart("req", labels, []series{{Name: tr(r, "requests"), Slot: 1, Values: reqs}})
	v.BlkChart = areaChart("blk", labels, []series{{Name: tr(r, "blocks"), Slot: 2, Values: blks}})
	v.ReqSpark = sparkline(reqs, 1)
	var keys []string
	var vals []int64
	for _, x := range v.Intercept {
		keys, vals = append(keys, x.Key), append(vals, x.Count)
	}
	v.BlkSlices = slices6(keys, vals)
	v.BlkDonut = donut(v.BlkSlices, tr(r, "blocked"))
	p := page{Title: "Statistics", Active: "stats"}
	if q, err := c.QPS(ctx, 35); err == nil {
		v.QPS = bars(q, "15:04:05")
		if len(q) > 0 {
			v.QPSNow = q[len(q)-1].Count
		}
	} else {
		t.Errors = append(t.Errors, "qps: "+err.Error())
	}
	if len(t.Errors) > 0 {
		p.Error = tr(r, "SafeLine did not answer every request: %v", t.Errors)
	}
	p.Data = map[string]any{"V": v, "Instances": s.Clients, "Tr": s.traffic(ctx, r, c)}
	s.render(w, r, rc, "stats.html", p)
}

// statsQPS feeds the live QPS chart.
func (s *Server) statsQPS(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	c := s.client(r.URL.Query().Get("instance"))
	if c == nil {
		c = s.Clients[0]
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	q, err := c.QPS(ctx, 35)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(bars(q, "15:04:05"))
}
