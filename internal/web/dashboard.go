package web

import (
	"context"
	"html/template"
	"net/http"
	"slices"
	"strings"
	"time"

	"wafpanel/internal/safeline"
	"wafpanel/internal/stats"
)

const (
	dashTTL      = time.Minute
	dashPageSize = 100
	dashMaxPages = 30
)

type kv struct {
	Key   string
	Count int
}

type hourBar struct {
	Label  string
	Count  int
	Denied int
	Pct    int
}

// Chart is the attacks-per-hour area chart with blocked attacks overlaid.
func (a *agg) Chart(attacks, blocked string) template.HTML {
	labels := make([]string, len(a.Hours))
	all := make([]float64, len(a.Hours))
	den := make([]float64, len(a.Hours))
	for i, h := range a.Hours {
		labels[i], all[i], den[i] = h.Label, float64(h.Count), float64(h.Denied)
	}
	return areaChart("att", labels, []series{{Name: attacks, Slot: 1, Values: all}, {Name: blocked, Slot: 2, Values: den}})
}

// TypeSlices are the attack types folded to at most six slices.
func (a *agg) TypeSlices() []slice {
	var keys []string
	var vals []int64
	for _, t := range a.AllTypes {
		keys, vals = append(keys, t.Key), append(vals, int64(t.Count))
	}
	return slices6(keys, vals)
}

func (a *agg) TypesDonut(label string) template.HTML { return donut(a.TypeSlices(), label) }

type agg struct {
	AllTypes  []kv
	Total     int64
	Fetched   int
	Denied    int
	Passed    int
	Types     []kv
	IPs       []kv
	Hosts     []kv
	Hours     []hourBar
	Truncated bool
}

type dashInstance struct {
	ID, Name  string
	HealthErr string
	Status    stats.Instance
	Sites     []safeline.Site
	SitesErr  string
	Agg       *agg
	AggErr    string
	At        time.Time
}

type dashCache struct {
	at   time.Time
	data dashInstance
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	statuses, counters, started := s.Stats.Snapshot()
	var list []dashInstance
	for _, c := range s.Clients {
		d := s.instanceDash(r.Context(), c)
		d.Status = statuses[c.ID]
		list = append(list, d)
	}
	var sent, failed, siemSent, siemDropped int64
	for k, v := range counters {
		switch {
		case strings.HasPrefix(k, "alerts_sent_total"):
			sent += v
		case strings.HasPrefix(k, "alerts_failed_total"):
			failed += v
		case strings.HasPrefix(k, "siem_sent_total"):
			siemSent += v
		case strings.HasPrefix(k, "siem_dropped_total"):
			siemDropped += v
		}
	}
	s.render(w, r, rc, "dashboard.html", page{Title: "Overview", Active: "dash", Data: map[string]any{
		"Instances":   list,
		"Started":     started,
		"Alerts24h":   s.History.Since(time.Now().Add(-24 * time.Hour)),
		"Recent":      s.History.Recent(5),
		"AlertsSent":  sent,
		"AlertsFail":  failed,
		"SIEMSent":    siemSent,
		"SIEMDropped": siemDropped,
		"Rules":       len(s.currentRules()),
	}})
}

// instanceDash returns the cached 24h picture of one instance.
func (s *Server) instanceDash(ctx context.Context, c *safeline.Client) dashInstance {
	s.mu.Lock()
	cached := s.dash[c.ID]
	s.mu.Unlock()
	if cached != nil && time.Since(cached.at) < dashTTL {
		return cached.data
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	d := dashInstance{ID: c.ID, Name: c.Name, At: time.Now()}
	if err := c.Health(ctx); err != nil {
		d.HealthErr = err.Error()
	}
	if sites, err := c.Sites(ctx); err != nil {
		d.SitesErr = err.Error()
	} else {
		d.Sites = sites
	}
	if a, err := aggregate(ctx, c, time.Now().Add(-24*time.Hour)); err != nil {
		d.AggErr = err.Error()
	} else {
		d.Agg = a
	}
	s.mu.Lock()
	s.dash[c.ID] = &dashCache{at: time.Now(), data: d}
	s.mu.Unlock()
	return d
}

func aggregate(ctx context.Context, c *safeline.Client, since time.Time) (*agg, error) {
	a := &agg{}
	types, ips, hosts := map[string]int{}, map[string]int{}, map[string]int{}
	now := time.Now().Truncate(time.Hour)
	hours := make([]hourBar, 24)
	for i := range hours {
		hours[i].Label = now.Add(time.Duration(i-23) * time.Hour).Local().Format("15")
	}
	for page := 1; page <= dashMaxPages; page++ {
		rows, total, err := c.SearchRecords(ctx, safeline.RecordFilter{Start: since, Page: page, Size: dashPageSize})
		if err != nil {
			return nil, err
		}
		a.Total = total
		for _, r := range rows {
			a.Fetched++
			if r.Denied() {
				a.Denied++
			} else {
				a.Passed++
			}
			types[safeline.AttackTypeCode(r.AttackType)]++
			ips[r.SrcIP]++
			hosts[r.Host]++
			if idx := 23 - int(now.Sub(r.Time.Truncate(time.Hour))/time.Hour); idx >= 0 && idx < 24 {
				hours[idx].Count++
				if r.Denied() {
					hours[idx].Denied++
				}
			}
		}
		if len(rows) < dashPageSize {
			break
		}
		if page == dashMaxPages {
			a.Truncated = true
		}
	}
	peak := 0
	for _, h := range hours {
		peak = max(peak, h.Count)
	}
	for i := range hours {
		if peak > 0 {
			hours[i].Pct = hours[i].Count * 100 / peak
		}
	}
	a.Hours = hours
	a.Types, a.IPs, a.Hosts = top(types, 8), top(ips, 8), top(hosts, 8)
	a.AllTypes = top(types, 100)
	return a, nil
}

func top(m map[string]int, n int) []kv {
	out := make([]kv, 0, len(m))
	for k, v := range m {
		out = append(out, kv{k, v})
	}
	slices.SortFunc(out, func(a, b kv) int {
		if a.Count != b.Count {
			return b.Count - a.Count
		}
		if a.Key < b.Key {
			return -1
		}
		return 1
	})
	return out[:min(n, len(out))]
}
