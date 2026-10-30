package analytics

import (
	"cmp"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// Stat counts requests with their errors and traffic.
type Stat struct {
	N     int64 `json:"n"`
	E4    int64 `json:"e4,omitempty"`
	E5    int64 `json:"e5,omitempty"`
	Bytes int64 `json:"b,omitempty"`
}

func (s *Stat) add(o Stat) {
	s.N += o.N
	s.E4 += o.E4
	s.E5 += o.E5
	s.Bytes += o.Bytes
}

// Point is one step of a time series.
type Point struct {
	T int64 `json:"t"` // unix seconds of the step start
	Stat
	UpErr int64 `json:"u,omitempty"`
}

// Bucket holds everything counted for one site over one hour or one day.
// Keyed maps are cut to their top entries when the period is over; the
// rest is summed under Other.
type Bucket struct {
	Start int64 `json:"t"`
	Stat
	Status    map[string]int64 `json:"status,omitempty"`
	Methods   map[string]int64 `json:"methods,omitempty"`
	Hosts     map[string]int64 `json:"hosts,omitempty"`
	Countries map[string]int64 `json:"countries,omitempty"` // "RU|Russia"
	Cities    map[string]int64 `json:"cities,omitempty"`    // "RU|Moscow"
	OS        map[string]int64 `json:"os,omitempty"`
	Clients   map[string]int64 `json:"clients,omitempty"`
	Bots      map[string]int64 `json:"bots,omitempty"`
	Referrers map[string]int64 `json:"referrers,omitempty"`
	Paths     map[string]*Stat `json:"paths,omitempty"` // "GET /api/:id"
	IPs       map[string]*Stat `json:"ips,omitempty"`
	UpErr     map[string]int64 `json:"uperr,omitempty"`    // kind
	UpErrUp   map[string]int64 `json:"uperr_up,omitempty"` // upstream address
	UpErrN    int64            `json:"uperr_n,omitempty"`
	UniqIPs   HLL              `json:"uniq_ips"`
	UniqVis   HLL              `json:"uniq_visitors"` // address + User-Agent
	// Series is filled in day rollups: one point per hour.
	Series []Point `json:"series,omitempty"`
}

// Other collects entries cut from a top list.
const Other = "(other)"

var caps = map[string]int{"paths": 300, "ips": 500, "referrers": 200, "cities": 300, "clients": 150, "default": 100}

func inc(m *map[string]int64, k string, n int64) {
	if *m == nil {
		*m = map[string]int64{}
	}
	(*m)[k] += n
}

func incStat(m *map[string]*Stat, k string, s Stat) {
	if *m == nil {
		*m = map[string]*Stat{}
	}
	if (*m)[k] == nil {
		(*m)[k] = &Stat{}
	}
	(*m)[k].add(s)
}

func statOf(status int, bytes int64) Stat {
	s := Stat{N: 1, Bytes: bytes}
	switch {
	case status >= 500:
		s.E5 = 1
	case status >= 400:
		s.E4 = 1
	}
	return s
}

func (b *Bucket) addAccess(a Access, place Place, c Client) {
	s := statOf(a.Status, a.Bytes)
	b.add(s)
	inc(&b.Status, fmt.Sprint(a.Status), 1)
	inc(&b.Methods, a.Method, 1)
	if a.Host != "" {
		inc(&b.Hosts, a.Host, 1)
	}
	inc(&b.Countries, place.Country+"|"+place.Name, 1)
	if place.City != "" {
		inc(&b.Cities, place.Country+"|"+place.City, 1)
	}
	inc(&b.OS, c.OS, 1)
	inc(&b.Clients, c.Client, 1)
	if c.Bot != "" {
		inc(&b.Bots, c.Bot, 1)
	}
	if r := refHost(a.Referer, a.Host); r != "" {
		inc(&b.Referrers, r, 1)
	}
	incStat(&b.Paths, a.Method+" "+NormalizePath(a.Path), s)
	incStat(&b.IPs, a.IP, s)
	b.UniqIPs.Add(a.IP)
	b.UniqVis.Add(a.IP + "\x00" + a.UA)
}

// refHost is the referrer's host; the site's own pages do not count.
func refHost(ref, host string) string {
	if ref == "" {
		return ""
	}
	r := ref
	if i := strings.Index(r, "://"); i >= 0 {
		r = r[i+3:]
	}
	if i := strings.IndexAny(r, "/?#"); i >= 0 {
		r = r[:i]
	}
	r = strings.ToLower(r)
	if j := strings.LastIndexByte(r, ':'); j > 0 && !strings.Contains(r, "]") {
		r = r[:j]
	}
	if r == "" || r == host {
		return ""
	}
	return r
}

func (b *Bucket) addError(e UpstreamError) {
	b.UpErrN++
	inc(&b.UpErr, e.Kind, 1)
	if e.Upstream != "" {
		inc(&b.UpErrUp, e.Upstream, 1)
	}
}

// merge adds o into b.
func (b *Bucket) merge(o *Bucket) {
	b.add(o.Stat)
	b.UpErrN += o.UpErrN
	for _, p := range []struct{ dst, src *map[string]int64 }{
		{&b.Status, &o.Status}, {&b.Methods, &o.Methods}, {&b.Hosts, &o.Hosts}, {&b.Countries, &o.Countries},
		{&b.Cities, &o.Cities}, {&b.OS, &o.OS}, {&b.Clients, &o.Clients}, {&b.Bots, &o.Bots},
		{&b.Referrers, &o.Referrers}, {&b.UpErr, &o.UpErr}, {&b.UpErrUp, &o.UpErrUp},
	} {
		for k, v := range *p.src {
			inc(p.dst, k, v)
		}
	}
	for k, v := range o.Paths {
		incStat(&b.Paths, k, *v)
	}
	for k, v := range o.IPs {
		incStat(&b.IPs, k, *v)
	}
	b.UniqIPs.Merge(&o.UniqIPs)
	b.UniqVis.Merge(&o.UniqVis)
}

func trim(m map[string]int64, n int) map[string]int64 {
	if len(m) <= n {
		return m
	}
	keys := slices.SortedFunc(maps.Keys(m), func(a, b string) int { return cmp.Compare(m[b], m[a]) })
	out := make(map[string]int64, n+1)
	for i, k := range keys {
		if i < n || k == Other {
			out[k] += m[k]
		} else {
			out[Other] += m[k]
		}
	}
	return out
}

func trimStat(m map[string]*Stat, n int) map[string]*Stat {
	if len(m) <= n {
		return m
	}
	keys := slices.SortedFunc(maps.Keys(m), func(a, b string) int { return cmp.Compare(m[b].N, m[a].N) })
	out := make(map[string]*Stat, n+1)
	for i, k := range keys {
		if i < n || k == Other {
			out[k] = m[k]
			continue
		}
		if out[Other] == nil {
			out[Other] = &Stat{}
		}
		out[Other].add(*m[k])
	}
	return out
}

func (b *Bucket) trim() {
	d := caps["default"]
	b.Status, b.Methods, b.Hosts, b.Countries = trim(b.Status, d), trim(b.Methods, d), trim(b.Hosts, d), trim(b.Countries, d)
	b.Cities, b.OS, b.Clients, b.Bots = trim(b.Cities, caps["cities"]), trim(b.OS, d), trim(b.Clients, caps["clients"]), trim(b.Bots, d)
	b.Referrers, b.UpErr, b.UpErrUp = trim(b.Referrers, caps["referrers"]), trim(b.UpErr, d), trim(b.UpErrUp, d)
	b.Paths, b.IPs = trimStat(b.Paths, caps["paths"]), trimStat(b.IPs, caps["ips"])
}

// Store keeps hourly buckets of the last two days in memory and a rollup
// per day on disk: dir/<site>/<YYYY-MM-DD>.json.gz.
type Store struct {
	Dir       string
	Retention time.Duration

	mu    sync.Mutex
	hours map[string]map[int64]*Bucket // site → hour start → bucket
	days  map[string]map[int64]*Bucket // site → day start (local) → rollup
	dirty map[string]map[int64]bool    // site → day start
}

type dayFile struct {
	Day   *Bucket   `json:"day"`
	Hours []*Bucket `json:"hours,omitempty"`
}

// Hours stay in memory for whole days: today and the two days before.
// Lines older than that (a backfill, a late file) go straight into the
// day rollup, so a day is never rebuilt from part of its hours.
const keepHours = 48

func cutDay(now time.Time) int64 { return dayOf(now.AddDate(0, 0, -2)) }

func hourOf(t time.Time) int64 { return t.Truncate(time.Hour).Unix() }

func dayOf(t time.Time) int64 {
	y, m, d := t.Local().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.Local).Unix()
}

func (s *Store) init() {
	if s.hours == nil {
		s.hours, s.days, s.dirty = map[string]map[int64]*Bucket{}, map[string]map[int64]*Bucket{}, map[string]map[int64]bool{}
	}
}

// target returns the bucket a line at t goes to, and the series point to
// update when that bucket is a day rollup.
func (s *Store) target(site string, t time.Time) (*Bucket, *Point) {
	s.init()
	if s.hours[site] == nil {
		s.hours[site] = map[int64]*Bucket{}
		s.dirty[site] = map[int64]bool{}
	}
	day := dayOf(t)
	s.dirty[site][day] = true
	if day < cutDay(time.Now()) {
		if s.days[site] == nil {
			s.days[site] = map[int64]*Bucket{}
		}
		d := s.days[site][day]
		if d == nil {
			d = &Bucket{Start: day}
			s.days[site][day] = d
		}
		h := hourOf(t)
		i := slices.IndexFunc(d.Series, func(p Point) bool { return p.T == h })
		if i < 0 {
			d.Series = append(d.Series, Point{T: h})
			slices.SortFunc(d.Series, func(a, b Point) int { return cmp.Compare(a.T, b.T) })
			i = slices.IndexFunc(d.Series, func(p Point) bool { return p.T == h })
		}
		return d, &d.Series[i]
	}
	h := hourOf(t)
	b := s.hours[site][h]
	if b == nil {
		b = &Bucket{Start: h}
		s.hours[site][h] = b
	}
	return b, nil
}

// tooOld drops lines of a backfill older than the retention.
func (s *Store) tooOld(t time.Time) bool {
	return s.Retention > 0 && time.Since(t) > s.Retention
}

func (s *Store) AddAccess(site string, a Access, place Place, c Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tooOld(a.Time) {
		return
	}
	b, p := s.target(site, a.Time)
	b.addAccess(a, place, c)
	if p != nil {
		p.add(statOf(a.Status, a.Bytes))
	}
}

func (s *Store) AddError(site string, e UpstreamError) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tooOld(e.Time) {
		return
	}
	b, p := s.target(site, e.Time)
	b.addError(e)
	if p != nil {
		p.UpErr++
	}
}

// rollup builds the day bucket of site from its hours.
func (s *Store) rollup(site string, day int64) *Bucket {
	d := &Bucket{Start: day}
	end := time.Unix(day, 0).AddDate(0, 0, 1).Unix()
	var hs []int64
	for h := range s.hours[site] {
		if h >= day && h < end {
			hs = append(hs, h)
		}
	}
	slices.Sort(hs)
	if day < cutDay(time.Now()) {
		// Kept as a rollup only: it was updated in place.
		if d := s.days[site][day]; d != nil {
			d.trim()
			return d
		}
	}
	for _, h := range hs {
		b := s.hours[site][h]
		d.merge(b)
		d.Series = append(d.Series, Point{T: h, Stat: b.Stat, UpErr: b.UpErrN})
	}
	d.trim()
	return d
}

// Flush writes the days that changed and drops hours older than two days.
func (s *Store) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()
	now := time.Now()
	var errs []error
	for site, days := range s.dirty {
		for day := range days {
			d := s.rollup(site, day)
			if s.days[site] == nil {
				s.days[site] = map[int64]*Bucket{}
			}
			s.days[site][day] = d
			f := dayFile{Day: d}
			end := time.Unix(day, 0).AddDate(0, 0, 1).Unix()
			for h, b := range s.hours[site] {
				if h >= day && h < end {
					f.Hours = append(f.Hours, b)
				}
			}
			slices.SortFunc(f.Hours, func(a, b *Bucket) int { return cmp.Compare(a.Start, b.Start) })
			if err := s.write(site, day, f); err != nil {
				errs = append(errs, err)
				continue
			}
			delete(days, day)
		}
	}
	cut := cutDay(now)
	for _, hs := range s.hours {
		for h, b := range hs {
			switch {
			case h < cut:
				delete(hs, h) // its day was written above or earlier
			case h < hourOf(now):
				b.trim() // a finished hour no longer grows
			}
		}
	}
	if len(errs) == 0 {
		s.prune(now)
	}
	return errors.Join(errs...)
}

// prune forgets and deletes days beyond the retention.
func (s *Store) prune(now time.Time) {
	if s.Retention <= 0 {
		return
	}
	for site, days := range s.days {
		for day := range days {
			if now.Sub(time.Unix(day, 0)) > s.Retention+24*time.Hour {
				delete(days, day)
				os.Remove(s.path(site, day))
			}
		}
	}
}

func (s *Store) path(site string, day int64) string {
	return filepath.Join(s.Dir, site, time.Unix(day, 0).Format("2006-01-02")+".json.gz")
}

func (s *Store) write(site string, day int64, f dayFile) error {
	p := s.path(site, day)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".day-*")
	if err != nil {
		return err
	}
	zw := gzip.NewWriter(tmp)
	err = json.NewEncoder(zw).Encode(f)
	if e := zw.Close(); err == nil {
		err = e
	}
	if e := tmp.Close(); err == nil {
		err = e
	}
	if err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), p)
}

// Load reads the day rollups within the retention and the hours of the
// last two days.
func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()
	cut := cutDay(time.Now())
	return filepath.WalkDir(s.Dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".json.gz") || strings.HasPrefix(d.Name(), ".") {
			return nil
		}
		site := filepath.Base(filepath.Dir(p))
		day, err := time.ParseInLocation("2006-01-02", strings.TrimSuffix(d.Name(), ".json.gz"), time.Local)
		if err != nil {
			return nil
		}
		if s.Retention > 0 && time.Since(day) > s.Retention+24*time.Hour {
			return os.Remove(p)
		}
		f, err := readDay(p)
		if err != nil || f.Day == nil {
			return nil // a damaged file only loses its day
		}
		if s.days[site] == nil {
			s.days[site] = map[int64]*Bucket{}
		}
		s.days[site][day.Unix()] = f.Day
		for _, h := range f.Hours {
			if h.Start >= cut {
				if s.hours[site] == nil {
					s.hours[site] = map[int64]*Bucket{}
					s.dirty[site] = map[int64]bool{}
				}
				s.hours[site][h.Start] = h
			}
		}
		return nil
	})
}

func readDay(p string) (dayFile, error) {
	var f dayFile
	fh, err := os.Open(p)
	if err != nil {
		return f, err
	}
	defer fh.Close()
	zr, err := gzip.NewReader(fh)
	if err != nil {
		return f, err
	}
	err = json.NewDecoder(zr).Decode(&f)
	return f, err
}

// Sites lists the sites that have data.
func (s *Store) Sites() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	set := map[string]bool{}
	for k := range s.hours {
		set[k] = true
	}
	for k := range s.days {
		set[k] = true
	}
	return slices.Sorted(maps.Keys(set))
}

// Query merges the data of sites (all when empty) between from and to.
// Up to two days back it uses hourly buckets and returns an hourly
// series; further back it uses day rollups, with an hourly series up to
// seven days and a daily one beyond.
func (s *Store) Query(sites []string, from, to time.Time) *Bucket {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()
	if len(sites) == 0 {
		for k := range s.hours {
			sites = append(sites, k)
		}
		for k := range s.days {
			if !slices.Contains(sites, k) {
				sites = append(sites, k)
			}
		}
	}
	out := &Bucket{Start: from.Unix()}
	series := map[int64]*Point{}
	addPoint := func(t int64, st Stat, up int64) {
		p := series[t]
		if p == nil {
			p = &Point{T: t}
			series[t] = p
		}
		p.add(st)
		p.UpErr += up
	}
	span := to.Sub(from)
	hourly := span <= keepHours*time.Hour
	for _, site := range sites {
		if hourly {
			for h, b := range s.hours[site] {
				if h >= hourOf(from) && h < to.Unix() {
					out.merge(b)
					addPoint(h, b.Stat, b.UpErrN)
				}
			}
			continue
		}
		today := dayOf(time.Now())
		for day, b := range s.days[site] {
			if day < dayOf(from) || day >= to.Unix() {
				continue
			}
			if day >= today-86400 { // today and yesterday: hours are fresher
				continue
			}
			out.merge(b)
			if span <= 8*24*time.Hour {
				for _, p := range b.Series {
					addPoint(p.T, p.Stat, p.UpErr)
				}
			} else {
				addPoint(day, b.Stat, b.UpErrN)
			}
		}
		for h, b := range s.hours[site] {
			if h < today-86400 || h < from.Unix() {
				continue
			}
			out.merge(b)
			if span <= 8*24*time.Hour {
				addPoint(h, b.Stat, b.UpErrN)
			} else {
				addPoint(dayOf(time.Unix(h, 0)), b.Stat, b.UpErrN)
			}
		}
	}
	for _, p := range series {
		out.Series = append(out.Series, *p)
	}
	slices.SortFunc(out.Series, func(a, b Point) int { return cmp.Compare(a.T, b.T) })
	return out
}
