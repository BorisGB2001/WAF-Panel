package analytics

import (
	"encoding/base64"
	"encoding/json"
	"hash/fnv"
	"math"
	"math/bits"
)

// hllP gives 2^11 registers: about 2.3% error in 2 KiB per counter.
const (
	hllP = 11
	hllM = 1 << hllP
)

// HLL is a HyperLogLog distinct counter. Counters of hours merge into
// days and days into months, which plain per-hour unique counts cannot.
type HLL struct{ reg []uint8 }

func hash64(s string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(s))
	// splitmix64 finalizer: FNV alone spreads short keys poorly.
	x := h.Sum64()
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}

func (h *HLL) Add(s string) {
	if h.reg == nil {
		h.reg = make([]uint8, hllM)
	}
	x := hash64(s)
	i := x >> (64 - hllP)
	rank := uint8(bits.LeadingZeros64(x<<hllP|1<<(hllP-1)) + 1)
	if rank > h.reg[i] {
		h.reg[i] = rank
	}
}

func (h *HLL) Merge(o *HLL) {
	if o == nil || o.reg == nil {
		return
	}
	if h.reg == nil {
		h.reg = make([]uint8, hllM)
	}
	for i, v := range o.reg {
		if v > h.reg[i] {
			h.reg[i] = v
		}
	}
}

// Count estimates the number of distinct values added.
func (h *HLL) Count() int64 {
	if h == nil || h.reg == nil {
		return 0
	}
	sum, zeros := 0.0, 0
	for _, v := range h.reg {
		sum += 1 / float64(uint64(1)<<v)
		if v == 0 {
			zeros++
		}
	}
	m := float64(hllM)
	est := 0.7213 / (1 + 1.079/m) * m * m / sum
	if est <= 2.5*m && zeros > 0 {
		est = m * math.Log(m/float64(zeros)) // linear counting for small sets
	}
	return int64(est + 0.5)
}

func (h HLL) MarshalJSON() ([]byte, error) {
	if h.reg == nil {
		return []byte(`""`), nil
	}
	return json.Marshal(base64.StdEncoding.EncodeToString(h.reg))
}

func (h *HLL) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if s == "" {
		h.reg = nil
		return nil
	}
	reg, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(reg) != hllM {
		h.reg = nil
		return nil
	}
	h.reg = reg
	return nil
}
