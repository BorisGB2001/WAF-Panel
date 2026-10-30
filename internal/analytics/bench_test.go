package analytics

import "testing"

func BenchmarkLine(b *testing.B) {
	st := &Store{Dir: b.TempDir()}
	c := &Collector{Store: st}
	f := c.access("4")
	for i := 0; i < b.N; i++ {
		f(sample)
	}
}
