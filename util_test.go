package main

import (
	"testing"

	"github.com/monoidic/dns"
)

func TestRanges(t *testing.T) {
	defaultStart := [][2]string{{"f.x.", "h.x."}, {"m.x.", "t.x."}, {"z.x.", "x."}}
	for _, datum := range []struct {
		start    [][2]string
		in       [2]string
		expected [][2]string
	}{
		// entirely before
		{in: [2]string{"a.x.", "b.x."}, expected: [][2]string{{"a.x.", "b.x."}, {"f.x.", "h.x."}, {"m.x.", "t.x."}, {"z.x.", "x."}}},
		// starts before, ends within first range
		{in: [2]string{"a.x.", "f.x."}, expected: [][2]string{{"a.x.", "h.x."}, {"m.x.", "t.x."}, {"z.x.", "x."}}},
		{in: [2]string{"a.x.", "g.x."}, expected: [][2]string{{"a.x.", "h.x."}, {"m.x.", "t.x."}, {"z.x.", "x."}}},
		{in: [2]string{"a.x.", "h.x."}, expected: [][2]string{{"a.x.", "h.x."}, {"m.x.", "t.x."}, {"z.x.", "x."}}},
		// starts before, ends between first and second
		{in: [2]string{"a.x.", "i.x."}, expected: [][2]string{{"a.x.", "i.x."}, {"m.x.", "t.x."}, {"z.x.", "x."}}},
		// starts before, ends within second range
		{in: [2]string{"a.x.", "m.x."}, expected: [][2]string{{"a.x.", "t.x."}, {"z.x.", "x."}}},
		{in: [2]string{"a.x.", "n.x."}, expected: [][2]string{{"a.x.", "t.x."}, {"z.x.", "x."}}},
		{in: [2]string{"a.x.", "t.x."}, expected: [][2]string{{"a.x.", "t.x."}, {"z.x.", "x."}}},
		// starts before first, ends after last range
		{in: [2]string{"a.x.", "v.x."}, expected: [][2]string{{"a.x.", "v.x."}, {"z.x.", "x."}}},

		// starts and ends in first
		{in: [2]string{"f.x.", "g.x."}, expected: [][2]string{{"f.x.", "h.x."}, {"m.x.", "t.x."}, {"z.x.", "x."}}},
		{in: [2]string{"f.x.", "h.x."}, expected: [][2]string{{"f.x.", "h.x."}, {"m.x.", "t.x."}, {"z.x.", "x."}}},
		// starts in first, ends between first and second
		{in: [2]string{"f.x.", "i.x."}, expected: [][2]string{{"f.x.", "i.x."}, {"m.x.", "t.x."}, {"z.x.", "x."}}},

		// between first and second
		{in: [2]string{"i.x.", "j.x."}, expected: [][2]string{{"f.x.", "h.x."}, {"i.x.", "j.x."}, {"m.x.", "t.x."}, {"z.x.", "x."}}},

		// starts between, ends in second
		{in: [2]string{"i.x.", "m.x."}, expected: [][2]string{{"f.x.", "h.x."}, {"i.x.", "t.x."}, {"z.x.", "x."}}},
		{in: [2]string{"i.x.", "n.x."}, expected: [][2]string{{"f.x.", "h.x."}, {"i.x.", "t.x."}, {"z.x.", "x."}}},
		{in: [2]string{"i.x.", "t.x."}, expected: [][2]string{{"f.x.", "h.x."}, {"i.x.", "t.x."}, {"z.x.", "x."}}},

		// starts in first, ends in second
		{in: [2]string{"f.x.", "t.x."}, expected: [][2]string{{"f.x.", "t.x."}, {"z.x.", "x."}}},
		{in: [2]string{"g.x.", "t.x."}, expected: [][2]string{{"f.x.", "t.x."}, {"z.x.", "x."}}},
		{in: [2]string{"h.x.", "t.x."}, expected: [][2]string{{"f.x.", "t.x."}, {"z.x.", "x."}}},
		{in: [2]string{"f.x.", "m.x."}, expected: [][2]string{{"f.x.", "t.x."}, {"z.x.", "x."}}},
		{in: [2]string{"f.x.", "n.x."}, expected: [][2]string{{"f.x.", "t.x."}, {"z.x.", "x."}}},

		// entirely after
		{in: [2]string{"u.x.", "v.x."}, expected: [][2]string{{"f.x.", "h.x."}, {"m.x.", "t.x."}, {"u.x.", "v.x."}, {"z.x.", "x."}}},

		// wrapping stuff
		// starts in first, wraps
		{in: [2]string{"a.x.", "x."}, expected: [][2]string{{"a.x.", "x."}}},

		{in: [2]string{"f.x.", "x."}, expected: [][2]string{{"f.x.", "x."}}},
		{in: [2]string{"g.x.", "x."}, expected: [][2]string{{"f.x.", "x."}}},
		{in: [2]string{"h.x.", "x."}, expected: [][2]string{{"f.x.", "x."}}},

		// starts between first and second, wraps
		{in: [2]string{"i.x.", "x."}, expected: [][2]string{{"f.x.", "h.x."}, {"i.x.", "x."}}},

		// starts in second, wraps
		{in: [2]string{"m.x.", "x."}, expected: [][2]string{{"f.x.", "h.x."}, {"m.x.", "x."}}},
		{in: [2]string{"n.x.", "x."}, expected: [][2]string{{"f.x.", "h.x."}, {"m.x.", "x."}}},
		{in: [2]string{"t.x.", "x."}, expected: [][2]string{{"f.x.", "h.x."}, {"m.x.", "x."}}},

		// starts after, wraps
		{in: [2]string{"v.x.", "x."}, expected: [][2]string{{"f.x.", "h.x."}, {"m.x.", "t.x."}, {"v.x.", "x."}}},

		// no-op merge with wrapping range
		{in: [2]string{"z.x.", "{.x."}, expected: [][2]string{{"f.x.", "h.x."}, {"m.x.", "t.x."}, {"z.x.", "x."}}},
		{in: [2]string{"{.x.", "}.x."}, expected: [][2]string{{"f.x.", "h.x."}, {"m.x.", "t.x."}, {"z.x.", "x."}}},
		{in: [2]string{"z.x.", "x."}, expected: [][2]string{{"f.x.", "h.x."}, {"m.x.", "t.x."}, {"z.x.", "x."}}},
		{in: [2]string{"{.x.", "x."}, expected: [][2]string{{"f.x.", "h.x."}, {"m.x.", "t.x."}, {"z.x.", "x."}}},

		// found in the wild
		{start: [][2]string{{"x.", "w.x."}, {"xr000.x.", "x."}}, in: [2]string{"w.x.", "x."}, expected: [][2]string{{"x.", "x."}}},
	} {
		start := defaultStart
		if datum.start != nil {
			start = datum.start
		}
		r := RangeSet[string]{Ranges: copyArr(start), Compare: dns.Compare, WrapV: "x.", HasWrap: true}
		r.Add(datum.in[0], datum.in[1])
		if !equals(r.Ranges, datum.expected) {
			t.Errorf("initial data: %v, input: %v, expected: %v, actual: %v", start, datum.in, datum.expected, r.Ranges)
			return
		}
	}
}

func equals[T comparable](a, b [][2]T) bool {
	if len(a) != len(b) {
		return false
	}
	for i, a_v := range a {
		b_v := b[i]
		if a_v[0] != b_v[0] || a_v[1] != b_v[1] {
			return false
		}
	}
	return true
}

func copyArr[T any](a []T) []T {
	ret := make([]T, len(a))
	copy(ret, a)
	return ret
}
