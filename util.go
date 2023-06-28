package main

import (
	"fmt"
	"log"
	"math"
	"math/rand"
	"reflect"
	"sort"
	"strings"
	"sync"

	"github.com/monoidic/dns"
)

func normalizeRR(rr dns.RR) {
	hdr := rr.Header()
	hdr.Name = strings.ToLower(hdr.Name)
	hdr.Ttl = 0

	switch rrT := rr.(type) {
	case *dns.NS:
		rrT.Ns = strings.ToLower(rrT.Ns)
	case *dns.CNAME:
		rrT.Target = strings.ToLower(rrT.Target)
	case *dns.DNAME:
		rrT.Target = strings.ToLower(rrT.Target)
	case *dns.MX:
		rrT.Mx = strings.ToLower(rrT.Mx)
	case *dns.PTR:
		rrT.Ptr = strings.ToLower(rrT.Ptr)
	case *dns.SOA:
		rrT.Ns = strings.ToLower(rrT.Ns)
		rrT.Mbox = strings.ToLower(rrT.Mbox)
	case *dns.NSEC:
		rrT.NextDomain = strings.ToLower(rrT.NextDomain)

	case *dns.MB:
		rrT.Mb = strings.ToLower(rrT.Mb)
	case *dns.MG:
		rrT.Mg = strings.ToLower(rrT.Mg)
	case *dns.MINFO:
		rrT.Rmail = strings.ToLower(rrT.Rmail)
		rrT.Email = strings.ToLower(rrT.Email)
	case *dns.MR:
		rrT.Mr = strings.ToLower(rrT.Mr)
	case *dns.MF:
		rrT.Mf = strings.ToLower(rrT.Mf)
	case *dns.MD:
		rrT.Md = strings.ToLower(rrT.Md)
	case *dns.AFSDB:
		rrT.Hostname = strings.ToLower(rrT.Hostname)
	case *dns.RT:
		rrT.Host = strings.ToLower(rrT.Host)
	case *dns.RP:
		rrT.Mbox = strings.ToLower(rrT.Mbox)
		rrT.Txt = strings.ToLower(rrT.Txt)
	case *dns.SRV:
		rrT.Target = strings.ToLower(rrT.Target)
	case *dns.NAPTR:
		rrT.Replacement = strings.ToLower(rrT.Replacement)
	case *dns.PX:
		rrT.Map822 = strings.ToLower(rrT.Map822)
		rrT.Mapx400 = strings.ToLower(rrT.Mapx400)
	case *dns.RRSIG:
		rrT.SignerName = strings.ToLower(rrT.SignerName)
	case *dns.KX:
		rrT.Exchanger = strings.ToLower(rrT.Exchanger)
	case *dns.TALINK:
		rrT.PreviousName = strings.ToLower(rrT.PreviousName)
		rrT.NextName = strings.ToLower(rrT.NextName)
	case *dns.IPSECKEY:
		rrT.GatewayHost = strings.ToLower(rrT.GatewayHost)
	case *dns.AMTRELAY:
		rrT.GatewayHost = strings.ToLower(rrT.GatewayHost)
	case *dns.NSAPPTR:
		rrT.Ptr = strings.ToLower(rrT.Ptr)
	case *dns.HIP:
		for i, v := range rrT.RendezvousServers {
			rrT.RendezvousServers[i] = strings.ToLower(v)
		}
	case *dns.LP:
		rrT.Fqdn = strings.ToLower(rrT.Fqdn)
	}
}

func closeChanWait[T any](wg *sync.WaitGroup, ch chan T) {
	wg.Wait()
	close(ch)
}

type Set[T comparable] map[T]struct{}

func (s Set[T]) Contains(key T) bool {
	_, ret := s[key]
	return ret
}

func (s Set[T]) Add(key T) {
	s[key] = struct{}{}
}

func (s Set[T]) Delete(key T) {
	delete(s, key)
}

func (s Set[T]) String() string {
	var b strings.Builder
	check1(b.WriteString(reflect.TypeOf(s).Name())) // e.g "Set[string]"
	check(b.WriteByte('{'))

	first := true
	for e := range s {
		if !first {
			check1(b.WriteString(", "))
		} else {
			first = false
		}
		check1(b.WriteString(fmt.Sprintf("\"%#v\"", e)))
	}

	check(b.WriteByte('}'))

	return b.String()
}

func makeSet[T comparable](l []T) Set[T] {
	ret := make(Set[T])
	for _, k := range l {
		ret.Add(k)
	}
	return ret
}

// select random nameserver from config
func randomNS() string {
	return usedNs[rand.Intn(usedNsLen)]
}

// given a CNAME chain, returns the final entry, and detect loops
func cnameChainFinalEntry(arr []dns.CNAME) (string, bool) {
	m := make(map[string]string, len(arr))
	for _, entry := range arr {
		m[entry.Hdr.Name] = m[entry.Target]
	}

	finalFrom := arr[len(arr)-1].Hdr.Name
	cnameLoop := true
	for i := 0; i < len(arr); i++ {
		target, ok := m[finalFrom]
		if !ok {
			cnameLoop = false
			break
		}
		finalFrom = target
	}
	return finalFrom, cnameLoop
}

// reverse an ASCII string
func reverseASCII(s string) string {
	b := []byte(s)
	reverseList(b)
	return string(b)
}

// reverse a list
func reverseList[T any](l []T) {
	lLen := len(l)
	for i := 0; i < lLen/2; i++ {
		i2 := lLen - i - 1
		l[i], l[i2] = l[i2], l[i]
	}
}

type splitRange struct {
	prevKnown  [2]string
	afterKnown [2]string
}

// split the search space for nsec
func splitAscii(zone string, n, length int) []splitRange {
	if n == 1 {
		return []splitRange{{}}
	}

	steps := make([]string, n-1)

	for i := 0; i < n-1; i++ {
		steps[i] = fmt.Sprintf("%s.%s", fractString(float64(i+1)/float64(n), length), zone)
	}

	ret := make([]splitRange, n)

	ret[0] = splitRange{
		afterKnown: [2]string{steps[0], zone},
	}
	ret[n-1] = splitRange{
		prevKnown: [2]string{zone, steps[n-2]},
	}

	for i := 1; i < n-1; i++ {
		ret[i] = splitRange{
			prevKnown:  [2]string{zone, steps[i-1]},
			afterKnown: [2]string{steps[i], zone},
		}
	}

	return ret
}

const fractChars = "0123456789abcdefghijklmnopqrstuvwxyz"

var fractIndexes = fractIndex()

func fractIndex() map[rune]float64 {
	ret := make(map[rune]float64, len(fractChars))
	for i, c := range fractChars {
		ret[c] = float64(i)
	}
	return ret
}

// convert a fraction [0-1) into a string
func fractString(fract float64, length int) string {
	buf := make([]byte, length)
	fractLen := len(fractChars)
	fractLenF := float64(fractLen)

	for i := 0; i < length; i++ {
		idx := int(fract * fractLenF)
		if idx == fractLen {
			idx = fractLen - 1
		}
		buf[i] = fractChars[idx]
		fract = (fract - float64(idx)/fractLenF) * fractLenF
	}

	return string(buf)
}

// converts a string into a fraction [0-1)
func stringFract(s string) float64 {
	var ret float64
	for i, c := range s {
		ret += fractIndexes[c] / math.Pow(float64(len(fractChars)), float64(i+1))
		fmt.Printf("i=%d c=%c ret=%f\n", i, c, ret)
	}
	return ret
}

// inserts a value into an array at a given index;
// same semantics as append()
func arrInsert[T any](arr []T, index int, e T) []T {
	var tmp []T
	tmpLen := len(arr) + 1
	if cap(arr) > tmpLen {
		tmp = arr[:tmpLen]
	} else {
		tmp = make([]T, tmpLen)
		copy(tmp, arr[:index])
	}
	copy(tmp[index+1:], arr[index:])
	tmp[index] = e

	return tmp
}

func arrRemoveMulti[T any](arr []T, start, end int) []T {
	if start == end {
		return arr
	}
	if start > end {
		log.Panicf("incorrect indices start=%d and end=%d on %v", start, end, arr)
	}

	numRemoved := end - start
	newLen := len(arr) - numRemoved

	copy(arr[start:], arr[end:])
	return arr[:newLen]
}

// container for arbitrary ranges of values
type RangeSet[T any] struct {
	// the merged ranges
	Ranges [][2]T
	// a three-way comparison function like strcmp;
	// 0 for equality, -1 for v1 < v2, 1 for v1 > v2
	Compare func(v1, v2 T) int
	// a sentinel value indicating wrapping around from this value to the start
	// if HasWrap is true and the final value is this, then any value sorting after it
	// is considered within the range
	WrapV T
	// whether or not there is a "wraparound value"
	HasWrap bool
}

// helper to check whether a given value exists + return its index
func (r *RangeSet[T]) containsI(v T) (bool, int) {
	l := len(r.Ranges)
	if l == 0 {
		return false, 0
	}

	// whether or not the end of the last range is the wrap value
	endWraps := r.HasWrap && r.Compare(r.Ranges[l-1][1], r.WrapV) == 0

	i := sort.Search(l, func(i int) bool { return (endWraps && i == l-1) || r.Compare(r.Ranges[i][0], v) <= 0 })

	rn := r.Ranges[i]
	start, end := rn[0], rn[1]
	// value is in the wrapped area or within the range
	return (endWraps && i == l-1 && r.Compare(v, end) >= 0) || (r.Compare(v, end) == -1 && r.Compare(start, v) <= 0), i
}

// check whether a given value is contained within the range set
func (r *RangeSet[T]) Contains(v T) bool {
	ret, _ := r.containsI(v)
	return ret
}

// check whether a range is contained within the range set
func (r *RangeSet[T]) ContainsRange(start, end T) bool {
	// a range is contained entirely if both the start and end exist
	// and are contained within the same defined range
	startMatch, startI := r.containsI(start)
	if !startMatch {
		return false
	}
	endMatch, endI := r.containsI(end)
	return endMatch && startI == endI
}

// add a range, potentially expanding or merging existing ranges
func (r *RangeSet[T]) Add(start, end T) {
	l := len(r.Ranges)
	if l == 0 {
		// first range
		r.Ranges = [][2]T{{start, end}}
		return
	}

	// whether or not the end of the last range is the wrap value
	endWraps := r.HasWrap && r.Compare(r.Ranges[l-1][1], r.WrapV) == 0

	// index of the first range where the end of the range is greater than or equal to the given start value
	// (or just the last existing range if wraparound is in use and it falls within it)
	startI := sort.Search(l, func(i int) bool { return (endWraps && i == l-1) || r.Compare(r.Ranges[i][1], start) >= 0 })

	// similar to startI, but for the end range
	var endI int
	if r.HasWrap && r.Compare(end, r.WrapV) == 0 {
		// end is equal to the wrap value; always add to the end
		endI = l
	} else {
		endI = sort.Search(l, func(i int) bool { return (endWraps && i == l-1) || r.Compare(r.Ranges[i][1], end) >= 0 })
	}

	if startI != l {
		if r.Compare(start, r.Ranges[startI][0]) == 1 && ((r.HasWrap && r.Compare(r.Ranges[startI][1], r.WrapV) == 0) || r.Compare(start, r.Ranges[startI][1]) <= 0) {
			// given start value is within a range
			// extend left to the start of this range
			start = r.Ranges[startI][0]
		}

		// only possible if startI != l; also implicitly impossible
		// if end is the wrap value
		if endI != l {
			if r.Compare(end, r.Ranges[endI][0]) >= 0 {
				// given end value is within a range
				// extend right to the end of this range
				end = r.Ranges[endI][1]
				endI++
			}
		}
	}

	// remove (possibly empty) range of values which will be merged
	r.Ranges = arrRemoveMulti(r.Ranges, startI, endI)
	// insert (possibly merged from existing removed ranges) range
	r.Ranges = arrInsert(r.Ranges, startI, [2]T{start, end})
}
