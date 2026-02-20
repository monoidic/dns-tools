package main

import (
	"fmt"
	"iter"
	"math/big"
	"math/rand"
	"net/netip"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/monoidic/dns"
)

func chanWorkers[T any](ch chan T, n int, f func()) {
	var wg sync.WaitGroup
	for range n {
		wg.Go(f)
	}
	go func() {
		wg.Wait()
		close(ch)
	}()
}

type Set[T comparable] map[T]empty

func (s Set[T]) Contains(key T) bool {
	_, ret := s[key]
	return ret
}

func (s Set[T]) Add(key T) {
	s[key] = empty{}
}

func (s Set[T]) Delete(key T) {
	delete(s, key)
}

func (s Set[T]) String() string {
	var b strings.Builder
	check1(b.WriteString(reflect.TypeOf(s).Name())) // e.g "Set[string]"
	check(b.WriteByte('{'))

	var addComma bool

	for e := range s {
		if addComma {
			b.WriteByte(',')
		} else {
			addComma = true
		}
		check1(b.WriteString(fmt.Sprintf("\"%#v\"", e)))
	}

	b.WriteByte('}')

	return b.String()
}

// select random nameserver from config
func randomNS() string {
	return usedNs[rand.Intn(usedNsLen)]
}

// given a CNAME chain, returns the final entry, and detect loops
func cnameChainFinalEntry(arr []dns.CNAME) (dns.Name, bool) {
	m := make(map[dns.Name]dns.Name, len(arr))
	for _, entry := range arr {
		m[entry.Hdr.Name.Canonical()] = m[entry.Target.Canonical()]
	}

	finalFrom := arr[len(arr)-1].Hdr.Name
	cnameLoop := true
	for range len(arr) {
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
	slices.Reverse(b)
	return string(b)
}

const labelChars = "-0123456789_abcdefghijklmnopqrstuvwxyz"

// (len(labelChars) ** 63) - 1
const maxLabelNum = "3360211291428788092142712546522052463429324340985584366991884014475006149629779669799771752913436671"

var fractIndexes = fractIndex()

func fractIndex() map[rune]int64 {
	ret := make(map[rune]int64, len(labelChars))
	for i, c := range labelChars {
		ret[c] = int64(i)
	}
	return ret
}

// convert a bigint into a DNS label
func numToLabel(num *big.Int, length int) string {
	if !(length >= 1 && length <= 63) {
		panic("invalid label length")
	}

	buf := make([]byte, length)
	var numIt, div, power, nFractChars, indexMult big.Int

	numIt.Set(num)
	nFractChars.SetInt64(int64(len(labelChars)))

	for i := range length {
		// div, numIt = divmod(numIt, pow(nFractChars, 62 - i))
		div.DivMod(
			&numIt,
			indexMult.Exp(
				&nFractChars,
				power.SetInt64(62-int64(i)),
				nil,
			),
			&numIt,
		)
		buf[i] = labelChars[div.Int64()]
	}

	return string(buf)
}

// converts a DNS label into a bigint
func labelToNum(s string) *big.Int {
	var ret, power, indexMult, indexNum, nFractChars big.Int
	nFractChars.SetInt64(int64(len(labelChars)))

	for i, c := range s {
		// ret += fractIndexes[c] * pow(nFractChars, 62 - i)
		ret.Add(&ret,
			indexNum.Mul(
				indexNum.SetInt64(fractIndexes[c]),
				indexMult.Exp(
					&nFractChars,
					power.SetInt64(62-int64(i)),
					nil,
				),
			),
		)
	}

	return &ret
}

func splitAscii(start, end *big.Int, n, length int) iter.Seq[string] {
	return func(yield func(string) bool) {
		var num, nBig, iBig, diff, itNum big.Int

		// diff = (end - start) / n
		diff.Div(
			num.Sub(end, start),
			nBig.SetInt64(int64(n)),
		)

		for i := 1; i < n; i++ {
			// itNum = start + i * diff
			itNum.Add(start, itNum.Mul(&diff, iBig.SetInt64(int64(i))))
			s := numToLabel(&itNum, length)
			if !yield(s) {
				break
			}
		}
	}
}

type retryWrap[inType, tmpType any] struct {
	// wrapped value
	val inType
	// in case state should be held inbetween stages
	tmp tmpType
	// decrement and reinsert if greater than zero,
	// otherwise use last returned value
	retriesLeft int
	// stage of the task
	stage int
}

type empty struct{}

func chanToSeq[T any](ch <-chan T) iter.Seq[T] {
	return func(yield func(T) bool) {
		for e := range ch {
			if !yield(e) {
				break
			}
		}
		// always exhaust chan
		for range ch {
		}
	}
}

func seqToChan[T any](seq iter.Seq[T], bufsize int) <-chan T {
	ch := make(chan T, bufsize)
	go func() {
		for e := range seq {
			ch <- e
		}
		close(ch)
	}()
	return ch
}

func bufferedSeq[T any](seq iter.Seq[T], bufsize int) iter.Seq[T] {
	ch := make(chan T, bufsize)
	var done bool

	go func() {
		for e := range seq {
			if done {
				break
			}
			ch <- e
		}
		close(ch)
	}()

	return func(yield func(T) bool) {
		for e := range ch {
			if !yield(e) {
				break
			}
		}
		done = true
	}
}

func priorityChanGen[T any]() (inLow, inHigh, out chan T, stop func()) {
	inLow = make(chan T, MIDBUFLEN)
	inHigh = make(chan T, MIDBUFLEN)
	out = make(chan T, MIDBUFLEN)

	doneCh := make(chan empty)

	stop = func() {
		doneCh <- empty{}
	}

	go func() {
		for {
			var val T
			select {
			case <-doneCh:
				close(out)
				close(inHigh)
				close(inLow)
				return
			default:
				select {
				case val = <-inHigh:
				default:
					select {
					case val = <-inHigh:
					case val = <-inLow:
					case <-doneCh:
						close(out)
						close(inHigh)
						close(inLow)
						return
					}
				}
			}
			out <- val
		}
	}()

	return inLow, inHigh, out, stop
}

var ptrV6Pattern = regexp.MustCompile("....")

// convert full-length PTR name (v4 or v6), e.g 4.3.2.1.in-addr.arpa, to the netip.Addr for the corresponding IP address (1.2.3.4 for the given example)
func ptrToIP(d dns.Name) (netip.Addr, error) {
	s := d.String()
	if strings.HasSuffix(s, ".ip6.arpa.") {
		s = s[:len(s)-len(".ip6.arpa.")]
		s = strings.ReplaceAll(s, ".", "")
		s = reverseASCII(s)
		s = strings.Join(ptrV6Pattern.FindAllString(s, -1), ":")
	} else if strings.HasSuffix(s, ".in-addr.arpa.") {
		s = s[:len(s)-len(".in-addr.arpa.")]
		l := strings.Split(s, ".")
		slices.Reverse(l)
		s = strings.Join(l, ".")
	} else {
		return netip.Addr{}, Error{s: fmt.Sprintf("invalid addr: %q", s)}
	}
	return netip.ParseAddr(s)
}
