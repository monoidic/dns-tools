package main

import (
	"fmt"
	"iter"
	"math/big"
	"math/rand"
	"reflect"
	"slices"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/monoidic/rangeset"
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

func makeSet[T comparable](l []T) Set[T] {
	ret := make(Set[T], len(l))
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

type splitRange struct {
	prevKnown  rangeset.RangeEntry[string]
	afterKnown rangeset.RangeEntry[string]
}

const fractChars = "-0123456789abcdefghijklmnopqrstuvwxyz"

var fractIndexes = fractIndex()

func fractIndex() map[rune]int64 {
	ret := make(map[rune]int64, len(fractChars))
	for i, c := range fractChars {
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
	nFractChars.SetInt64(int64(len(fractChars)))

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
		buf[i] = fractChars[div.Int64()]
	}

	return string(buf)
}

// converts a DNS label into a bigint
func labelToNum(s string) *big.Int {
	var ret, power, indexMult, indexNum, nFractChars big.Int
	nFractChars.SetInt64(int64(len(fractChars)))

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

func collect[T any](seq iter.Seq[T]) []T {
	var ret []T
	for e := range seq {
		ret = append(ret, e)
	}
	return ret
}

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
