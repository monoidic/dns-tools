package main

import (
	"fmt"
	"iter"
	"math"
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

const fractChars = "0123456789-abcdefghijklmnopqrstuvwxyz"

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

	for i := range length {
		idx := int(fract * fractLenF)
		if idx == fractLen {
			idx = fractLen - 1
		}
		buf[i] = fractChars[idx]
		fract = (fract - float64(idx)/fractLenF) * fractLenF
		if fract < 0 {
			fract = 0
		}
	}

	return string(buf)
}

// converts a string into a fraction [0-1)
func stringFract(s string) float64 {
	var ret float64
	for i, c := range s {
		ret += fractIndexes[c] / math.Pow(float64(len(fractChars)), float64(i+1))
	}
	return ret
}

func splitAscii(start, end float64, n, length int) iter.Seq[string] {
	return func(yield func(string) bool) {
		diff := (end - start) / float64(n)
		for i := 1; i < n; i++ {
			s := fractString(start+(diff*float64(i)), length)
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
