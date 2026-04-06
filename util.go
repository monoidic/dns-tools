package main

import (
	"fmt"
	"iter"
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
	check1(b.WriteString(reflect.TypeFor[Set[T]]().Name())) // e.g "Set[string]"
	check(b.WriteByte('{'))

	var addComma bool

	for e := range s {
		if addComma {
			b.WriteByte(',')
		} else {
			addComma = true
		}
		check1(fmt.Fprintf(&b, "%#v", e))
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
		defer func() {
			done = true
		}()
		for e := range ch {
			if !yield(e) {
				return
			}
		}
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

func filteredNsecs(zone dns.Name, msg *dns.Msg) ([]*dns.NSEC, []*dns.NSEC3) {
	var signatures []*dns.RRSIG
	var nsecSigs []*dns.NSEC
	var nsec3Sigs []*dns.NSEC3

	for _, rr := range msg.Ns { // authority section
		switch rrT := rr.(type) {
		case *dns.RRSIG:
			switch rrT.TypeCovered {
			case dns.TypeNSEC, dns.TypeNSEC3:
				dns.Canonicalize(rrT)
				if rrT.SignerName == zone {
					signatures = append(signatures, rrT)
				}
			}
		case *dns.NSEC:
			dns.Canonicalize(rrT)
			nsecSigs = append(nsecSigs, rrT)
		case *dns.NSEC3:
			dns.Canonicalize(rrT)
			nsec3Sigs = append(nsec3Sigs, rrT)
		}
	}

nsecLoop:
	for i, rrT := range nsecSigs {
		for _, sig := range signatures {
			if sig.Hdr.Name == rrT.Hdr.Name {
				continue nsecLoop
			}
		}
		// no match
		nsecSigs[i] = nil
	}

nsec3Loop:
	for i, rrT := range nsec3Sigs {
		for _, sig := range signatures {
			if sig.Hdr.Name == rrT.Hdr.Name {
				continue nsec3Loop
			}
		}
		// no match
		nsec3Sigs[i] = nil
	}

	// remove non-matches
	nsecSigs = slices.DeleteFunc(nsecSigs, func(rrT *dns.NSEC) bool { return rrT == nil })
	nsec3Sigs = slices.DeleteFunc(nsec3Sigs, func(rrT *dns.NSEC3) bool { return rrT == nil })

	return nsecSigs, nsec3Sigs
}
