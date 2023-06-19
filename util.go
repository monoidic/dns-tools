package main

import (
	"fmt"
	"math/rand"
	"reflect"
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
		afterKnown: [2]string{steps[0], ""},
	}
	ret[n-1] = splitRange{
		prevKnown: [2]string{zone, steps[n-2]},
	}

	for i := 1; i < n-1; i++ {
		ret[i] = splitRange{
			prevKnown:  [2]string{zone, steps[i-1]},
			afterKnown: [2]string{steps[i], ""},
		}
	}

	return ret
}

const fractChars = "0123456789abcdefghijklmnopqrstuvwxyz"

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

// return the element
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

// remove the element at a given index from the slice
func arrRemove[T any](arr []T, index int) []T {
	copy(arr[index:], arr[index+1:])
	return arr[:len(arr)-1]
}
