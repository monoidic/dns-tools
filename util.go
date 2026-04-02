package main

import (
	"cmp"
	"errors"
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

type labelConverter struct {
	alphabet    string
	mults       []big.Int
	maxLabelNum *big.Int
}

const (
	MAX_LABEL_LEN = 63
	MAX_NAME_LEN  = 255
)

func newLabelConverter(alphabet string) *labelConverter {
	mults := make([]big.Int, MAX_LABEL_LEN)
	alphaLen := big.NewInt(int64(len(alphabet)))
	iter := big.NewInt(0)

	for i := range MAX_LABEL_LEN {
		iter.Mul(iter, alphaLen)
		iter.Add(iter, big1)
		mults[i].Set(iter)
	}

	iter.Mul(iter, alphaLen)
	iter.Sub(iter, big1)

	return &labelConverter{
		alphabet:    alphabet,
		mults:       mults,
		maxLabelNum: iter,
	}
}

var (
	bigneg1 = big.NewInt(-1)
	big0    = big.NewInt(0)
	big1    = big.NewInt(1)
)

// converts a DNS label into a bigint
func (lc *labelConverter) labelToNum(labelS string) (*big.Int, error) {
	label := []byte(labelS)
	if !(1 <= len(label) && len(label) <= MAX_LABEL_LEN) {
		return nil, errInvalidLabel
	}

	multI := MAX_LABEL_LEN - 1

	tmp := &big.Int{}

	ret := (&big.Int{}).SetInt64(int64(len(label) - 1))

	for _, v := range label {
		idx := strings.IndexByte(lc.alphabet, v)
		if idx == -1 {
			return nil, errLabelCharset
		}
		tmp.SetInt64(int64(idx))
		tmp.Mul(tmp, &lc.mults[multI])
		ret.Add(ret, tmp)
		multI--
	}

	return ret, nil
}

// convert a bigint into a DNS label
func (lc *labelConverter) numToLabel(num *big.Int) (string, error) {
	if !lc.numValid(num) {
		return "", errInvalidLabelNum
	}

	// local copy
	num = (&big.Int{}).Set(num)

	multI := MAX_LABEL_LEN - 1

	var ret []byte
	chunk := &big.Int{}

	for num.Cmp(bigneg1) == 1 {
		chunk.QuoRem(num, &lc.mults[multI], num)
		ret = append(ret, lc.alphabet[chunk.Uint64()])

		num.Sub(num, big1)
		multI--
	}

	return string(ret), nil
}

func (lc *labelConverter) numValid(num *big.Int) bool {
	return num.Cmp(big0) >= 0 && num.Cmp(lc.maxLabelNum) <= 0
}

func (lc *labelConverter) prevWithLen(num *big.Int, length int, repeatOk bool) (*big.Int, bool) {
	if !lc.numValid(num) {
		return nil, false
	}

	// local copy
	num = (&big.Int{}).Set(num)

	if !repeatOk {
		// ensure we can't just return the same value
		num.Sub(num, big1)
	}

	tmp := &big.Int{}

	for {
		if num.Cmp(big0) == -1 {
			return nil, false
		}

		label, err := lc.numToLabel(num)
		if err != nil {
			return nil, false
		}

		switch cmp.Compare(len(label), length) {
		case 0: // match
			return num, true
		case -1: // current label is shorter than target
			tmp.SetInt64(int64(len(label) - 1))
			num.Sub(num, tmp)
		case 1: // current label is longer than target
			// seek back from e.g "abc" to "aba", then back 1 to "ab"
			// num -= label[-1] * mult[-len(label)]
			v := strings.IndexByte(lc.alphabet, label[len(label)-1])
			tmp.SetInt64(int64(v))
			tmp.Mul(tmp, &lc.mults[MAX_LABEL_LEN-len(label)])
			tmp.Add(tmp, big1)

			num.Sub(num, tmp)
		}
	}
}

func (lc *labelConverter) nextWithLen(num *big.Int, length int, repeatOk bool) (*big.Int, bool) {
	if !lc.numValid(num) {
		return nil, false
	}

	// local copy
	num = (&big.Int{}).Set(num)

	if !repeatOk {
		// ensure we can't just return the same value
		num.Add(num, big1)
	}

	tmp := &big.Int{}

	for {
		if num.Cmp(lc.maxLabelNum) == 1 {
			return nil, false
		}

		label, err := lc.numToLabel(num)
		if err != nil {
			return nil, false
		}

		switch cmp.Compare(len(label), length) {
		case 0: // match
			return num, true
		case -1: // current label is shorter than target
			// just walk forwards by the diff lol
			//			log.Printf("%s -1 iter %d", num, iterNum)
			tmp.SetInt64(int64(length - len(label)))
			num.Add(num, tmp)
		case 1: // current label is longer than target
			// go to next break on this label length
			// num += (len(alphabet)-label[-1]) * mult[len(label)-1]
			//			log.Printf("%s 1 length %d iter %d", num, length, iterNum)
			v := len(lc.alphabet) - strings.IndexByte(lc.alphabet, label[len(label)-1])
			tmp.SetInt64(int64(v))
			tmp.Mul(tmp, &lc.mults[MAX_LABEL_LEN-len(label)])

			num.Add(num, tmp)
		}
	}
}

func (lc *labelConverter) bisectLabel(start, end *big.Int, length int) iter.Seq[string] {
	// TODO use length for calculating division mask or something
	// TODO FINISH THIS FUNCTION
	return func(yield func(string) bool) {
		var mid big.Int

		rnd := rand.New(rand.NewSource(rand.Int63()))

		// get a random number in the range of start to end
		mid.Sub(end, start)
		mid.Rand(rnd, &mid)
		mid.Add(start, &mid)

		label, err := lc.numToLabel(&mid)
		if err != nil {
			return
		}

		if len(label) == length {
			if !yield(label) {
				return
			}
		}

		for _, f := range []func(*big.Int, int, bool) (*big.Int, bool){lc.nextWithLen, lc.prevWithLen} {
			num, ok := f(&mid, length, false)
			if !ok {
				continue
			}
			label, err := lc.numToLabel(num)
			if err != nil {
				continue
			}
			if !yield(label) {
				return
			}
		}
	}
}

var (
	// very limited range
	lcAscii = newLabelConverter("-0123456789_abcdefghijklmnopqrstuvwxyz")
	// more symbols
	lcSymbols = newLabelConverter("!#$%&*+-/0123456789:;<=>?@[]^_`abcdefghijklmnopqrstuvwxyz{|}~")
	// full valid label range
	lcFull             = newLabelConverter("\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")
	errInvalidLabel    = errors.New("invalid label for this label converter")
	errInvalidLabelNum = errors.New("invalid label num for this label converter")
	errLabelCharset    = errors.New("invalid label for given label converter")
)

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
