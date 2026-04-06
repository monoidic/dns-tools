package main

import (
	"cmp"
	"errors"
	"iter"
	"math/big"
	"math/rand"
	"slices"
	"strings"

	"github.com/monoidic/dns"
)

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
	lcFull = newLabelConverter("\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

	ncAscii   = newNameConverter("-0123456789_abcdefghijklmnopqrstuvwxyz")
	ncSymbols = newNameConverter("!#$%&*+-/0123456789:;<=>?@[]^_`abcdefghijklmnopqrstuvwxyz{|}~")
	ncFull    = newNameConverter("\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#$%&'()*+,-./0123456789:;<=>?@[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

	errInvalidLabel    = errors.New("invalid label for this label converter")
	errInvalidLabelNum = errors.New("invalid label num for this label converter")
	errLabelCharset    = errors.New("invalid label for this label converter")

	errNameCharset           = errors.New("invalid name for this name converter")
	errInvalidNameNum        = errors.New("invalid name num for this name converter")
	errNameTooLongForZoneEnd = errors.New("name too long for zone end calculation")
)

type nameConverter struct {
	alphabet    string
	alphaLen    *big.Int
	maxNameNum  *big.Int
	stepDiffs   [MAX_NAME_LEN - 2][MAX_LABEL_LEN]big.Int
	expandDiffs [MAX_NAME_LEN - 2]big.Int
}

func newNameConverter(alphabet string) *nameConverter {
	ret := &nameConverter{
		alphabet: alphabet,
		alphaLen: big.NewInt(int64(len(alphabet))),
	}

	// expandDiffs relies on stepDiffs
	ret.mkStepDiffs()
	ret.mkExpandDiffs()

	ret.maxNameNum = (&big.Int{}).Set(&ret.stepDiffs[MAX_NAME_LEN-3][0])
	ret.maxNameNum.Mul(ret.maxNameNum, ret.alphaLen)

	return ret
}

func (nc *nameConverter) mkStepDiffs() {
	nc.mkStepDiffsRecurse(MAX_NAME_LEN-3, 0)
}

func (nc *nameConverter) mkStepDiffsRecurse(spacesToLeft, leftmostLabelLen int) *big.Int {
	num := &nc.stepDiffs[spacesToLeft][leftmostLabelLen]
	if num.Cmp(big0) != 0 {
		return num
	}

	roomForNewLabel := spacesToLeft >= 2
	roomForLabelExpansion := spacesToLeft >= 1 && (leftmostLabelLen+1) < MAX_LABEL_LEN

	if roomForNewLabel {
		addend := nc.mkStepDiffsRecurse(spacesToLeft-2, 0)
		num.Add(num, addend)
	}

	if roomForLabelExpansion {
		addend := nc.mkStepDiffsRecurse(spacesToLeft-1, leftmostLabelLen+1)
		num.Add(num, addend)
	}

	num.Mul(num, nc.alphaLen)
	num.Add(num, big1)

	// already updated in nc.stepDiffs
	return num
}

func (nc *nameConverter) mkExpandDiffs() {
	// expandDiffs should be set already lol
	for spacesToLeft := 1; spacesToLeft < MAX_NAME_LEN-1; spacesToLeft++ {
		idx := MAX_NAME_LEN - 4 - spacesToLeft
		num := &nc.expandDiffs[spacesToLeft-1]
		if idx < 0 {
			num.SetInt64(1)
			continue
		}
		num.Set(&nc.stepDiffs[idx][0])
		num.Mul(num, nc.alphaLen)
		num.Add(num, big1)
	}
}

func (nc *nameConverter) nameToNum(name dns.Name) (*big.Int, error) {
	labels := name.SplitRaw()

	num := big.NewInt(0)
	tmp := &big.Int{}

	for len(labels) > 0 {
		firstLabel := labels[0]

		// stray end label
		if firstLabel == nc.alphabet[:1] {
			num.Add(num, big1)
			labels = labels[1:]
			continue
		}

		currentNameLen := len(labels) + 1
		for _, label := range labels {
			currentNameLen += len(label)
		}

		spacesToLeft := MAX_NAME_LEN - currentNameLen
		lastChar := firstLabel[len(firstLabel)-1:]

		// negate expansion
		if lastChar == nc.alphabet[:1] {
			idx := MAX_NAME_LEN - spacesToLeft - 3 - 1
			expand := &nc.expandDiffs[idx]

			num.Add(num, expand)
			labels[0] = firstLabel[:len(firstLabel)-1]
			continue
		}

		// step
		leftmostLabelLen := len(firstLabel)
		step := &nc.stepDiffs[spacesToLeft][leftmostLabelLen-1]

		stepOff := strings.Index(nc.alphabet, lastChar)
		if stepOff == -1 {
			return nil, errNameCharset
		}

		tmp.SetInt64(int64(stepOff))
		tmp.Mul(tmp, step)

		num.Add(num, tmp)
		labels[0] = firstLabel[:leftmostLabelLen-1] + nc.alphabet[:1]
	}

	return num, nil
}

func (nc *nameConverter) numToName(num *big.Int) (dns.Name, error) {
	if !(num != nil && num.Cmp(big0) >= 0 && num.Cmp(nc.maxNameNum) <= 0) {
		return dns.Name{}, errInvalidNameNum
	}
	var labelsB [][]byte

	if num.Cmp(big0) == 0 {
		return dns.NameFromString(".")
	}

	num.Sub(num, big1)
	labelsB = [][]byte{{nc.alphabet[0]}}

	steps := &big.Int{}

	for num.Cmp(big0) == 1 {
		firstLabel := labelsB[0]
		lastChar := string(firstLabel[len(firstLabel)-1:])

		// step
		currentNameLen := len(labelsB) + 1
		for _, label := range labelsB {
			currentNameLen += len(label)
		}

		spacesToLeft := MAX_NAME_LEN - currentNameLen
		leftmostLabelLen := len(firstLabel)
		step := &nc.stepDiffs[spacesToLeft][leftmostLabelLen-1]

		steps.QuoRem(num, step, num)
		if steps.Cmp(big0) == 1 {
			vIDX := strings.Index(nc.alphabet, lastChar)
			vIDX += int(steps.Int64())
			v := nc.alphabet[vIDX]

			// labelsB[0] = firstLabel[:len(firstLabel)-2] + v
			labelsB[0][leftmostLabelLen-1] = v
			continue
		}

		// expand
		idx := MAX_NAME_LEN - spacesToLeft - 3
		if leftmostLabelLen < MAX_LABEL_LEN && idx >= 0 {
			expand := &nc.expandDiffs[idx]
			if expand.Cmp(num) <= 0 {
				num.Sub(num, expand)
				labelsB[0] = append(labelsB[0], nc.alphabet[0])
				continue
			}
		}

		// add new label
		num.Sub(num, big1)
		labelsB = slices.Insert(labelsB, 0, []byte{nc.alphabet[0]})
	}

	labels := make([]string, len(labelsB))
	for i, v := range labelsB {
		labels[i] = string(v)
	}

	return dns.NameFromLabels(labels)
}

// last encodable name still falling under the given zone forin the given alphabet
func (nc *nameConverter) getZoneEndNum(zone dns.Name) (*big.Int, error) {
	idx := MAX_NAME_LEN - zone.EncodedLen() - 2
	if idx < 0 {
		return nil, errNameTooLongForZoneEnd
	}

	num, err := nc.nameToNum(zone)
	if err != nil {
		return nil, err
	}

	tmp := (&big.Int{}).Set(&nc.stepDiffs[idx][0])
	tmp.Mul(tmp, nc.alphaLen)

	num.Add(num, tmp)

	return num, nil
}
