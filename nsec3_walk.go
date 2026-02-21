package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"iter"
	"math/big"
	"math/rand/v2"
	"slices"
	"strings"
	"sync"

	"github.com/monoidic/dns"
	"github.com/monoidic/rangeset"
	"golang.org/x/sync/semaphore"
)

type Nsec3Hash struct {
	H [20]byte
}

func (nh Nsec3Hash) String() string {
	return base32.HexEncoding.EncodeToString(nh.H[:])
}

func labelToNsec3Hash(label string) Nsec3Hash {
	var ret Nsec3Hash
	label = strings.ToUpper(label)
	check1(base32.HexEncoding.Decode(ret.H[:], []byte(label)))
	return ret
}

func nsec3RRToHashes(rrT *dns.NSEC3) (Nsec3Hash, Nsec3Hash) {
	var end Nsec3Hash
	start := labelToNsec3Hash(rrT.Hdr.Name.SplitRaw()[0])
	copy(end.H[:], rrT.NextDomain.Raw())

	return start, end
}

func labelDiff(start, end Nsec3Hash) *big.Int {
	total := &big.Int{}
	switch bytes.Compare(start.H[:], end.H[:]) {
	case 0: // covers whole zone
		return nsec3Total()
	case -1: // start < end
		total = total.Sub(end.toNum(), start.toNum())
	case 1: // start > end, wraparound
		// add up start to ffff... + 0000... to end (=> ffff... - start  + end)
		total = total.Sub(nsec3HashEnd.toNum(), start.toNum())
		total = total.Add(total, end.toNum())
	}

	return total
}

func labelDiffSmall(start, end Nsec3Hash) bool {
	return minDiff.Cmp(labelDiff(start, end)) != -1
}

func (nh *Nsec3Hash) toNum() *big.Int {
	ret := big.NewInt(0)
	part := big.NewInt(0)

	for i := range 2 {
		part = part.SetUint64(binary.BigEndian.Uint64(nh.H[i*8 : i*8+8]))
		ret = ret.Lsh(ret, 64)
		ret = ret.Or(ret, part)
	}

	part = part.SetUint64(uint64(binary.BigEndian.Uint32(nh.H[16:])))
	ret = ret.Lsh(ret, 32)
	ret = ret.Or(ret, part)

	return ret
}

// zero-initialized
var nsec3HashStart = Nsec3Hash{}

// all ones
var nsec3HashEnd = Nsec3Hash{H: [20]byte{
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff,
}}

type nsec3WalkZone struct {
	zone        dns.Name
	id          int64
	knownRanges *rangeset.RangeSet[Nsec3Hash]
	busyRanges  Set[rangeset.RangeEntry[Nsec3Hash]]
	rrTypesCh   chan *dns.NSEC3
	salt        []byte
	sem         *semaphore.Weighted
	mux         *sync.RWMutex
	nsec3Param  *dns.NSEC3PARAM
	splitZone   []string
	connCache   *connCache
	iterations  int
}

func (wz *nsec3WalkZone) contains(hash Nsec3Hash) bool {
	if wz.knownRanges.ProtectedContains(hash) {
		return true
	}
	enclosing := wz.enclosingKnownRange(hash)
	return wz.busyRanges.Contains(enclosing)
}

func (wz *nsec3WalkZone) enclosingKnownRange(hash Nsec3Hash) rangeset.RangeEntry[Nsec3Hash] {
	var ret rangeset.RangeEntry[Nsec3Hash]
	wz.knownRanges.Mux.RLock()
	defer wz.knownRanges.Mux.RUnlock()
	if len(wz.knownRanges.Ranges) == 0 {
		ret.Start = nsec3HashStart
		ret.End = nsec3HashEnd
		return ret
	}

	idx, _ := slices.BinarySearchFunc(wz.knownRanges.Ranges, hash, func(re rangeset.RangeEntry[Nsec3Hash], h Nsec3Hash) int {
		return bytes.Compare(re.End.H[:], h.H[:])
	})
	if idx == 0 {
		ret.Start = nsec3HashStart
	} else {
		ret.Start = wz.knownRanges.Ranges[idx-1].End
	}

	if idx == len(wz.knownRanges.Ranges) {
		ret.End = nsec3HashEnd
	} else {
		ret.End = wz.knownRanges.Ranges[idx].Start
	}

	return ret
}

func (wz nsec3WalkZone) String() string {
	var sb strings.Builder

	var nonFirst bool

	for _, rn := range wz.knownRanges.Ranges {
		if nonFirst {
			sb.WriteRune(' ')
		} else {
			nonFirst = true
		}

		sb.WriteString(fmt.Sprintf("%s-%s", rn.Start, rn.End))
	}

	return sb.String()
}

func nsec3Total() *big.Int {
	all := big.NewInt(1)
	all = all.Lsh(all, 160)
	return all
}

func (wz *nsec3WalkZone) sizeKnown() *big.Int {
	total := big.NewInt(0)
	wz.knownRanges.Mux.RLock()
	defer wz.knownRanges.Mux.RUnlock()
	for _, nsecRange := range wz.knownRanges.Ranges {
		start := nsecRange.Start.toNum()
		end := nsecRange.End.toNum()

		size := end.Sub(end, start)
		total = total.Add(total, size)
	}

	return total
}

func (wz *nsec3WalkZone) percentDiscovered() string {
	unknown := wz.sizeKnown()
	unknown = unknown.Mul(unknown, big.NewInt(100_00))

	all := nsec3Total()

	unknown = unknown.Div(unknown, all)
	num := float64(unknown.Int64()) / 100
	return fmt.Sprintf("%.2f%%", num)
}

type hashEntry struct {
	// if construct==true, then unmodified original, need to modify
	label     []byte
	hash      Nsec3Hash
	idx       int
	indexes   [3]uint8
	construct bool
}

func (h hashEntry) reconstructLabel() string {
	if !h.construct {
		return string(h.label)
	}

	out := slices.Clone(h.label)
	id := h.idx

	for i := range h.indexes {
		charIdx := id % 36
		id /= 36
		out[h.indexes[i]] = nsec3walkcharset[charIdx]
	}

	return string(out[1:])
}

func (wz *nsec3WalkZone) addKnown(rr *dns.NSEC3, rn rangeset.RangeEntry[Nsec3Hash]) bool {
	if bytes.Compare(rn.Start.H[:], rn.End.H[:]) != -1 {
		// wraparound
		ret := wz.addKnown(rr, rangeset.RangeEntry[Nsec3Hash]{Start: rn.Start, End: nsec3HashEnd})
		wz.addKnown(rr, rangeset.RangeEntry[Nsec3Hash]{Start: nsec3HashStart, End: rn.End})
		return ret
	}

	if wz.knownRanges.ProtectedContainsRange(rn) {
		return false
	}

	wz.knownRanges.ProtectedAdd(rn)

	// do not add nsec3HashStart to known
	if rn.Start == nsec3HashStart {
		return true
	}

	wz.rrTypesCh <- rr

	return true
}

// assumes sha1 cuz protocol ossification lole
// label is a nsec-formatted label, e.g "\x04abcd", zone is the rest, e.g "\x07example\x03com\x00", salt is decoded salt
// tries to be efficient
func nsec3Hash(label, zone, salt []byte, iterations int) Nsec3Hash {
	h := sha1.New()

	h.Write(label)
	h.Write(zone)
	h.Write(salt)
	hashB := h.Sum(nil)

	for range iterations {
		h.Reset()
		h.Write(hashB)
		h.Write(salt)
		hashB = h.Sum(hashB[:0])
	}

	var ret Nsec3Hash
	copy(ret.H[:], hashB)
	return ret
}

const nsec3walkcharset = "0123456789abcdefghijklmnopqrstuvwxyz"

// generate random (pre-encoded) DNS label for a string matching the pattern ^[0-9a-z]{20,63}$
func randomLabel() []byte {
	length := rangeRandNum(20, 63)
	ret := make([]byte, length+1)
	ret[0] = byte(length)
	for i := range length {
		ret[i+1] = byte(nsec3walkcharset[rand.IntN(len(nsec3walkcharset))])
	}
	return ret
}

func randomLabelLen(min, max int) []byte {
	length := rangeRandNum(min, max)
	ret := make([]byte, length+1)
	ret[0] = byte(length)
	for i := range length {
		ret[i+1] = byte(nsec3walkcharset[rand.IntN(len(nsec3walkcharset))])
	}
	return ret
}

func rangeRandNum(minV, maxV int) int {
	diff := maxV - minV
	return minV + rand.IntN(diff)
}

func nRandNums(minV, maxV, n int) []int {
	ret := make([]int, n)

	for i := range n {
		num := rangeRandNum(minV, maxV)
		for slices.Contains(ret[:i], num) {
			num = rangeRandNum(minV, maxV)
		}
		ret[i] = num
	}
	return ret
}

func randomLabels(yield func([]byte) bool) {
	for {
		label := randomLabel()

		// pick random different positions in label to permute for batch (aside from length indicator)
		slNums := nRandNums(1, len(label), 4)
		w := slNums[0]
		x := slNums[1]
		y := slNums[2]
		z := slNums[3]

		// 36⁴ (1 679 616) entries per batch

		for i := range len(nsec3walkcharset) {
			label[w] = nsec3walkcharset[i]
			for j := range len(nsec3walkcharset) {
				label[x] = nsec3walkcharset[j]
				for k := range len(nsec3walkcharset) {
					label[y] = nsec3walkcharset[k]
					for l := range len(nsec3walkcharset) {
						label[z] = nsec3walkcharset[l]

						if !yield(label) {
							return
						}
					}
				}
			}
		}
	}
}

func genHashes(zone, salt []byte, iterations int) iter.Seq[hashEntry] {
	return func(yield func(hashEntry) bool) {
		for label := range randomLabels {
			hash := nsec3Hash(label, zone, salt, iterations)
			if !yield(hashEntry{
				hash:  hash,
				label: slices.Clone(label[1:]),
			}) {
				return
			}
		}
	}
}

func genHashesMulti(ctx context.Context, zone, salt []byte, iterations int) <-chan hashEntry {
	out := make(chan hashEntry, MIDBUFLEN)

	chanWorkers(out, numProcs, func() {
		for {
			for e := range genHashes(zone, salt, iterations) {
				select {
				case <-ctx.Done():
					return
				case out <- e:
				}
			}
		}
	})

	return out
}

const MULTITHREAD_NSEC3_THRESHOLD = 2

// chooses single-threaded or multi-threaded genHashes variant based on iteration number
func genHashesWrap(ctx context.Context, zone, salt []byte, iterations int) iter.Seq[hashEntry] {
	if !noCL && openclDevice == nil {
		initOpenclInfo()
	}

	if noCL && iterations < MULTITHREAD_NSEC3_THRESHOLD {
		return genHashes(zone, salt, iterations)
	}

	ctx, cancel := context.WithCancel(ctx)

	var ch <-chan hashEntry

	if noCL {
		ch = genHashesMulti(ctx, zone, salt, iterations)
	} else {
		ch = nsec3HashOpenCL(ctx, zone, salt, iterations)
	}

	return func(yield func(hashEntry) bool) {
		defer cancel()
		for e := range ch {
			if !yield(e) {
				return
			}
		}
	}
}

func nsec3Walk(db *sql.DB) {
	readerWriter("performing NSEC3 walks", db, getDbNameData(`
	SELECT DISTINCT zone.name, zone.id
	FROM name AS zone
	INNER JOIN zone_nsec_state ON zone_nsec_state.zone_id = zone.id
	INNER JOIN nsec_state ON zone_nsec_state.nsec_state_id = nsec_state.id
	WHERE nsec_state.name='nsec3'
	AND zone.nsec_walked=FALSE
	AND zone.inserted=FALSE
`, db), nsec3WalkMaster)
}

func nsec3ParamQuery(connCache *connCache, zone dns.Name) *dns.NSEC3PARAM {
	msg := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Opcode:           dns.OpcodeQuery,
			RecursionDesired: true,
			Rcode:            dns.RcodeSuccess,
		},
		Question: []dns.Question{{
			Qclass: dns.ClassINET,
			Qtype:  dns.TypeNSEC3PARAM,
			Name:   zone,
		}},
	}

	msgSetSize(&msg)
	msg.Extra[0].(*dns.OPT).SetDo()

	for range retries {
		res, err := plainResolveRandom(&msg, connCache)
		if err != nil {
			continue
		}

		for _, rr := range res.Answer {
			switch rrT := rr.(type) {
			case *dns.NSEC3PARAM:
				return rrT
			}
		}
	}

	return nil
}

func nsec3Query(connCache *connCache, name dns.Name) *dns.Msg {
	msg := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Opcode:           dns.OpcodeQuery,
			RecursionDesired: true,
			Rcode:            dns.RcodeSuccess,
		},
		Question: []dns.Question{{
			Qclass: dns.ClassINET,
			Qtype:  dns.TypeCNAME,
			Name:   name,
		}},
	}

	msgSetSize(&msg)
	msg.Extra[0].(*dns.OPT).SetDo()

	for range retries {
		res, err := plainResolveRandom(&msg, connCache)
		if err == nil && res.Rcode != dns.RcodeServerFailure {
			return res
		}
	}

	return nil
}

func nsec3WalkMaster(db *sql.DB, seq iter.Seq[nameData]) {
	tablesFields := map[string]string{
		"name":    "name",
		"rr_type": "name",
	}

	namesStmts := map[string]string{
		"nsec3_params": "INSERT OR IGNORE INTO nsec3_zone_params (zone_id, salt, iterations) VALUES (?, ?, ?)",
		"hash":         "INSERT OR IGNORE INTO nsec3_hashes (nsec3_zone_id, nsec3_hash) VALUES ((SELECT id FROM nsec3_zone_params WHERE zone_id=?), ?)",
		// lol...
		"hash_rrtype": "INSERT OR IGNORE INTO nsec3_hash_rr_map (nsec3_hash_id, rr_type_id) VALUES ((SELECT id FROM nsec3_hashes WHERE nsec3_zone_id=(SELECT id FROM nsec3_zone_params WHERE zone_id=?) AND nsec3_hash=?), ?)",
		"set_walked":  "UPDATE name SET nsec_walked=TRUE WHERE id=?",
	}

	netWriter(db, seq, tablesFields, namesStmts, nsec3WalkWorker, nsec3WalkInsert)
}

func nsec3WalkWorker(zoneChan <-chan retryWrap[nameData, empty], refeedChan chan<- retryWrap[nameData, empty], dataOutChan chan<- nsec3WalkZone, retryWg *sync.WaitGroup) {
	resolverWorker(zoneChan, refeedChan, dataOutChan, &dns.Msg{}, nsec3WalkResolve, retryWg)
}

func nsec3WalkInsert(tableMap TableMap, stmtMap StmtMap, zw nsec3WalkZone) {
	zoneID := zw.id

	buf := make([]byte, 32)

	hexSalt := string(hex.AppendEncode(nil, zw.salt))

	stmtMap.exec("nsec3_params", zoneID, hexSalt, zw.iterations)

	for rr := range zw.rrTypesCh {
		start, _ := nsec3RRToHashes(rr)
		base32.HexEncoding.Encode(buf, start.H[:])
		hash := string(buf)

		stmtMap.exec("hash", zoneID, hash)

	typeLoop:
		for t := range rr.TypeBitMap.Iter {
			switch t {
			case dns.TypeNSEC3, dns.TypeRRSIG:
				continue typeLoop // skip
			}
			rrTypeID := tableMap.get("rr_type", t.String())
			stmtMap.exec("hash_rrtype", zoneID, hash, rrTypeID)
		}
	}

	stmtMap.exec("set_walked", zoneID)
}

func nsec3Compare(v1, v2 Nsec3Hash) int {
	return bytes.Compare(v1.H[:], v2.H[:])
}

const (
	MIN_DIFF = 1024
)

var minDiff = big.NewInt(MIN_DIFF)

func nsec3WalkResolve(connCache *connCache, _ *dns.Msg, zd *retryWrap[nameData, empty]) (nsec3WalkZone, error) {
	wz := nsec3WalkZone{
		zone:        zd.val.name,
		splitZone:   zd.val.name.SplitRaw(),
		id:          zd.val.id,
		rrTypesCh:   make(chan *dns.NSEC3),
		knownRanges: &rangeset.RangeSet[Nsec3Hash]{Compare: nsec3Compare},
		busyRanges:  make(Set[rangeset.RangeEntry[Nsec3Hash]]),
		mux:         &sync.RWMutex{},
		sem:         semaphore.NewWeighted(1000),
		connCache:   connCache,
	}

	// fmt.Printf("starting walk on zone %s\n", zone)

	nsec3Param := nsec3ParamQuery(connCache, wz.zone)
	if nsec3Param == nil {
		return nsec3WalkZone{}, errors.New("unable to fetch NSEC3PARAM")
	}
	wz.nsec3Param = nsec3Param

	wz.salt = nsec3Param.Salt.Raw()
	wz.iterations = int(nsec3Param.Iterations)

	encodedZone := wz.zone.ToWire()

	producedGuesses := make(chan hashEntry, MIDBUFLEN)
	filteredGuesses := make(chan hashEntry, MIDBUFLEN)
	ctx, cancel := context.WithCancel(context.Background())
	// actually called in processGuess; just here to shut up the linter
	defer cancel()

	// producer
	go func() {
		defer close(producedGuesses)
		for guess := range genHashesWrap(ctx, encodedZone, wz.salt, wz.iterations) {
			select {
			case <-ctx.Done():
				return
			case producedGuesses <- guess:
			}
		}
	}()

	// filters
	chanWorkers(filteredGuesses, numProcs, func() {
		for guess := range producedGuesses {
			wz.mux.RLock()
			contains := wz.contains(guess.hash)
			wz.mux.RUnlock()

			if !contains {
				filteredGuesses <- guess
			}
		}
	})

	var err error

	for guess := range filteredGuesses {
		go processGuess(&wz, cancel, guess, &err)
	}

	return wz, err
}

func processGuess(wz *nsec3WalkZone, cancel context.CancelFunc, guess hashEntry, errP *error) {
	wz.mux.RLock()
	contains := wz.contains(guess.hash)
	wz.mux.RUnlock()
	if contains {
		return
	}

	// re-check with a write lock, just in case the range was claimed by a different write lock before this one was claimed
	wz.mux.Lock()
	contains = wz.contains(guess.hash)
	if contains {
		wz.mux.Unlock()
		return
	}

	enclosing := wz.enclosingKnownRange(guess.hash)
	wz.busyRanges.Add(enclosing)
	wz.mux.Unlock()

	// cleanup
	defer func() {
		wz.mux.Lock()
		wz.busyRanges.Delete(enclosing)
		wz.mux.Unlock()
	}()

	hashName := check1(dns.NameFromLabels(append([]string{guess.reconstructLabel()}, wz.splitZone...)))

	_ = wz.sem.Acquire(context.Background(), 1)
	res := nsec3Query(wz.connCache, hashName)
	wz.sem.Release(1)
	if res == nil {
		return
	}

	for _, rr := range res.Ns {
		switch rrT := rr.(type) {
		case *dns.SOA:
			dns.Canonicalize(rrT)
			if soaZone := rrT.Hdr.Name; dns.Compare(wz.zone, soaZone) != 0 && dns.IsSubDomain(wz.zone, soaZone) {
				return
			}
		}
	}
	var sawThis bool

	var entries []rangeset.RangeEntry[Nsec3Hash]
	var bitmaps []dns.TypeBitMap

	for _, rr := range res.Ns {
		switch rrT := rr.(type) {
		case *dns.NSEC3:
			dns.Canonicalize(rrT)
			if !(rrT.Salt == wz.nsec3Param.Salt && rrT.Iterations == wz.nsec3Param.Iterations) {
				// params changed in the middle of the walk
				wz.mux.Lock()
				*errP = errors.New("nsec3 params changed")
				cancel()
				wz.mux.Unlock()
				return
			}

			if rrT.Cover(hashName) {
				sawThis = true
			}

			start, end := nsec3RRToHashes(rrT)

			if labelDiffSmall(start, end) {
				wz.mux.Lock()
				*errP = errors.New("nsec3 white lies?")
				cancel()
				wz.mux.Unlock()
				return
			}

			entries = append(entries, rangeset.RangeEntry[Nsec3Hash]{Start: start, End: end})
			bitmaps = append(bitmaps, rrT.TypeBitMap)

			entry := rangeset.RangeEntry[Nsec3Hash]{Start: start, End: end}

			wz.addKnown(rrT, entry)
		}
	}

	if !sawThis {
		fmt.Printf("expected to see something covering hashName=%s hash=%s did not\n", hashName, guess.hash)
		for _, rr := range res.Ns {
			fmt.Println(rr)
		}
	}

	/*
		if !noCL {
			// validate hash
			label := guess.reconstructLabel()
			reconstructedLabel := []byte{byte(len(label))}
			reconstructedLabel = append(reconstructedLabel, ([]byte(label))...)
			expected := nsec3Hash(reconstructedLabel, wz.zone.ToWire(), wz.salt, wz.iterations)
			if expected != guess.hash {
				log.Panicf("lol broken opencl, expected %s, got %s, label %s, raw label %s, reconstructed %s, name %s", expected, guess.hash, hex.EncodeToString([]byte(label)), hex.EncodeToString([]byte(guess.label)), hex.EncodeToString([]byte(reconstructedLabel)), hex.EncodeToString(hashName.ToWire()))
			}
		}
	*/

	wz.mux.RLock()
	defer wz.mux.RUnlock()
	fmt.Printf("zone=%s %d ranges %s zone discovered\n", wz.zone, len(wz.knownRanges.Ranges), wz.percentDiscovered())

	if len(wz.knownRanges.Ranges) < 100 {
		fmt.Println(wz.String())
	}

	if len(wz.knownRanges.Ranges) == 1 {
		rn := wz.knownRanges.Ranges[0]
		if rn.Start == nsec3HashStart && rn.End == nsec3HashEnd {
			cancel()
			close(wz.rrTypesCh)
		}
	}
}
