package main

import (
	"context"
	"database/sql"
	"fmt"
	"iter"
	"math/big"
	"slices"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/monoidic/rangeset"
	"golang.org/x/sync/semaphore"
)

type walkZone struct {
	zone       string
	id         int64
	subdomains Set[string]
	rrTypes    map[string][]string
	sem        *semaphore.Weighted
	wg         *sync.WaitGroup
	pool       *sync.Pool
	mux        *sync.Mutex
}

func addKnown(zone string, rs *rangeset.RangeSet[string], rn rangeset.RangeEntry[string], bitmap []uint16, rrTypes map[string][]string) bool {
	if !dns.IsSubDomain(zone, rn.Start) {
		return false
	}

	if rs.ContainsRange(rn) {
		return false
	}

	var nsecTypes []string
	for _, t := range bitmap {
		switch t {
		case dns.TypeNSEC, dns.TypeRRSIG: // skip
		default:
			nsecTypes = append(nsecTypes, dns.Type(t).String())
		}
	}

	rrTypes[rn.Start] = nsecTypes
	rs.Add(rn)

	return true
}

func unknownRanges(zone string, rs *rangeset.RangeSet[string]) iter.Seq[rangeset.RangeEntry[string]] {
	return func(yield func(rangeset.RangeEntry[string]) bool) {
		l := len(rs.Ranges)

		if l == 0 {
			// no known results, just give the whole zone
			_ = yield(rangeset.RangeEntry[string]{Start: zone, End: zone})
			return
		}

		firstName := rs.Ranges[0].Start
		if firstName != zone {
			// unknown range before first known range
			if !yield(rangeset.RangeEntry[string]{Start: zone, End: firstName}) {
				return
			}
		}

		last := rs.Ranges[0].End
		for i := range l - 1 {
			start := rs.Ranges[i].End
			end := rs.Ranges[i+1].Start
			last = rs.Ranges[i+1].End

			if !yield(rangeset.RangeEntry[string]{Start: start, End: end}) {
				return
			}
		}

		if last != zone {
			if !yield(rangeset.RangeEntry[string]{Start: last, End: zone}) {
				return
			}
		}
	}
}

func nsecWalkWorker(zoneChan <-chan retryWrap[fieldData, empty], refeedChan chan<- retryWrap[fieldData, empty], dataOutChan chan<- *walkZone, wg, retryWg *sync.WaitGroup) {
	resolverWorker(zoneChan, refeedChan, dataOutChan, &dns.Msg{}, nsecWalkResolve, wg, retryWg)
}

func nsecWalkResolveWorker(wz *walkZone, thisRn rangeset.RangeEntry[string]) {
	defer wz.wg.Done()

	zone := wz.zone

	knownRanges := rangeset.RangeSet[string]{Compare: dnsCompare, HasRWrap: true, RWrapV: zone}

	full := rangeset.RangeEntry[string]{Start: zone, End: zone}
	for _, rn := range []rangeset.RangeEntry[string]{{Start: zone, End: thisRn.Start}, {Start: thisRn.End, End: zone}} {
		if rn != full {
			knownRanges.Add(rn)
		}
	}

	unknowns := slices.Collect(unknownRanges(zone, &knownRanges))

	for _, rn := range unknowns {
		for middle := range getMiddle(zone, rn) {
			wz.sem.Acquire(context.Background(), 1)
			connCache := wz.pool.Get().(*connCache)
			msg := nsecWalkerResolve(middle, connCache)
			wz.pool.Put(connCache)
			wz.sem.Release(1)

			if msg == nil {
				continue
			}

			var foundSubdomains bool

			for _, rr := range msg.Ns {
				switch rrT := rr.(type) {
				case *dns.SOA:
					normalizeRR(rrT)
					if soaZone := rrT.Hdr.Name; dnsCompare(zone, soaZone) != 0 && dns.IsSubDomain(zone, soaZone) {
						// fmt.Printf("found subdomain %s of domain %s\n", soaZone, zone)
						wz.mux.Lock()
						wz.subdomains.Add(soaZone)
						wz.mux.Unlock()
						foundSubdomains = true
					}
				}
			}

			if foundSubdomains {
				continue
			}

			var expanded bool
			for _, rr := range msg.Ns {
				switch rrT := rr.(type) {
				case *dns.NSEC:
					normalizeRR(rrT)
					wz.mux.Lock()
					if addKnown(zone, &knownRanges, rangeset.RangeEntry[string]{Start: rrT.Hdr.Name, End: rrT.NextDomain}, rrT.TypeBitMap, wz.rrTypes) {
						// fmt.Printf("added entry %v\n", rrT)
						expanded = true
					}
					wz.mux.Unlock()
				}
			}

			if expanded {
				// no need to get more from this range
				break
			}
		}
	}

	for rn := range unknownRanges(zone, &knownRanges) {
		if slices.Contains(unknowns, rn) {
			// contained in original set of ranges; ignore
			fmt.Printf("skipped range: %s\n", rn)
			continue
		}

		wz.wg.Add(1)
		go nsecWalkResolveWorker(wz, rn)
	}
}

func nsecWalkResolve(_ *connCache, _ *dns.Msg, zd *retryWrap[fieldData, empty]) (*walkZone, error) {
	wz := &walkZone{
		zone:       zd.val.name,
		id:         zd.val.id,
		rrTypes:    make(map[string][]string),
		subdomains: make(Set[string]),
		sem:        semaphore.NewWeighted(int64(numProcs)),
		wg:         &sync.WaitGroup{},
		pool:       &sync.Pool{},
		mux:        &sync.Mutex{},
	}

	zone := zd.val.name

	wz.pool.New = func() any { return getConnCache() }
	wz.wg.Add(1)
	go nsecWalkResolveWorker(wz, rangeset.RangeEntry[string]{Start: zone, End: zone})
	wz.wg.Wait()

	return wz, nil
}

func nsecWalkerResolve(name string, connCache *connCache) *dns.Msg {
	msg := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Opcode:           dns.OpcodeQuery,
			RecursionDesired: true,
			Rcode:            dns.RcodeSuccess,
		},
		Question: []dns.Question{{
			Qclass: dns.ClassINET,
			Qtype:  dns.TypeAPL,
			Name:   name,
		}},
	}

	msgSetSize(&msg)
	msg.Extra[0].(*dns.OPT).SetDo()

	for range retries {
		res, err := plainResolveRandom(&msg, connCache)
		if err == nil {
			return res
		}
	}

	return nil
}

func nsecWalkMaster(db *sql.DB, seq iter.Seq[fieldData]) {
	tablesFields := map[string]string{
		"name":    "name",
		"rr_type": "name",
		"rr_name": "name",
	}
	namesStmts := map[string]string{
		"walk_res":     "INSERT OR IGNORE INTO zone_walk_res (zone_id, rr_name_id, rr_type_id) VALUES (?, ?, ?)",
		"subdomain":    "UPDATE name SET parent_id=? WHERE id=?",
		"set_walked":   "UPDATE name SET nsec_walked=TRUE WHERE id=?",
		"name_to_zone": "UPDATE name SET is_zone=TRUE WHERE id=?",
	}

	netWriter(db, seq, tablesFields, namesStmts, nsecWalkWorker, nsecWalkInsert)
}

func nsecWalkResults(db *sql.DB) {
	readerWriter("fetching zone walk results", db, getUnqueriedNsecRes(db), nsecWalkResWriter)
}

func nsecWalkResWriter(db *sql.DB, seq iter.Seq[rrDBData]) {
	tablesFields := map[string]string{
		"name":     "name",
		"rr_type":  "name",
		"rr_name":  "name",
		"rr_value": "value",
	}
	namesStmts := map[string]string{
		"insert":  "INSERT OR IGNORE INTO zone2rr (zone_id, rr_type_id, rr_name_id, rr_value_id, from_self) VALUES (?, ?, ?, ?, TRUE)",
		"queried": "UPDATE zone_walk_res SET queried=TRUE WHERE id=?",
	}

	netWriter(db, seq, tablesFields, namesStmts, nsecWalkResultResolver, nsecWalkResWrite)
}

func nsecWalkResWrite(tableMap TableMap, stmtMap StmtMap, res nsecWalkResolveRes) {
	var rrTypeID, rrNameID int64
	defaultRRTypeID := res.rrType.id
	defaultRRNameID := res.rrName.id

	for _, rr := range res.results {
		if rr.rrType == res.rrType.name {
			rrTypeID = defaultRRTypeID
		} else {
			rrTypeID = tableMap.get("rr_type", rr.rrType)
		}

		if rr.rrName == res.rrName.name {
			rrNameID = defaultRRNameID
		} else {
			rrNameID = tableMap.get("rr_name", rr.rrName)
		}

		rrValueID := tableMap.get("rr_value", rr.rrValue)
		zoneID := res.rrValue.id

		stmtMap.exec("insert", zoneID, rrTypeID, rrNameID, rrValueID)
	}

	stmtMap.exec("queried", res.id)
}

func nsecWalkInsert(tableMap TableMap, stmtMap StmtMap, zw *walkZone) {
	zoneID := zw.id

	for rrName, rrtL := range zw.rrTypes {
		rrNameID := tableMap.get("rr_name", rrName)

		for _, rrType := range rrtL {
			if rrType == "NS" {
				zw.subdomains.Add(rrName)
			}

			rrTypeID := tableMap.get("rr_type", rrType)

			stmtMap.exec("walk_res", zoneID, rrNameID, rrTypeID)
		}
	}

	for subdomain := range zw.subdomains {
		childZoneID := tableMap.get("name", subdomain)
		stmtMap.exec("name_to_zone", childZoneID)
		stmtMap.exec("subdomain", zoneID, childZoneID)
	}

	stmtMap.exec("set_walked", zoneID)
}

func nsecWalk(db *sql.DB) {
	readerWriter("performing NSEC walks", db, getDbFieldData(`
	SELECT DISTINCT zone.name, zone.id
	FROM name AS zone
	INNER JOIN zone_nsec_state ON zone_nsec_state.zone_id = zone.id
	INNER JOIN nsec_state ON zone_nsec_state.nsec_state_id = nsec_state.id
	WHERE nsec_state.name='plain_nsec'
	AND zone.nsec_walked=FALSE
	AND zone.inserted=FALSE
`, db), nsecWalkMaster)
}

func _getMiddle(zone string, rn rangeset.RangeEntry[string]) iter.Seq[[]string] {
	start := rn.Start
	end := rn.End
	return func(yield func([]string) bool) {
		splitStart := dns.SplitDomainName(start)
		splitEnd := dns.SplitDomainName(end)

		if !(end == zone || end == ".") && splitEnd == nil {
			panic(fmt.Sprintf("end splits to nil: %s", end))
		}

		if (!(start == zone || start == ".")) && splitStart == nil {
			panic(fmt.Sprintf("start splits to nil: %s", start))
		}

		splitStartCopy := slices.Clone(splitStart)
		splitEndCopy := slices.Clone(splitEnd)
		slices.Reverse(splitStartCopy)
		slices.Reverse(splitEndCopy)

		var commonLabels int
		for i := range min(len(splitStartCopy), len(splitEndCopy)) {
			if splitStartCopy[i] != splitEndCopy[i] {
				break
			}
			commonLabels++
		}

		common := splitStartCopy[:commonLabels]
		slices.Reverse(common)

		if len(splitEnd) > 0 && len(strings.Trim(splitEnd[0], labelChars)) > 0 {
			// random crap that should work for the range ["example.com."", "*.example.com."]
			// shouldn't run into this very often anyway
			if splitEnd[0] == "*" {
				for _, s := range []string{" ", "!", "$"} {
					res := append([]string{s}, common...)
					if !yield(res) {
						return
					}
				}
			}

			if !yield(splitStart) {
				return
			}
			if !yield(append([]string{"-"}, splitStart...)) {
				return
			}
		}

		startNum := big.NewInt(0)
		endNum := big.NewInt(0)
		endNum.SetString(maxLabelNum, 10)
		var startLen, endLen int

		if commonLabels < len(splitStartCopy) {
			startNum = labelToNum(splitStartCopy[commonLabels])
			startLen = len(splitStartCopy[commonLabels])
		}
		if commonLabels < len(splitEndCopy) {
			endNum = labelToNum(splitEndCopy[commonLabels])
			endLen = len(splitEndCopy[commonLabels])
		}

		if startNum.Cmp(endNum) != -1 {
			// startNum >= endNum
			startNum.SetInt64(0)
			endNum.SetString(maxLabelNum, 10)
		}

		// TODO could run up against the limit of 255 bytes per name
		splitALen := max(20, min(63, 2+max(startLen, endLen)))
		for splitS := range splitAscii(startNum, endNum, 2, splitALen) {
			res := append([]string{splitS}, common...)
			if !yield(res) {
				return
			}
		}
	}
}

func getMiddle(zone string, rn rangeset.RangeEntry[string]) iter.Seq[string] {
	return func(yield func(string) bool) {
		for s := range _getMiddle(zone, rn) {
			res := strings.Join(s, ".") + "."
			if _, ok := dns.IsDomainName(res); !ok {
				continue
			}
			if !(dns.IsSubDomain(zone, res) && dnsCompare(rn.Start, res) <= 0 && (rn.End == zone || dnsCompare(res, rn.End) == -1)) {
				continue
			}
			if !yield(res) {
				break
			}
		}
	}
}

// TODO get Compare into miekg/dns

// returns an integer value similar to strcmp
// (0 for equal values, -1 if s1 < s2, 1 if s1 > s2)
func dnsCompare(s1, s2 string) int {
	s1b := doDDD([]byte(s1))
	s2b := doDDD([]byte(s2))

	s1 = string(s1b)
	s2 = string(s2b)

	s1lend := len(s1)
	s2lend := len(s2)

	for i := 0; ; i++ {
		s1lstart, end1 := dns.PrevLabel(s1, i)
		s2lstart, end2 := dns.PrevLabel(s2, i)

		if end1 && end2 {
			return 0
		}

		s1l := string(s1b[s1lstart:s1lend])
		s2l := string(s2b[s2lstart:s2lend])

		if cmp := labelCompare(s1l, s2l); cmp != 0 {
			return cmp
		}

		s1lend = s1lstart - 1
		s2lend = s2lstart - 1
		if s1lend == -1 {
			s1lend = 0
		}
		if s2lend == -1 {
			s2lend = 0
		}
	}
}

func doDDD(b []byte) []byte {
	lb := len(b)
	for i := range lb {
		if i+3 < lb && b[i] == '\\' && isDigit(b[i+1]) && isDigit(b[i+2]) && isDigit(b[i+3]) {
			b[i] = dddToByte(b[i+1 : i+4])
			for j := i + 1; j < lb-3; j++ {
				b[j] = b[j+3]
			}
			lb -= 3
		}
	}
	return b[:lb]
}

func dddToByte(s []byte) byte {
	_ = s[2] // bounds check hint to compiler; see golang.org/issue/14808
	return byte((s[0]-'0')*100 + (s[1]-'0')*10 + (s[2] - '0'))
}

func isDigit(b byte) bool { return b <= '9' && b >= '0' }

// essentially strcasecmp
// (0 for equal values, -1 if s1 < s2, 1 if s1 > s2)
func labelCompare(a, b string) int {
	la := len(a)
	lb := len(b)
	minLen := la
	if lb < la {
		minLen = lb
	}
	for i := range minLen {
		ai := a[i]
		bi := b[i]
		if ai >= 'A' && ai <= 'Z' {
			ai |= 'a' - 'A'
		}
		if bi >= 'A' && bi <= 'Z' {
			bi |= 'a' - 'A'
		}
		if ai != bi {
			if ai > bi {
				return 1
			}
			return -1
		}
	}

	if la > lb {
		return 1
	} else if la < lb {
		return -1
	}
	return 0
}
