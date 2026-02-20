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

	"github.com/monoidic/dns"
	"github.com/monoidic/rangeset"
	"golang.org/x/sync/semaphore"
)

type walkZone struct {
	zone       dns.Name
	id         int64
	subdomains Set[dns.Name]
	rrTypes    map[dns.Name][]string
	sem        *semaphore.Weighted
	wg         *sync.WaitGroup
	pool       *sync.Pool
	mux        *sync.Mutex
}

func addKnown(zone dns.Name, rs *rangeset.RangeSet[dns.Name], rn rangeset.RangeEntry[dns.Name], bitmap dns.TypeBitMap, rrTypes map[dns.Name][]string, mux *sync.Mutex) bool {
	if !dns.IsSubDomain(zone, rn.Start) {
		return false
	}

	if rs.ContainsRange(rn) {
		return false
	}

	var nsecTypes []string
	for t := range bitmap.Iter {
		switch t {
		case dns.TypeNSEC, dns.TypeRRSIG: // skip
		default:
			nsecTypes = append(nsecTypes, t.String())
		}
	}

	mux.Lock()
	rrTypes[rn.Start] = nsecTypes
	mux.Unlock()

	rs.Add(rn)

	return true
}

func unknownRanges(zone dns.Name, rs *rangeset.RangeSet[dns.Name]) iter.Seq[rangeset.RangeEntry[dns.Name]] {
	return func(yield func(rangeset.RangeEntry[dns.Name]) bool) {
		l := len(rs.Ranges)

		if l == 0 {
			// no known results, just give the whole zone
			_ = yield(rangeset.RangeEntry[dns.Name]{Start: zone, End: zone})
			return
		}

		firstName := rs.Ranges[0].Start
		if firstName != zone {
			// unknown range before first known range
			if !yield(rangeset.RangeEntry[dns.Name]{Start: zone, End: firstName}) {
				return
			}
		}

		last := rs.Ranges[0].End
		for i := range l - 1 {
			start := rs.Ranges[i].End
			end := rs.Ranges[i+1].Start
			last = rs.Ranges[i+1].End

			if !yield(rangeset.RangeEntry[dns.Name]{Start: start, End: end}) {
				return
			}
		}

		if last != zone {
			if !yield(rangeset.RangeEntry[dns.Name]{Start: last, End: zone}) {
				return
			}
		}
	}
}

func nsecWalkWorker(zoneChan <-chan retryWrap[nameData, empty], refeedChan chan<- retryWrap[nameData, empty], dataOutChan chan<- *walkZone, retryWg *sync.WaitGroup) {
	resolverWorker(zoneChan, refeedChan, dataOutChan, &dns.Msg{}, nsecWalkResolve, retryWg)
}

func nsecWalkResolveWorker(wz *walkZone, thisRn rangeset.RangeEntry[dns.Name]) {
	zone := wz.zone

	knownRanges := rangeset.RangeSet[dns.Name]{Compare: dns.Compare, HasRWrap: true, RWrapV: zone}

	full := rangeset.RangeEntry[dns.Name]{Start: zone, End: zone}
	for _, rn := range []rangeset.RangeEntry[dns.Name]{{Start: zone, End: thisRn.Start}, {Start: thisRn.End, End: zone}} {
		if rn != full {
			knownRanges.Add(rn)
		}
	}

	unknowns := slices.Collect(unknownRanges(zone, &knownRanges))

	for _, rn := range unknowns {
		for middle := range getMiddle(zone, rn) {
			_ = wz.sem.Acquire(context.Background(), 1)
			connCache := wz.pool.Get().(*connCache)
			msg := nsecWalkerResolve(middle, connCache)
			wz.pool.Put(connCache)
			wz.sem.Release(1)

			if msg == nil {
				continue
			}

			var subdomains []dns.Name

			for _, rr := range msg.Ns {
				switch rrT := rr.(type) {
				case *dns.SOA:
					dns.Canonicalize(rrT)
					if soaZone := rrT.Hdr.Name; dns.Compare(zone, soaZone) != 0 && dns.IsSubDomain(zone, soaZone) {
						// fmt.Printf("found subdomain %s of domain %s\n", soaZone, zone)
						subdomains = append(subdomains, soaZone)
					}
				case *dns.RRSIG:
					dns.Canonicalize(rrT)
					if rrsigZone := rrT.SignerName; dns.Compare(zone, rrsigZone) != 0 && dns.IsSubDomain(zone, rrsigZone) {
						// fmt.Printf("found subdomain %s of domain %s\n", soaZone, zone)
						subdomains = append(subdomains, rrsigZone)
					}
				}
			}

			if len(subdomains) > 0 {
				wz.mux.Lock()
				for _, subdomain := range subdomains {
					wz.subdomains.Add(subdomain)
				}
				wz.mux.Unlock()
				continue
			}

			var expanded bool
			for _, rr := range msg.Ns {
				switch rrT := rr.(type) {
				case *dns.NSEC:
					dns.Canonicalize(rrT)
					if addKnown(zone, &knownRanges, rangeset.RangeEntry[dns.Name]{Start: rrT.Hdr.Name, End: rrT.NextDomain}, rrT.TypeBitMap, wz.rrTypes, wz.mux) {
						// fmt.Printf("added entry %v\n", rrT)
						expanded = true
					}
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

		wz.wg.Go(func() { nsecWalkResolveWorker(wz, rn) })
	}
}

func nsecWalkResolve(_ *connCache, _ *dns.Msg, zd *retryWrap[nameData, empty]) (*walkZone, error) {
	wz := &walkZone{
		zone:       zd.val.name,
		id:         zd.val.id,
		rrTypes:    make(map[dns.Name][]string),
		subdomains: make(Set[dns.Name]),
		sem:        semaphore.NewWeighted(1000),
		wg:         &sync.WaitGroup{},
		pool:       &sync.Pool{},
		mux:        &sync.Mutex{},
	}

	zone := zd.val.name

	wz.pool.New = func() any { return getConnCache() }
	wz.wg.Go(func() { nsecWalkResolveWorker(wz, rangeset.RangeEntry[dns.Name]{Start: zone, End: zone}) })
	wz.wg.Wait()

	return wz, nil
}

func nsecWalkerResolve(name dns.Name, connCache *connCache) *dns.Msg {
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
		if err == nil {
			return res
		}
	}

	return nil
}

func nsecWalkMaster(db *sql.DB, seq iter.Seq[nameData]) {
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
			rrNameID = tableMap.get("rr_name", rr.rrName.String())
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
		rrNameID := tableMap.get("rr_name", rrName.String())

		for _, rrType := range rrtL {
			if rrType == "NS" {
				zw.subdomains.Add(rrName)
			}

			rrTypeID := tableMap.get("rr_type", rrType)

			stmtMap.exec("walk_res", zoneID, rrNameID, rrTypeID)
		}
	}

	for subdomain := range zw.subdomains {
		childZoneID := tableMap.get("name", subdomain.String())
		stmtMap.exec("name_to_zone", childZoneID)
		stmtMap.exec("subdomain", zoneID, childZoneID)
	}

	stmtMap.exec("set_walked", zoneID)
}

func nsecWalk(db *sql.DB) {
	readerWriter("performing NSEC walks", db, getDbNameData(`
	SELECT DISTINCT zone.name, zone.id
	FROM name AS zone
	INNER JOIN zone_nsec_state ON zone_nsec_state.zone_id = zone.id
	INNER JOIN nsec_state ON zone_nsec_state.nsec_state_id = nsec_state.id
	WHERE nsec_state.name='plain_nsec'
	AND zone.nsec_walked=FALSE
	AND zone.inserted=FALSE
`, db), nsecWalkMaster)
}

var rootName = mustParseName(".")

func _getMiddle(zone dns.Name, rn rangeset.RangeEntry[dns.Name]) iter.Seq[dns.Name] {
	start := rn.Start
	end := rn.End
	return func(yield func(dns.Name) bool) {
		splitStart := start.SplitRaw()
		splitEnd := end.SplitRaw()

		if !(end == zone || end == rootName) && splitEnd == nil {
			panic(fmt.Sprintf("end splits to nil: %s", end))
		}

		if (!(start == zone || start == rootName)) && splitStart == nil {
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
					if res, err := dns.NameFromLabels(append([]string{s}, common...)); err == nil && !yield(res) {
						return
					}
				}
			}

			if !yield(start) {
				return
			}
			if res, err := dns.NameFromLabels(append([]string{"-"}, splitStart...)); err == nil && !yield(res) {
				return
			}
		}

		if len(splitEnd) > 0 {
			last := splitEnd[0]
			if last[len(last)-1] == '-' {
				last = last[:len(last)-1] + ","
				if res, err := dns.NameFromLabels(append([]string{last}, common...)); err == nil && !yield(res) {
					return
				}
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

		commonLen := check1(dns.NameFromLabels(common)).EncodedLen()

		splitALen := min(max(20, min(63, 2+max(startLen, endLen))), 255-commonLen-2)
		for splitS := range splitAscii(startNum, endNum, 2, splitALen) {
			if res, err := dns.NameFromLabels(append([]string{splitS}, common...)); err == nil && !yield(res) {
				return
			}
		}

		if len(splitStartCopy) < len(splitEndCopy) && dns.IsSubDomain(start, end) {
			startNum := big.NewInt(0)
			endNum := labelToNum(splitEndCopy[commonLabels])
			for splitS := range splitAscii(startNum, endNum, 2, 20) {
				if res, err := dns.NameFromLabels(append([]string{splitS}, common...)); err == nil && !yield(res) {
					return
				}
			}
		}
	}
}

func getMiddle(zone dns.Name, rn rangeset.RangeEntry[dns.Name]) iter.Seq[dns.Name] {
	return func(yield func(dns.Name) bool) {
		for res := range _getMiddle(zone, rn) {
			if !(dns.IsSubDomain(zone, res) && dns.Compare(rn.Start, res) <= 0 && (rn.End == zone || dns.Compare(res, rn.End) == -1)) {
				continue
			}
			if !yield(res) {
				break
			}
		}
	}
}
