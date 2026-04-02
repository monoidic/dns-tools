package main

import (
	"context"
	"database/sql"
	"fmt"
	"iter"
	"log"
	"math/big"
	"slices"
	"strings"
	"sync"

	"github.com/monoidic/dns"
	"github.com/monoidic/rangeset"
	"golang.org/x/sync/semaphore"
)

type walkZone struct {
	zone        dns.Name
	id          int64
	rrTypeChan  chan dns.RR
	sem         *semaphore.Weighted
	wg          *sync.WaitGroup
	pool        *sync.Pool
	mux         *sync.Mutex
	seenCounter map[rangeset.RangeEntry[dns.Name]]int
}

func (wz *walkZone) addKnown(rr dns.RR, rs *rangeset.RangeSet[dns.Name], rn rangeset.RangeEntry[dns.Name]) bool {
	if !dns.IsSubDomain(wz.zone, rn.Start) {
		return false
	}

	if rs.ContainsRange(rn) {
		return false
	}

	rs.Add(rn)
	wz.rrTypeChan <- rr

	return true
}

func (wz *walkZone) unknownRanges(rs *rangeset.RangeSet[dns.Name]) iter.Seq[rangeset.RangeEntry[dns.Name]] {
	return func(yield func(rangeset.RangeEntry[dns.Name]) bool) {
		zone := wz.zone

		l := rs.Len()

		if l == 0 {
			// no known results, just give the whole zone
			_ = yield(rangeset.RangeEntry[dns.Name]{Start: zone, End: zone})
			return
		}

		firstRn := check1(rs.Get(0))
		firstName := firstRn.Start
		if firstName != zone {
			// unknown range before first known range
			if !yield(rangeset.RangeEntry[dns.Name]{Start: zone, End: firstName}) {
				return
			}
		}

		last := firstRn.End
		vi := firstRn
		for i := range l - 1 {
			vii := check1(rs.Get(i + 1))
			start := vi.End
			end := vii.Start
			last = vii.End

			if !yield(rangeset.RangeEntry[dns.Name]{Start: start, End: end}) {
				return
			}
			vi = vii
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

	knownRanges := rangeset.NewRangeset(dns.Compare, zone, true)

	full := rangeset.RangeEntry[dns.Name]{Start: zone, End: zone}
	for _, rn := range []rangeset.RangeEntry[dns.Name]{{Start: zone, End: thisRn.Start}, {Start: thisRn.End, End: zone}} {
		if rn != full {
			knownRanges.Add(rn)
		}
	}

	unknowns := slices.Collect(wz.unknownRanges(knownRanges))
	subdomains := make(Set[dns.Name])

	for _, rn := range unknowns {
		for middle := range getMiddle(zone, rn) {
			check(wz.sem.Acquire(context.Background(), 1))
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
					dns.Canonicalize(rrT)
					if soaZone := rrT.Hdr.Name; dns.Compare(zone, soaZone) != 0 && dns.IsSubDomain(zone, soaZone) {
						// fmt.Printf("found subdomain %s of domain %s\n", soaZone, zone)
						wz.rrTypeChan <- rr
						foundSubdomains = true
						subdomains.Add(soaZone)
					}
				case *dns.RRSIG:
					dns.Canonicalize(rrT)
					if rrsigZone := rrT.SignerName; dns.Compare(zone, rrsigZone) != 0 && dns.IsSubDomain(zone, rrsigZone) {
						// fmt.Printf("found subdomain %s of domain %s\n", soaZone, zone)
						wz.rrTypeChan <- rr
						foundSubdomains = true
						subdomains.Add(rrsigZone)
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
					dns.Canonicalize(rrT)
					if wz.addKnown(rr, knownRanges, rangeset.RangeEntry[dns.Name]{Start: rrT.Hdr.Name, End: rrT.NextDomain}) {
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

	var thisDuped bool

	unknowns = slices.Collect(wz.unknownRanges(knownRanges))
unkRanges:
	for _, rn := range unknowns {
		if rn == thisRn {
			thisDuped = true
			for subdomain := range subdomains {
				if dns.IsSubDomain(subdomain, rn.Start) && dns.IsSubDomain(subdomain, rn.End) {
					log.Printf("skip walking subdomain range %s for zone %s", rn, subdomain)
					continue unkRanges
				}
			}
			log.Printf("redoing range %s", rn)
			if !nsecForever {
				wz.mux.Lock()
				wz.seenCounter[thisRn]++
				doSkip := wz.seenCounter[thisRn] >= retries
				if doSkip {
					delete(wz.seenCounter, thisRn)
					wz.mux.Unlock()
					fmt.Printf("skipped range: %s\n", rn)
					continue
				}
				wz.mux.Unlock()
			}
		}
		wz.wg.Go(func() { nsecWalkResolveWorker(wz, rn) })
	}

	if !thisDuped && !nsecForever {
		wz.mux.Lock()
		delete(wz.seenCounter, thisRn)
		wz.mux.Unlock()
	}
}

func nsecWalkResolve(_ *connCache, _ *dns.Msg, zd *retryWrap[nameData, empty]) (*walkZone, error) {
	wz := &walkZone{
		zone:        zd.val.name,
		id:          zd.val.id,
		rrTypeChan:  make(chan dns.RR, MIDBUFLEN),
		sem:         semaphore.NewWeighted(1000),
		wg:          &sync.WaitGroup{},
		pool:        &sync.Pool{},
		seenCounter: make(map[rangeset.RangeEntry[dns.Name]]int),
		mux:         &sync.Mutex{},
	}

	zone := zd.val.name

	wz.pool.New = func() any { return getConnCache() }
	wz.wg.Go(func() { nsecWalkResolveWorker(wz, rangeset.RangeEntry[dns.Name]{Start: zone, End: zone}) })

	go func() {
		wz.wg.Wait()
		close(wz.rrTypeChan)
	}()

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

	res, err := plainResolveRandom(&msg, connCache)
	if err == nil {
		return res
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

func nsecWalkResWrite(tsm *TableStmtMap, res nsecWalkResolveRes) {
	var rrTypeID, rrNameID int64
	defaultRRTypeID := res.rrType.id
	defaultRRNameID := res.rrName.id

	for _, rr := range res.results {
		if rr.rrType == res.rrType.name {
			rrTypeID = defaultRRTypeID
		} else {
			rrTypeID = tsm.get("rr_type", rr.rrType)
		}

		if rr.rrName == res.rrName.name {
			rrNameID = defaultRRNameID
		} else {
			rrNameID = tsm.get("rr_name", rr.rrName.String())
		}

		rrValueID := tsm.get("rr_value", rr.rrValue)
		zoneID := res.rrValue.id

		tsm.exec("insert", zoneID, rrTypeID, rrNameID, rrValueID)
	}

	tsm.exec("queried", res.id)
}

func nsecWalkInsert(tsm *TableStmtMap, zw *walkZone) {
	zoneID := zw.id

	addSubdomain := func(subdomain dns.Name) {
		childZoneID := tsm.get("name", subdomain.String())
		tsm.exec("name_to_zone", childZoneID)
		tsm.exec("subdomain", zoneID, childZoneID)
	}

rrLoop:
	for rr := range zw.rrTypeChan {
		// NSEC, SOA or RRSIG
		switch rrT := rr.(type) {
		case *dns.SOA:
			addSubdomain(rrT.Hdr.Name)
			continue rrLoop
		case *dns.RRSIG:
			addSubdomain(rrT.SignerName)
			continue rrLoop
		}

		rrT := rr.(*dns.NSEC)
		rrName := rrT.Hdr.Name
		rrNameID := tsm.get("rr_name", rrName.String())
		// TODO detect wildcards via dns.RRSIG.Labels?

	rrtLoop:
		for rrType := range rrT.TypeBitMap.Iter {
			switch rrType {
			case dns.TypeNSEC, dns.TypeRRSIG:
				// skip
				continue rrtLoop
			}
			if rrType == dns.TypeNS && rrName != zw.zone {
				addSubdomain(rrName)
			}

			rrTypeID := tsm.get("rr_type", rrType.String())

			tsm.exec("walk_res", zoneID, rrNameID, rrTypeID)
		}
	}

	tsm.exec("set_walked", zoneID)
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
	AND zone.is_zone=TRUE AND zone.registered=TRUE AND zone.valid=TRUE
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
			log.Panicf("end splits to nil: %s", end)
		}

		if (!(start == zone || start == rootName)) && splitStart == nil {
			log.Panicf("start splits to nil: %s", start)
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

		startNum := &big.Int{}
		endNum := &big.Int{}

		for _, lc := range []*labelConverter{lcAscii, lcSymbols, lcFull} {
			startNum.Set(big0)
			endNum.Set(lc.maxLabelNum)
			var startLen, endLen int

			if commonLabels < len(splitStartCopy) {
				startNumX, err := lc.labelToNum(splitStartCopy[commonLabels])
				if err != nil {
					continue
				}
				startNum.Set(startNumX)
				startLen = len(splitStartCopy[commonLabels])
			}
			if commonLabels < len(splitEndCopy) {
				endNumX, err := lc.labelToNum(splitEndCopy[commonLabels])
				if err != nil {
					continue
				}
				endNum.Set(endNumX)
				endLen = len(splitEndCopy[commonLabels])
			}

			if startNum.Cmp(endNum) != -1 {
				// startNum >= endNum
				startNum.SetInt64(0)
				endNum.Set(lc.maxLabelNum)
			}

			commonLen := check1(dns.NameFromLabels(common)).EncodedLen()

			// try to be at least a bit longer than the start/end of the range
			splitALen := 2 + max(startLen, endLen)
			// try to be at least 10 characters regardless
			splitALen = max(splitALen, 10)
			// clamp according to protocol-defined max label/name limits
			splitALen = min(splitALen, MAX_NAME_LEN-commonLen-2, MAX_LABEL_LEN)
			for splitS := range lc.bisectLabel(startNum, endNum, splitALen) {
				if res, err := dns.NameFromLabels(append([]string{splitS}, common...)); err == nil && !yield(res) {
					return
				}
			}

			if !(len(splitStartCopy) < len(splitEndCopy) && dns.IsSubDomain(start, end)) {
				continue
			}

			startNum.Set(big0)
			endNumX, err := lc.labelToNum(splitEndCopy[commonLabels])
			if err != nil {
				continue
			}
			endNum.Set(endNumX)

			for splitS := range lc.bisectLabel(startNum, endNum, 20) {
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
				return
			}
		}
	}
}
