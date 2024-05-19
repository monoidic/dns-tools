package main

import (
	"database/sql"
	"fmt"
	"iter"
	"slices"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/monoidic/rangeset"
)

type middleFunc func([]string) []string

type walkZone struct {
	zone        string
	id          int64
	knownRanges rangeset.RangeSet[string]
	subdomains  Set[string]
	rrTypes     map[string][]string
}

func (wz *walkZone) addKnown(rn rangeset.RangeEntry[string], bitmap []uint16) bool {
	if !(rn.Start == wz.zone || strings.HasSuffix(rn.Start, "."+wz.zone)) { // subdomain check
		return false
		// TODO list these somewhere?
	}

	if wz.knownRanges.ContainsRange(rn) {
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

	wz.rrTypes[rn.Start] = nsecTypes
	wz.knownRanges.Add(rn)

	return true
}

func (wz *walkZone) unknownRanges(yield func(rangeset.RangeEntry[string]) bool) {
	l := len(wz.knownRanges.Ranges)
	zone := wz.zone

	if l == 0 {
		// no known results, just give the whole zone
		_ = yield(rangeset.RangeEntry[string]{Start: zone, End: zone})
		return
	}

	firstName := wz.knownRanges.Ranges[0].Start
	if firstName != zone {
		// unknown range before first known range
		if !yield(rangeset.RangeEntry[string]{Start: zone, End: firstName}) {
			return
		}
	}

	last := wz.knownRanges.Ranges[0].End
	for i := range l - 1 {
		start := wz.knownRanges.Ranges[i].End
		end := wz.knownRanges.Ranges[i+1].Start
		last = wz.knownRanges.Ranges[i+1].End

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

func nsecWalkWorker(zoneChan <-chan retryWrap[fieldData, empty], refeedChan chan<- retryWrap[fieldData, empty], dataOutChan chan<- walkZone, wg, retryWg *sync.WaitGroup) {
	resolverWorker(zoneChan, refeedChan, dataOutChan, dns.Msg{}, nsecWalkResolve, wg, retryWg)
}

// TODO
// spawn N resolver workers with input/output channels
// add number of ranges to waitgroup, write each to input channel (initially just one zone,zone), and wait on waitgroup
// worker generates a number of middle values and tries them all, then writes all the results to the channel and does wg.Done()
// writer writes all results to walkzone in parallel
// once all ranges have been written, iterate over zone again until whole zone is known or is not being changed
// keep track of iterations and whether anything was updated this iteration in writer?
func nsecWalkResolve(_ connCache, _ dns.Msg, zd *retryWrap[fieldData, empty]) (walkZone, error) {
	wz := walkZone{
		zone:        zd.val.name,
		id:          zd.val.id,
		rrTypes:     make(map[string][]string),
		subdomains:  make(Set[string]),
		knownRanges: rangeset.RangeSet[string]{Compare: dnsCompare, HasRWrap: true, RWrapV: zd.val.name},
	}

	// fmt.Printf("starting walk on zone %s\n", zone)

	connCaches := make([]connCache, numProcs)
	for i := range numProcs {
		cache := getConnCache()
		connCaches[i] = cache
		defer cache.clear()
	}

	for {
		var expanded bool
		var wg, workerWg sync.WaitGroup

		workerInChan := make(chan string, MIDBUFLEN)
		workerOutChan := make(chan *dns.Msg, MIDBUFLEN)

		wg.Add(1)
		workerWg.Add(numProcs)

		closeChanWait(&wg, workerInChan)
		closeChanWait(&workerWg, workerOutChan)

		for i := range numProcs {
			go nsecWalker(connCaches[i], workerInChan, workerOutChan, &wg, &workerWg)
		}

		go func() {
			defer wg.Done()
			for _, rn := range collect(wz.unknownRanges) {
				for middle := range getMiddle(wz.zone, rn) {
					wg.Add(1)
					workerInChan <- middle
				}
			}
		}()

		for res := range workerOutChan {
			if res == nil {
				continue
			}

			var foundSubdomains bool

			for _, rr := range res.Ns {
				switch rrT := rr.(type) {
				case *dns.SOA:
					normalizeRR(rrT)
					if soaZone := rrT.Hdr.Name; dnsCompare(wz.zone, soaZone) != 0 && dns.IsSubDomain(wz.zone, soaZone) {
						// fmt.Printf("found subdomain %s of domain %s\n", soaZone, zone)
						wz.subdomains.Add(soaZone)
						foundSubdomains = true
					}
				}
			}

			if foundSubdomains {
				continue
			}

			for _, rr := range res.Ns {
				switch rrT := rr.(type) {
				case *dns.NSEC:
					normalizeRR(rrT)
					if wz.addKnown(rangeset.RangeEntry[string]{Start: rrT.Hdr.Name, End: rrT.NextDomain}, rrT.TypeBitMap) {
						// fmt.Printf("added entry %v\n", rrT)
						expanded = true
					}
					// fmt.Printf("%#v\n", wz.knownRanges)
				}
			}
		}

		if !expanded {
			break
		}
	}

	return wz, nil
}

func nsecWalker(connCache connCache, inChan <-chan string, outChan chan<- *dns.Msg, wg, workerWg *sync.WaitGroup) {
	defer workerWg.Done()
	msg := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Opcode:           dns.OpcodeQuery,
			RecursionDesired: true,
			Rcode:            dns.RcodeSuccess,
		},
		Question: []dns.Question{{
			Qclass: dns.ClassINET,
			// Qtype: dns.TypeNSEC3PARAM,
			Qtype: dns.TypeAPL,
		}},
	}
	msgSetSize(&msg)
	msg.Extra[0].(*dns.OPT).SetDo()

	for middle := range inChan {
		msg.Question[0].Name = middle
		var err error
		var res *dns.Msg
		for range RETRIES {
			res, err = plainResolveRandom(msg, connCache)
			if err == nil {
				break
			}
		}

		if err == nil {
			outChan <- res
		} else {
			outChan <- nil
		}

		wg.Done()
	}
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

func nsecWalkInsert(tableMap TableMap, stmtMap StmtMap, zw walkZone) {
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

func decrementLabel(data []string) []string {
	label := []byte(data[0])
	label[len(label)-1]--
	return append([]string{string(label)}, data[1:]...)
}

func incrementLabel(data []string) []string {
	label := []byte(data[0])
	label[len(label)-1]++
	return append([]string{string(label)}, data[1:]...)
}

func minusAppended(data []string) []string {
	ret := make([]string, len(data))
	copy(ret, data)
	ret[0] += "-"
	return ret
}

func minusSubdomains(data []string) []string {
	return append([]string{"-", "-"}, data...)
}

func minusSubdomain(data []string) []string {
	return append([]string{"-"}, data...)
}

func nop(data []string) []string {
	return slices.Clone(data)
}

// TODO use splitAscii here
func _getMiddle(zone string, rn rangeset.RangeEntry[string]) iter.Seq[[]string] {
	start := rn.Start
	end := rn.End
	return func(yield func([]string) bool) {
		splitStart := dns.SplitDomainName(start)
		splitEnd := dns.SplitDomainName(end)

		if !(splitStart == nil || splitEnd == nil) {
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

			var startNum, endNum float64
			startNum = 0
			endNum = 1

			if commonLabels < len(splitStartCopy) {
				startNum = stringFract(splitStartCopy[commonLabels])
			}
			if commonLabels < len(splitEndCopy) {
				endNum = stringFract(splitEndCopy[commonLabels])
			}

			if startNum >= endNum {
				startNum = 0
				endNum = 1
			}

			for splitS := range splitAscii(startNum, endNum, 5, 20) {
				res := append([]string{splitS}, common...)
				if !yield(res) {
					return
				}
			}
		}

		if !(end == zone || end == ".") {
			if splitEnd == nil {
				panic(fmt.Sprintf("end splits to nil: %s", end))
			}

			for _, f := range []middleFunc{decrementLabel} { // nop
				if !yield(f(splitEnd)) {
					return
				}
			}
		}

		if !(start == zone || start == ".") {
			if splitStart == nil {
				panic(fmt.Sprintf("start splits to nil: %s", start))
			}

			for _, f := range []middleFunc{minusAppended, incrementLabel, minusSubdomains, minusSubdomain} { // nop minusSubdomains, minusSubdomain
				if !yield(f(splitStart)) {
					return
				}
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
