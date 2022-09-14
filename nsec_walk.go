package main

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/monoidic/dns"
)

type middleFunc func([]string) []string

type walkZone struct {
	zone            string
	id              int64
	unhandledRanges map[string]bool
	knownRanges     [][2]string // sorted list of ranges; ends with (<last_record>, "")
	subdomains      map[string]bool
	rrTypes         map[string][]string
}

/*
func (wz *walkZone) contains(z string) bool {
	l := len(wz.knownRanges)

	i := sort.Search(l, func(i int) bool { return dns.Compare(wz.knownRanges[i][0], z) <= 0 })
	if i == l {
		return false
	}

	r := wz.knownRanges[i]
	start, end := r[0], r[1]
	return dns.Compare(start, z) <= 0 && (end == "" || dns.Compare(z, end) == -1)
}
*/

func (wz *walkZone) addKnown(rr dns.NSEC) bool {
	normalizeRR(&rr)
	start := rr.Hdr.Name
	end := rr.NextDomain

	if !(start == wz.zone || strings.HasSuffix(start, "."+wz.zone)) { // subdomain check
		return false
		// TODO list these somewhere?
	}

	if _, ok := wz.rrTypes[start]; ok {
		return false
	}

	var nsecTypes []string
	for _, t := range rr.TypeBitMap {
		switch t {
		case dns.TypeNSEC, dns.TypeRRSIG: // skip
		default:
			nsecTypes = append(nsecTypes, dns.Type(t).String())
		}
	}

	wz.rrTypes[start] = nsecTypes

	l := len(wz.knownRanges)
	i := sort.Search(l, func(i int) bool { return dns.Compare(start, wz.knownRanges[i][0]) <= 0 })

	// fmt.Printf("dns.Compare(%s, %s) == %d\n", start, end, dns.Compare(start, end))
	// fmt.Printf("addKnown i=%d l=%d start=%s end=%s known=%v\n", i, l, start, end, wz.knownRanges)

	if i == l { // append
		// fmt.Printf("=past end start=%s end=%s\n", start, end)
		if l == 0 {
			wz.knownRanges = append(wz.knownRanges, [2]string{start, end})
			return true
		}

		lastKnown := wz.knownRanges[l-1][1]
		zone := wz.zone

		// if dns.Compare(lastKnown, zone) == 0 { // }
		if lastKnown == "" {
			// covered by wraparound
			// fmt.Printf("=covered by wraparound, lastKnown=%s start=%s end=%s\n", lastKnown, start, end)
			return true
		} else if dns.Compare(start, lastKnown) == 1 { // no overlap, append
			wz.knownRanges = append(wz.knownRanges, [2]string{start, end})
			return true
		}
		// # merge (oldStart < newStart <= (oldEnd, newEnd)) into (oldStart < max(oldEnd, newEnd))
		if dns.Compare(wz.knownRanges[l-1][0], start) != -1 {
			fmt.Printf("assertion failure, merge last range %s < %s evaluated false, lastKnown=%s, knownRanges=%v", wz.knownRanges[l-1][0], start, lastKnown, wz.knownRanges)
			return false
		}
		var newEnd string
		if dns.Compare(end, zone) == 0 || dns.Compare(lastKnown, zone) == 0 {
			newEnd = zone
		} else {
			if dns.Compare(end, lastKnown) == 1 {
				newEnd = end
			} else {
				newEnd = lastKnown
			}
		}
		wz.knownRanges[l-1][1] = newEnd
		return true
	} else if i == 0 { // prepend or merge with first
		switch dns.Compare(end, wz.knownRanges[0][0]) {
		case -1: // prepend
			// fmt.Printf("=before start=%s end=%s\n", start, end)
			wz.knownRanges = append([][2]string{{start, end}}, wz.knownRanges...)
		case 0: // merge
			wz.knownRanges[0][0] = start
		default:
			fmt.Printf("prepend or merge: %s > %s unexpected", end, wz.knownRanges[0][0])
			return false
		}
		return true
	}
	// fmt.Printf("=middle start=%s end=%s\n", start, end)
	// middle
	// explained in python/nsecWalk.py => Zone.AddToMiddle()

	iR := wz.knownRanges[i]
	prevR := wz.knownRanges[i-1]
	indexStart, indexEnd := iR[0], iR[1]
	prevStart, prevEnd := prevR[0], prevR[1]

	switch dns.Compare(start, indexStart) {
	case 0: // start
		if dns.Compare(end, indexEnd) == 1 {
			fmt.Printf("unexpected value at start == indexStart, %s _ %s _ %s _ %s", start, end, indexStart, indexEnd)
			return false
		}

	case 1: // middle
		if dns.Compare(start, indexEnd) == -1 { // middle
			if dns.Compare(end, indexEnd) == 1 {
				fmt.Printf("unexpected value at indexStart < start < indexEnd, %s _ %s _ %s _ %s", start, end, indexStart, indexEnd)
				return false
			}
		} else {
			fmt.Printf("unreachable, %s _ %s _ %s _ %s", start, end, indexStart, indexEnd)
			return false
		}

	case -1: // end or outside
		cmpEndIndexStart := dns.Compare(end, indexStart)
		cmpStartPrevEnd := dns.Compare(start, prevEnd)

		switch switchKey := cmpStartPrevEnd*3 + cmpEndIndexStart; switchKey {
		case 0*3 + 0: // end, merge
			tmp := append(wz.knownRanges[:i-1], [2]string{prevStart, indexEnd})
			wz.knownRanges = append(tmp, wz.knownRanges[i+1:]...)
		case 0*3 + -1: // end, extend
			wz.knownRanges[i-1][1] = end
		case 1*3 + 0: // outside, extend
			wz.knownRanges[i][0] = start
		case 1*3 + -1: // outside, new
			wz.knownRanges = append(wz.knownRanges[:i+1], wz.knownRanges[i:]...)
			wz.knownRanges[i] = [2]string{start, end}
		default:
			fmt.Printf("unexpected value, start=%s end=%s indexStart=%s indexEnd=%s prevStart=%s prevEnd=%s", start, end, indexStart, indexEnd, prevStart, prevEnd)
			return false
		}
	}

	return true
}

func (wz *walkZone) addUnhandled(start, end string) {
	wz.unhandledRanges[fmt.Sprintf("%s|%s", start, end)] = true
}

func (wz *walkZone) isUnhandled(start, end string) bool {
	return wz.unhandledRanges[fmt.Sprintf("%s|%s", start, end)]
}

func (wz *walkZone) nextUnknownRange() (string, string, bool) {
	l := len(wz.knownRanges)
	zone := wz.zone

	if l == 0 {
		if !wz.isUnhandled(zone, "") {
			return zone, "", true
		}
		return "", "", false
	}

	firstName := wz.knownRanges[0][0]
	if firstName != zone && !wz.isUnhandled(zone, firstName) {
		return zone, firstName, true
	}

	if l == 1 {
		lastName := wz.knownRanges[0][1]
		if lastName != "" && !wz.isUnhandled(lastName, "") {
			return lastName, "", true
		}
	} else {
		var last string
		for i := 0; i < l-1; i++ {
			start := wz.knownRanges[i][1]
			end := wz.knownRanges[i+1][0]
			last = wz.knownRanges[i+1][1]

			if !wz.isUnhandled(start, end) {
				return start, end, true
			}
		}

		if last != "" && !wz.isUnhandled(last, "") {
			return last, "", true
		}
	}

	return "", "", false
}

func nsecWalkWorker(zoneChan <-chan fieldData, dataOutChan chan<- walkZone, wg *sync.WaitGroup, once *sync.Once) {
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

	resolverWorker(zoneChan, dataOutChan, msg, nsecWalkQuery, wg, once)
}

func nsecWalkQuery(connCache connCache, msg dns.Msg, zd fieldData) walkZone {
	zone := zd.name
	wz := walkZone{zone: zone, id: zd.id, unhandledRanges: make(map[string]bool), rrTypes: make(map[string][]string), subdomains: make(map[string]bool)}
	// fmt.Printf("starting walk on zone %s\n", zone)

	for start, end, ok := wz.nextUnknownRange(); ok; start, end, ok = wz.nextUnknownRange() {
		// fmt.Printf("looping, start=%s end=%s known=%v\n", start, end, wz.knownRanges)
		if len(wz.knownRanges) == 1 && dns.Compare(wz.knownRanges[0][0], wz.knownRanges[0][1]) == 0 {
			break
		}
		var expanded bool
		var err error
		var res *dns.Msg

		for _, middle := range getMiddle(zone, start, end) {
			// fmt.Printf("guess: %s\n", middle)
			// fmt.Printf("trying middle %s between start=%s and end=%s\n", middle, start, end)
			msg.Question[0].Name = middle
			for i := 0; i < RETRIES; i++ {
				nameserver := randomNS()
				res, err = plainResolve(msg, connCache, nameserver)
				if err == nil {
					break
				}
				// fmt.Printf("resolution error %d for %s from nameserver %s : %v\n", i, middle, nameserver, err)
			}

			if err != nil {
				continue
			}

			var foundSubdomains bool

			for _, rr := range res.Ns {
				switch rrT := rr.(type) {
				case *dns.SOA:
					normalizeRR(rrT)
					if soaZone := rrT.Hdr.Name; dns.Compare(zone, soaZone) != 0 && dns.IsSubDomain(zone, soaZone) {
						// fmt.Printf("found subdomain %s of domain %s\n", soaZone, zone)
						wz.subdomains[soaZone] = true
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
					if wz.addKnown(*rrT) {
						// fmt.Printf("added entry %v\n", rrT)
						expanded = true
					}
					// fmt.Printf("%#v\n", wz.knownRanges)
				}
			}

			if expanded {
				break
			}
		}

		if !expanded {
			fmt.Printf("unhandled range start=%s end=%s on zone %s, ranges=%v\n", start, end, zone, wz.knownRanges)
			wz.addUnhandled(start, end)
		}
	}

	if len(wz.unhandledRanges) > 0 {
		fmt.Printf("unhandled in zone %s: %#v\n", wz.zone, wz.unhandledRanges)
	}

	return wz
}

func nsecWalkMaster(db *sql.DB, zoneChan <-chan fieldData, wg *sync.WaitGroup) {
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

	netWriter(db, zoneChan, wg, tablesFields, namesStmts, nsecWalkWorker, nsecWalkInsert)
}

func nsecWalkResults(db *sql.DB) {
	readerWriter("fetching zone walk results", db, getUnqueriedNsecRes, nsecWalkResWriter)
}

func nsecWalkResWriter(db *sql.DB, inChan <-chan rrDBData, wg *sync.WaitGroup) {
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

	netWriter(db, inChan, wg, tablesFields, namesStmts, nsecWalkResultResolver, nsecWalkResWrite)
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
				zw.subdomains[rrName] = true
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
	readerWriter("performing NSEC walks", db, getWalkableZones, nsecWalkMaster)
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
	return data
}

func getMiddle(zone, start, end string) []string {
	if dns.Compare(end, zone) == 0 {
		end = ""
	}

	var ret []string

	if !(end == "" || end == ".") {
		splitEnd := dns.SplitDomainName(end)
		if splitEnd == nil {
			panic(fmt.Sprintf("end splits to nil: %s", end))
		}

		for _, f := range []middleFunc{decrementLabel, nop} {
			res := strings.Join(f(splitEnd), ".") + "."
			if dns.IsSubDomain(zone, res) {
				ret = append(ret, res)
			}
		}
	}

	if !(start == "" || start == ".") {
		splitStart := dns.SplitDomainName(start)
		if splitStart == nil {
			panic(fmt.Sprintf("start splits to nil: %s", start))
		}

		for _, f := range []middleFunc{minusAppended, nop, minusSubdomains, minusSubdomain, incrementLabel} {
			res := strings.Join(f(splitStart), ".") + "."
			if dns.IsSubDomain(zone, res) && dns.Compare(start, res) <= 0 && (end == "" || dns.Compare(res, end) == -1) {
				ret = append(ret, res)
			}
		}
	}

	return ret
}

// TODO get Compare into miekg/dns

func doDDD(b []byte) []byte {
	lb := len(b)
	for i := 0; i < lb; i++ {
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
