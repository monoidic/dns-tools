package main

import (
	"database/sql"
	"fmt"
	"math/rand"
	"strings"
	"sync"

	"github.com/monoidic/dns"
)

type middleFunc func([]string) []string

type walkZone struct {
	zone            string
	id              int64
	unhandledRanges Set[string]
	knownRanges     RangeSet[string]
	subdomains      Set[string]
	rrTypes         map[string][]string
}

func (wz *walkZone) addKnown(start, end string, bitmap []uint16) bool {
	if !(start == wz.zone || strings.HasSuffix(start, "."+wz.zone)) { // subdomain check
		return false
		// TODO list these somewhere?
	}

	if wz.knownRanges.ContainsRange(start, end) {
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

	wz.rrTypes[start] = nsecTypes

	wz.knownRanges.Add(start, end)

	return true
}

func (wz *walkZone) addUnhandled(start, end string) {
	wz.unhandledRanges.Add(fmt.Sprintf("%s|%s", start, end))
}

func (wz *walkZone) isUnhandled(start, end string) bool {
	return wz.unhandledRanges.Contains(fmt.Sprintf("%s|%s", start, end))
}

func (wz *walkZone) nextUnknownRange() (string, string, bool) {
	l := len(wz.knownRanges.Ranges)
	zone := wz.zone

	if l == 0 {
		if !wz.isUnhandled(zone, zone) {
			return zone, zone, true
		}
		return "", "", false
	}

	firstName := wz.knownRanges.Ranges[0][0]
	if firstName != zone && !wz.isUnhandled(zone, firstName) {
		return zone, firstName, true
	}

	if l == 1 {
		lastName := wz.knownRanges.Ranges[0][1]
		if lastName != zone && !wz.isUnhandled(lastName, zone) {
			return lastName, zone, true
		}
	} else {
		var last string
		for i := 0; i < l-1; i++ {
			start := wz.knownRanges.Ranges[i][1]
			end := wz.knownRanges.Ranges[i+1][0]
			last = wz.knownRanges.Ranges[i+1][1]

			if !wz.isUnhandled(start, end) {
				return start, end, true
			}
		}

		if last != zone && !wz.isUnhandled(last, zone) {
			return last, zone, true
		}
	}

	return "", "", false
}

func nsecWalkWorker(zoneChan <-chan fieldData, dataOutChan chan<- walkZone, wg *sync.WaitGroup) {
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

	resolverWorker(zoneChan, dataOutChan, msg, splitNsecWalk, wg)
}

// split NSEC search space into n=NUMPROCS sections, run in parallel, and merge
func splitNsecWalk(_ connCache, msg dns.Msg, zd fieldData) walkZone {
	zone := zd.name
	wzch := make(chan walkZone, numProcs)

	for _, sr := range splitAscii(zone, numProcs, 5) {
		wz := walkZone{
			zone:            zone,
			id:              zd.id,
			unhandledRanges: make(Set[string]),
			rrTypes:         make(map[string][]string),
			subdomains:      make(Set[string]),
			knownRanges:     RangeSet[string]{Compare: dns.Compare, HasWrap: true, WrapV: zone},
		}
		for _, r := range [][2]string{sr.prevKnown, sr.afterKnown} {
			if len(r[0])+len(r[1]) > 0 {
				wz.addKnown(r[0], r[1], nil)
			}
		}

		go nsecWalkQuery(getConnCache(), msg, wz, wzch)
	}

	ret := walkZone{zone: zone, id: zd.id, unhandledRanges: make(Set[string]), rrTypes: make(map[string][]string), subdomains: make(Set[string])}
	for i := 0; i < numProcs; i++ {
		wz := <-wzch
		for r := range wz.unhandledRanges {
			ret.unhandledRanges.Add(r)
		}
		for k, v := range wz.rrTypes {
			if v != nil {
				ret.rrTypes[k] = v
			}
		}
		for d := range wz.subdomains {
			ret.subdomains.Add(d)
		}
	}

	close(wzch)
	return ret
}

func nsecWalkQuery(connCache connCache, msg dns.Msg, wz walkZone, wzch chan<- walkZone) {
	zone := wz.zone
	// fmt.Printf("starting walk on zone %s\n", zone)

	for start, end, ok := wz.nextUnknownRange(); ok; start, end, ok = wz.nextUnknownRange() {
		// fmt.Printf("looping, start=%s end=%s known=%v\n", start, end, wz.knownRanges)
		if len(wz.knownRanges.Ranges) == 1 && dns.Compare(wz.knownRanges.Ranges[0][0], wz.zone) == 0 && wz.knownRanges.Ranges[0][1] == wz.zone {
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
					if wz.addKnown(rrT.Hdr.Name, rrT.NextDomain, rrT.TypeBitMap) {
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

	connCache.clear()

	wzch <- wz
}

func nsecWalkMaster(db *sql.DB, zoneChan <-chan fieldData) {
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

	netWriter(db, zoneChan, tablesFields, namesStmts, nsecWalkWorker, nsecWalkInsert)
}

func nsecWalkResults(db *sql.DB) {
	readerWriter("fetching zone walk results", db, getUnqueriedNsecRes, nsecWalkResWriter)
}

func nsecWalkResWriter(db *sql.DB, inChan <-chan rrDBData) {
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

	netWriter(db, inChan, tablesFields, namesStmts, nsecWalkResultResolver, nsecWalkResWrite)
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
		end = zone
	}

	var ret []string
	var splitEnd, splitStart []string

	if !(end == zone || end == ".") {
		splitEnd = dns.SplitDomainName(end)
		if splitEnd == nil {
			panic(fmt.Sprintf("end splits to nil: %s", end))
		}

		for _, f := range []middleFunc{decrementLabel} { // nop
			res := strings.Join(f(splitEnd), ".") + "."
			if dns.IsSubDomain(zone, res) && dns.Compare(start, res) <= 0 && (end == zone || dns.Compare(res, end) == -1) {
				ret = append(ret, res)
			}
		}
	}

	if !(start == zone || start == ".") {
		splitStart = dns.SplitDomainName(start)
		if splitStart == nil {
			panic(fmt.Sprintf("start splits to nil: %s", start))
		}

		for _, f := range []middleFunc{minusAppended, incrementLabel} { // nop minusSubdomains, minusSubdomain
			res := strings.Join(f(splitStart), ".") + "."
			if dns.IsSubDomain(zone, res) && dns.Compare(start, res) <= 0 && (end == zone || dns.Compare(res, end) == -1) {
				ret = append(ret, res)
			}
		}
	}

	if !(splitStart == nil || splitEnd == nil) {
		startF := stringFract(splitStart[0])
		endF := stringFract(splitEnd[0])
		rangeF := endF - startF
		middleF := rand.Float64()*rangeF + startF
		middleS := fractString(middleF, 10)
		res := strings.Join(append([]string{middleS}, splitStart[1:]...), ".") + "."
		if dns.IsSubDomain(zone, res) && dns.Compare(start, res) <= 0 && (end == zone || dns.Compare(res, end) == -1) {
			ret = append(ret, res)
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
