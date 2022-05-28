package main

import (
	"database/sql"
	"fmt"
	"github.com/miekg/dns"
	"math/rand"
	"sort"
	"strings"
	"sync"
)

type middleFunc func([]string) []string

type walkZone struct {
	zone            string
	id              int64
	unhandledRanges map[string]bool
	knownRanges     [][2]string // sorted list of ranges; ends with (<last_record>, <first_record>)
	subdomains      map[string]bool
	rrTypes         map[string][]string
}

func (wz *walkZone) contains(z string) bool {
	l := len(wz.knownRanges)

	i := sort.Search(l, func(i int) bool { return Compare(wz.knownRanges[i][0], z) <= 0 })
	if i == l {
		return false
	}

	r := wz.knownRanges[i]
	start, end := r[0], r[1]
	return Compare(start, z) <= 0 && (end == wz.zone || Compare(z, end) == -1)
}

func (wz *walkZone) addKnown(rr dns.NSEC) bool {
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
		switch s := dns.Type(t).String(); s {
		case "NSEC", "RRSIG": // undesirable
		default:
			nsecTypes = append(nsecTypes, s)
		}
	}

	wz.rrTypes[start] = nsecTypes

	l := len(wz.knownRanges)
	i := sort.Search(l, func(i int) bool { return Compare(start, wz.knownRanges[i][0]) <= 0 })

	//fmt.Printf("compare(%s, %s) == %d\n", start, end, Compare(start, end))
	//fmt.Printf("addKnown i=%d l=%d start=%s end=%s known=%v\n", i, l, start, end, wz.knownRanges)

	if i == l { // append
		//fmt.Printf("=past end start=%s end=%s\n", start, end)
		if l == 0 {
			wz.knownRanges = append(wz.knownRanges, [2]string{start, end})
			return true
		}

		lastKnown := wz.knownRanges[l-1][1]
		zone := wz.zone

		// if Compare(lastKnown, zone) == 0 { // }
		if lastKnown == "" {
			// covered by wraparound
			//fmt.Printf("=covered by wraparound, lastKnown=%s start=%s end=%s\n", lastKnown, start, end)
		} else if Compare(start, lastKnown) == 1 { // no overlap, append
			wz.knownRanges = append(wz.knownRanges, [2]string{start, end})
		} else { // # merge (oldStart < newStart <= (oldEnd, newEnd)) into (oldStart < max(oldEnd, newEnd))
			if Compare(wz.knownRanges[l-1][0], start) != -1 {
				panic(fmt.Sprintf("assertion failure, merge last range %s < %s evaluated false, lastKnown=%s, knownRanges=%v", wz.knownRanges[l-1][0], start, lastKnown, wz.knownRanges))
			}
			var newEnd string
			if Compare(end, zone) == 0 || Compare(lastKnown, zone) == 0 {
				newEnd = zone
			} else {
				if Compare(end, lastKnown) == 1 {
					newEnd = end
				} else {
					newEnd = lastKnown
				}
			}
			wz.knownRanges[l-1][1] = newEnd
		}
		return true
	} else if i == 0 { // prepend or merge with first
		switch Compare(end, wz.knownRanges[0][0]) {
		case -1: // prepend
			// fmt.Printf("=before start=%s end=%s\n", start, end)
			wz.knownRanges = append([][2]string{[2]string{start, end}}, wz.knownRanges...)
		case 0: // merge
			wz.knownRanges[0][0] = start
		default:
			panic(fmt.Sprintf("prepend or merge: %s > %s unexpected", end, wz.knownRanges[0][0]))
		}
		return true
	}
	//fmt.Printf("=middle start=%s end=%s\n", start, end)
	// middle
	// explained in python/nsecWalk.py => Zone.AddToMiddle()

	iR := wz.knownRanges[i]
	prevR := wz.knownRanges[i-1]
	indexStart, indexEnd := iR[0], iR[1]
	prevStart, prevEnd := prevR[0], prevR[1]

	switch Compare(start, indexStart) {
	case 0: // start
		if Compare(end, indexEnd) == 1 {
			panic(fmt.Sprintf("unexpected value at start == indexStart, %s _ %s _ %s _ %s", start, end, indexStart, indexEnd))
		}
	case 1: // middle
		if Compare(start, indexEnd) == -1 { // middle
			if Compare(end, indexEnd) == 1 {
				panic(fmt.Sprintf("unexpected value at indexStart < start < indexEnd, %s _ %s _ %s _ %s", start, end, indexStart, indexEnd))
			}
		} else {
			panic(fmt.Sprintf("unreachable, %s _ %s _ %s _ %s", start, end, indexStart, indexEnd))
		}
	case -1: // end or outside
		cmpEndIndexStart := Compare(end, indexStart)
		cmpStartPrevEnd := Compare(start, prevEnd)

		switch switchKey := (cmpStartPrevEnd+1)*3 + (cmpEndIndexStart + 1); switchKey {
		case (0+1)*3 + (0 + 1): // end, merge
			tmp := append(wz.knownRanges[:i-1], [2]string{prevStart, indexEnd})
			wz.knownRanges = append(tmp, wz.knownRanges[i+1:]...)
		case (0+1)*3 + (-1 + 1): // end, extend
			wz.knownRanges[i-1][1] = end
		case (1+1)*3 + (0 + 1): // outside, extend
			wz.knownRanges[i][0] = start
		case (1+1)*3 + (-1 + 1): // outside, new
			wz.knownRanges = append(wz.knownRanges[:i+1], wz.knownRanges[i:]...)
			wz.knownRanges[i] = [2]string{start, end}
		default:
			panic(fmt.Sprintf("unexpected value, start=%s end=%s indexStart=%s indexEnd=%s prevStart=%s prevEnd=%s", start, end, indexStart, indexEnd, prevStart, prevEnd))
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

func nsecWalkWorker(zoneChan chan fieldData, dataOutChan chan walkZone, wg *sync.WaitGroup, once *sync.Once) {
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
	fmt.Printf("starting walk on zone %s\n", zone)

	for start, end, ok := wz.nextUnknownRange(); ok; start, end, ok = wz.nextUnknownRange() {
		// fmt.Printf("looping, start=%s end=%s known=%v\n", start, end, wz.knownRanges)
		if len(wz.knownRanges) == 1 && Compare(wz.knownRanges[0][0], wz.knownRanges[0][1]) == 0 {
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
				nameserver := usedNs[rand.Intn(usedNsLen)]
				res, err = plainResolve(msg, connCache, nameserver)
				if err == nil {
					break
				}
				//fmt.Printf("resolution error %d for %s from nameserver %s : %v\n", i, middle, nameserver, err)
			}

			if err != nil {
				continue
			}

			var foundSubdomains bool

			for _, rr := range res.Ns {
				switch rrT := rr.(type) {
				case *dns.SOA:
					soaZone := dns.Fqdn(rrT.Hdr.Name)
					if Compare(zone, soaZone) != 0 && dns.IsSubDomain(zone, soaZone) {
						soaZone = strings.ToLower(soaZone)
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

	return wz
}

func nsecWalkMaster(db *sql.DB, zoneChan chan fieldData, wg *sync.WaitGroup) {
	tablesFields := map[string]string{
		"name":    "name",
		"rr_type": "name",
		"rr_name": "name",
	}
	namesStmts := map[string]string{
		"walkRes":    "INSERT OR IGNORE INTO zone_walk_res (zone_id, rr_name_id, rr_type_id) VALUES (?, ?, ?)",
		"subdomain":  "INSERT OR IGNORE INTO zone_parent (child_id, parent_id) VALUES (?, ?)",
		"setWalked":  "UPDATE name SET nsec_walked=TRUE WHERE id=?",
		"nameToZone": "UPDATE name SET is_zone=TRUE WHERE id=?",
	}

	netWriter(db, zoneChan, wg, tablesFields, namesStmts, nsecWalkWorker, nsecWalkInsert)
}

func nsecWalkInsert(tableMap TableMap, stmtMap StmtMap, zw walkZone) {
	var err error
	zoneID := zw.id

	for rrName, rrtL := range zw.rrTypes {
		rrNameID := tableMap["rr_name"].get(rrName)

		for _, rrType := range rrtL {
			if rrType == "NS" {
				zw.subdomains[rrName] = true
			}

			rrTypeID := tableMap["rr_type"].get(rrType)

			_, err = stmtMap["walkRes"].stmt.Exec(zoneID, rrNameID, rrTypeID)
			check(err)
		}
	}

	for subdomain := range zw.subdomains {
		childZoneID := tableMap["name"].get(subdomain)
		_, err = stmtMap["nameToZone"].stmt.Exec(childZoneID)
		check(err)

		_, err = stmtMap["subdomain"].stmt.Exec(childZoneID, zoneID)
		check(err)
	}

	_, err = stmtMap["setWalked"].stmt.Exec(zoneID)
	check(err)
}

func nsecWalk(db *sql.DB) {
	fmt.Println("performing NSEC walks")

	var wg sync.WaitGroup
	zoneChan := make(chan fieldData, BUFLEN)
	go getWalkableZones(db, zoneChan, &wg)
	nsecWalkMaster(db, zoneChan, &wg)
}

func decrementLabel(data []string) []string {
	label := []byte(data[0])
	label[0]--
	return append([]string{string(label)}, data[1:]...)
}

func incrementLabel(data []string) []string {
	label := []byte(data[0])
	label[0]++
	return append([]string{string(label)}, data[1:]...)
}

func minusAppended(data []string) []string {
	ret := make([]string, len(data))
	copy(ret, data)
	ret[0] += "--"
	return ret
}

func minusSubdomains(data []string) []string {
	return append([]string{"--", "--"}, data...)
}

func minusSubdomain(data []string) []string {
	return append([]string{"--"}, data...)
}

func nop(data []string) []string {
	return data
}

func getMiddle(zone, start, end string) []string {
	splitStart := dns.SplitDomainName(start)
	if splitStart == nil {
		panic(fmt.Sprintf("start splits to nil: %s", start))
	}

	if Compare(end, zone) == 0 {
		end = ""
	}

	var ret []string

	if end != "" {
		splitEnd := dns.SplitDomainName(end)
		if splitEnd == nil {
			panic(fmt.Sprintf("end splits to nil: %s", end))
		}

		for _, f := range []middleFunc{decrementLabel} {
			res := strings.Join(f(splitEnd), ".") + "."
			if dns.IsSubDomain(zone, res) {
				ret = append(ret, res)
			}
		}
	}

	for _, f := range []middleFunc{nop, minusAppended, minusSubdomains, minusSubdomain, incrementLabel} {
		res := strings.Join(f(splitStart), ".") + "."
		if dns.IsSubDomain(zone, res) && Compare(start, res) <= 0 && (end == "" || Compare(res, end) == -1) {
			ret = append(ret, res)
		}
	}

	return ret
}

// TODO get Compare into miekg/dns

// Compare compares domains according to the canonical ordering specified in RFC4034
// returns an integer value similar to strcmp
// (0 for equal values, -1 if s1 < s2, 1 if s1 > s2)
func Compare(s1, s2 string) int {
	s1b := []byte(s1)
	s2b := []byte(s2)

	doDDD(s1b)
	doDDD(s2b)

	s1lend := len(s1)
	s2lend := len(s2)

	for i := 0; ; i++ {
		s1lstart, end1 := PrevLabel(s1, i)
		s2lstart, end2 := PrevLabel(s2, i)

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

func labelCompare(a, b string) int {
	la := len(a)
	lb := len(b)
	minLen := la
	if lb < la {
		minLen = lb
	}
	for i := 0; i < minLen; i++ {
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

func doDDD(b []byte) {
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
}

// PrevLabel returns the index of the label when starting from the right and
// jumping n labels to the left.
// The bool start is true when the start of the string has been overshot.
// Also see NextLabel.
func PrevLabel(s string, n int) (i int, start bool) {
	if s == "" {
		return 0, true
	}
	if n == 0 {
		return len(s), false
	}

	l := len(s) - 1
	if s[l] == '.' {
		l--
	}

	for ; l >= 0 && n > 0; l-- {
		if s[l] != '.' {
			continue
		}
		j := l - 1
		for j >= 0 && s[j] == '\\' {
			j--
		}

		if (j-l)%2 == 0 {
			continue
		}

		n--
		if n == 0 {
			return l + 1, false
		}
	}

	return 0, n > 1
}

func dddToByte(s []byte) byte {
	_ = s[2] // bounds check hint to compiler; see golang.org/issue/14808
	return byte((s[0]-'0')*100 + (s[1]-'0')*10 + (s[2] - '0'))
}

func isDigit(b byte) bool { return b <= '9' && b >= '0' }
