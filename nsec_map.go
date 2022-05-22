package main

import (
	"database/sql"
	"fmt"
	"github.com/miekg/dns"
	"math/rand"
	"strings"
	"sync"
)

const (
	hasNsec3param uint = 1 << iota
	hasNsec
	hasNsec3
)

var rnameBlacklist map[string]bool = makeSet([]string{
	//dns.cloudflare.com.",
	// "awsdns-hostmaster.amazon.com.",
	// "hostmaster.nsone.net.",
	// "admin.dnsimple.com.",
	// "administrator.dynu.com.",
	// "hostmaster.hichina.com.",
	// "hostmaster.eurodns.com.",
	// "tech.brandshelter.com.",
	// "hostmaster.vismasoftware.no.",
	// "domainadm.visma.com.",
})

// TODO split string a.b.c.d.e into e, d.e and c.d.e (length depends on longest suffix) and check if they appear in a set of these values?
var mnameBlacklistSuffixes []string = []string{
	// "ultradns.com.",
}

func makeSet[valueType comparable](l []valueType) map[valueType]bool {
	ret := make(map[valueType]bool)
	for _, k := range l {
		ret[k] = true
	}
	return ret
}

// TODO try to check nsecS itself and/or improve blacklist
func checkBlacklisted(mname, rname string) bool {
	if rnameBlacklist[rname] {
		return true
	}

	for _, suffix := range []string{"ultradns.com."} {
		if strings.HasSuffix(mname, suffix) {
			return true
		}
	}

	return false
}

func getNsecState(nsec3param string, nsecSigs []dns.NSEC, nsec3Sigs []*dns.NSEC3) (string, string) {
	var nsecT uint
	var nsecS string

	if nsec3param != "" {
		nsecT |= hasNsec3param
	}

	if len(nsecSigs) > 0 {
		nsecT |= hasNsec
	}

	if len(nsec3Sigs) > 0 {
		nsecT |= hasNsec3
	}

	var nsecSArr []string

	switch nsecT {
	case 0: // no nsec
		return "", ""
	case hasNsec: // regular nsec
		nsecType := "plain_nsec"
		for _, rr := range nsecSigs {
			decoded := []byte(rr.NextDomain)
			doDDD(decoded)
			if decoded[0] == 0 { // simple NSEC white lie
				nsecType = "secure_nsec"
			}
			nsecSArr = append(nsecSArr, rr.Hdr.Name+"^"+rr.NextDomain)
		}
		nsecS = strings.Join(nsecSArr, "|")
		return nsecType, nsecS

	case hasNsec3param: // regular nsec3
		return "nsec3", nsec3param

	default: // nsec confusion, strange response
		var prefix []string
		var suffix []string

		if nsecT&hasNsec3param != 0 {
			prefix = append(prefix, "nsec3param")
			suffix = append(suffix, nsec3param)
		}
		if nsecT&hasNsec > 0 {
			prefix = append(prefix, "nsec")
			var builder []string
			for _, rr := range nsecSigs {
				builder = append(builder, rr.Hdr.Name+"^"+rr.NextDomain)
			}
			suffix = append(suffix, strings.Join(builder, "|"))
		}
		if nsecT&hasNsec3 > 0 {
			prefix = append(prefix, "nsec3")
			var builder []string
			for _, rr := range nsec3Sigs {
				s, ok := rrToString(rr)
				if !ok {
					panic(fmt.Sprintf("nsec3RR2: %#v", rr))
				}
				builder = append(builder, s)
			}
			suffix = append(suffix, strings.Join(builder, "|"))
		}

		nsecSArr = append(nsecSArr, strings.Join(prefix, ","))
		nsecSArr = append(nsecSArr, suffix...)

		nsecS = strings.Join(nsecSArr, "&")

		return "nsec_confusion", nsecS
	}
}

func checkNsecWorker(inChan chan fieldData, outChan chan fdResults, wg *sync.WaitGroup, once *sync.Once) {
	msg := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Opcode:           dns.OpcodeQuery,
			RecursionDesired: true,
			Rcode:            dns.RcodeSuccess,
		},
		Question: []dns.Question{{
			Qclass: dns.ClassINET,
			Qtype:  dns.TypeNSEC3PARAM,
		}},
	}
	msgSetSize(&msg)
	msg.Extra[0].(*dns.OPT).SetDo()

	resolverWorker(inChan, outChan, msg, checkNsecQuery, wg, once)
}

func checkNsecQuery(connCache connCache, msg dns.Msg, fd fieldData) fdResults {
	var nsecState, rname, mname, nsec3param, nsecS string
	var err error
	var res *dns.Msg

	msg.Question[0].Name = fd.name

	for i := 0; i < RETRIES; i++ {
		nameserver := usedNs[rand.Intn(usedNsLen)]
		res, err = plainResolve(msg, connCache, nameserver)
		if err == nil {
			break
		}
		//fmt.Printf("checkNsecQuery err 1: nameserver %s, name %s, err no. %d: %v\n", nameserver, fd.name, i, err)
	}

	if !(err == nil && res.Rcode == dns.RcodeSuccess) {
		return fdResults{fieldData: fd} // empty
		//rcode := 69
		//if res != nil {
		//	rcode = res.Rcode
		//}
		//fmt.Printf("continue 1: zone=%s err=%s rcode=%d\n", fd.name, err, rcode)
	}

nsec3paramLoop:
	for _, rr := range res.Answer {
		switch rrT := rr.(type) {
		case *dns.NSEC3PARAM:
			var ok bool
			nsec3param, ok = rrToString(rrT)
			if !ok {
				panic(fmt.Sprintf("nsec3paramLoop: %#v", rrT))
			}
			break nsec3paramLoop
		}
	}

	var nsecSigs []dns.NSEC
	var nsec3Sigs []*dns.NSEC3

	for _, rr := range res.Ns { // authority section
		switch rrT := rr.(type) {
		case *dns.NSEC:
			nsecSigs = append(nsecSigs, *rrT)
		case *dns.NSEC3:
			nsec3Sigs = append(nsec3Sigs, rrT)
		}
	}

	nsecState, nsecS = getNsecState(nsec3param, nsecSigs, nsec3Sigs)

	if nsecState == "" { // no nsec/nsec3/nsec3param
		//fmt.Printf("continue 2: no nsec info for %s\n", fd.name)
		return fdResults{fieldData: fd}
	}

	var soaFound bool
soaLoop:
	for _, rr := range res.Ns { // authority section
		switch rrT := rr.(type) {
		case *dns.SOA:
			mname = rrT.Ns
			rname = rrT.Mbox
			soaFound = true
			break soaLoop
		}
	}

	if !soaFound {
		msg.Question[0].Qtype = dns.TypeSOA
		dnssecL := msg.Extra
		msg.Extra = []dns.RR{}

		for i := 0; i < RETRIES; i++ {
			nameserver := usedNs[rand.Intn(usedNsLen)]
			res, err = plainResolve(msg, connCache, nameserver)
			if err == nil {
				break
			}
			//fmt.Printf("checkNsecQuery err 2: nameserver %s, name %s, err no. %d: %v\n", nameserver, fd.name, i, err)
		}

		msg.Question[0].Qtype = dns.TypeNSEC3PARAM
		msg.Extra = dnssecL

		if err == nil {
		soaLoop2:
			for _, rr := range res.Answer {
				switch rrT := rr.(type) {
				case *dns.SOA:
					mname = rrT.Ns
					rname = rrT.Mbox
					soaFound = true
					break soaLoop2
				}
			}
		}

		if !soaFound { // unable to find SOA, skip
			//fmt.Printf("continue 3: unable to get SOA for %s\n", fd.name)
			return fdResults{fieldData: fd}
		}
	}

	if nsecState == "plain_nsec" && checkBlacklisted(mname, rname) {
		nsecState = "secure_nsec"
	}

	return fdResults{fieldData: fd, results: []string{nsecState, rname, mname, nsecS}}
}

func checkNsecMaster(db *sql.DB, zoneChan chan fieldData, wg *sync.WaitGroup) {
	tablesFields := map[string]string{
		"nsec_state": "name",
		"rname":      "name",
		"mname":      "name",
	}
	namesStmts := map[string]string{
		"insert": "INSERT INTO zone_nsec_state (zone_id, nsec_state_id, rname_id, mname_id, nsec) VALUES (?, ?, ?, ?, ?)",
		"update": "UPDATE name SET nsec_mapped=TRUE WHERE id=?",
	}

	netWriter(db, zoneChan, wg, tablesFields, namesStmts, checkNsecWorker, checkNsecInsert)
}

func checkNsecInsert(tableMap TableMap, stmtMap StmtMap, fd fdResults) {
	var err error
	zoneID := fd.id

	if len(fd.results) != 0 { // fetch failure
		nsecStateID := tableMap["nsec_state"].get(fd.results[0])
		rnameID := tableMap["rname"].get(fd.results[1])
		mnameID := tableMap["mname"].get(fd.results[2])
		nsecS := fd.results[3]

		_, err = stmtMap["insert"].stmt.Exec(zoneID, nsecStateID, rnameID, mnameID, nsecS)
		check(err)
	}

	_, err = stmtMap["update"].stmt.Exec(zoneID)
	check(err)
}

func checkNsec(db *sql.DB) {
	fmt.Println("checking NSEC security levels")

	zoneChan := make(chan fieldData, BUFLEN)
	var wg sync.WaitGroup
	go netZoneReader(db, zoneChan, &wg, "AND zone.nsec_mapped=FALSE")
	checkNsecMaster(db, zoneChan, &wg)
}
