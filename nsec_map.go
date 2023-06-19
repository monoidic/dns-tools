package main

import (
	"database/sql"
	"strings"
	"sync"

	"github.com/monoidic/dns"
)

const (
	hasNsec3param uint = 1 << iota
	hasNsec
	hasNsec3
)

var rnameBlacklist Set[string] = makeSet([]string{
	// dns.cloudflare.com.",
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

// TODO try to check nsecS itself and/or improve blacklist
func checkBlacklisted(mname, rname string) bool {
	if rnameBlacklist.Contains(rname) {
		return true
	}

	for _, suffix := range mnameBlacklistSuffixes {
		if strings.HasSuffix(mname, suffix) {
			return true
		}
	}

	return false
}

func getNsecState(nsec3param string, nsecSigs []dns.NSEC, nsec3Sigs []dns.NSEC3) (string, string) {
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
			decoded = doDDD(decoded)
			switch decoded[0] {
			case '\x00', '!':
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
			builder := make([]string, 0, len(nsecSigs))
			for _, rr := range nsecSigs {
				builder = append(builder, rr.Hdr.Name+"^"+rr.NextDomain)
			}
			suffix = append(suffix, strings.Join(builder, "|"))
		}
		if nsecT&hasNsec3 > 0 {
			prefix = append(prefix, "nsec3")
			builder := make([]string, 0, len(nsec3Sigs))
			for _, rr := range nsec3Sigs {
				builder = append(builder, rr.String())
			}
			suffix = append(suffix, strings.Join(builder, "|"))
		}

		nsecSArr = append(append(nsecSArr, strings.Join(prefix, ",")), suffix...)

		nsecS = strings.Join(nsecSArr, "&")

		return "nsec_confusion", nsecS
	}
}

func checkNsecWorker(inChan <-chan fieldData, outChan chan<- fdResults, wg *sync.WaitGroup) {
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
	setOpt(&msg).SetDo()

	resolverWorker(inChan, outChan, msg, checkNsecQuery, wg)
}

func checkNsecQuery(connCache connCache, msg dns.Msg, fd fieldData) fdResults {
	var nsecState, rname, mname, nsec3param, nsecS string
	var err error
	var res *dns.Msg

	msg.Question[0].Name = fd.name

	for i := 0; i < RETRIES; i++ {
		nameserver := randomNS()
		res, err = plainResolve(msg, connCache, nameserver)
		if err == nil {
			break
		}
	}

	if !(err == nil && res.Rcode == dns.RcodeSuccess) {
		return fdResults{fieldData: fd} // empty
	}

nsec3paramLoop:
	for _, rr := range res.Answer {
		switch rrT := rr.(type) {
		case *dns.NSEC3PARAM:
			nsec3param = rrT.String()
			break nsec3paramLoop
		}
	}

	var nsecSigs []dns.NSEC
	var nsec3Sigs []dns.NSEC3

	for _, rr := range res.Ns { // authority section
		switch rrT := rr.(type) {
		case *dns.NSEC:
			nsecSigs = append(nsecSigs, *rrT)
		case *dns.NSEC3:
			nsec3Sigs = append(nsec3Sigs, *rrT)
		}
	}

	nsecState, nsecS = getNsecState(nsec3param, nsecSigs, nsec3Sigs)

	if nsecState == "" { // no nsec/nsec3/nsec3param
		// fmt.Printf("continue 2: no nsec info for %s\n", fd.name)
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
			nameserver := randomNS()
			res, err = plainResolve(msg, connCache, nameserver)
			if err == nil {
				break
			}
			// fmt.Printf("checkNsecQuery err 2: nameserver %s, name %s, err no. %d: %v\n", nameserver, fd.name, i, err)
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
			// fmt.Printf("continue 3: unable to get SOA for %s\n", fd.name)
			return fdResults{fieldData: fd}
		}
	}

	if nsecState == "plain_nsec" && checkBlacklisted(mname, rname) {
		nsecState = "secure_nsec"
	}

	return fdResults{fieldData: fd, results: []string{nsecState, rname, mname, nsecS}}
}

func checkNsecMaster(db *sql.DB, zoneChan <-chan fieldData) {
	tablesFields := map[string]string{
		"nsec_state": "name",
		"rname":      "name",
		"mname":      "name",
	}
	namesStmts := map[string]string{
		"insert": "INSERT INTO zone_nsec_state (zone_id, nsec_state_id, rname_id, mname_id, nsec) VALUES (?, ?, ?, ?, ?)",
		"update": "UPDATE name SET nsec_mapped=TRUE WHERE id=?",
	}

	netWriter(db, zoneChan, tablesFields, namesStmts, checkNsecWorker, checkNsecInsert)
}

func checkNsecInsert(tableMap TableMap, stmtMap StmtMap, fd fdResults) {
	zoneID := fd.id

	if len(fd.results) != 0 { // fetch failure
		nsecStateID := tableMap.roGet("nsec_state", fd.results[0])
		rnameID := tableMap.get("rname", fd.results[1])
		mnameID := tableMap.get("mname", fd.results[2])
		nsecS := fd.results[3]

		stmtMap.exec("insert", zoneID, nsecStateID, rnameID, mnameID, nsecS)
	}

	stmtMap.exec("update", zoneID)
}

func checkNsec(db *sql.DB) {
	readerWriter("checking NSEC security levels", db, netZoneReaderGen("AND zone.nsec_mapped=FALSE"), checkNsecMaster)
}
