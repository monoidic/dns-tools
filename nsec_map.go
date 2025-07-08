package main

import (
	"database/sql"
	"fmt"
	"iter"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

type nsecMapResults struct {
	zoneID    int64
	success   bool
	nsecState string
	rname     string
	mname     string
	nsecS     string
	optout    bool
}

const (
	hasNsec uint = 1 << iota
	hasNsec3
)

func shortZone(rrT *dns.NSEC3) bool {
	start, end := nsec3RRToHashes(rrT)
	return start == end
}

func getNsecState(nsecSigs []*dns.NSEC, nsec3Sigs []*dns.NSEC3) (string, string, bool) {
	var nsecT uint
	var nsecS string

	if len(nsecSigs) > 0 {
		nsecT |= hasNsec
	}

	if len(nsec3Sigs) > 0 {
		nsecT |= hasNsec3
	}

	var nsecSArr []string

	switch nsecT {
	case 0: // no nsec
		return "", "", false
	case hasNsec: // regular nsec
		nsecType := "plain_nsec"
		for _, rr := range nsecSigs {
			for _, s := range []string{rr.Hdr.Name, rr.NextDomain} {
				decoded := []byte(s)
				decoded = doDDD(decoded)
				switch decoded[0] {
				case '\x00', '!', '~':
					nsecType = "secure_nsec"
				}
			}
			nsecSArr = append(nsecSArr, rr.Hdr.Name+"^"+rr.NextDomain)
		}
		nsecS = strings.Join(nsecSArr, "|")
		return nsecType, nsecS, false

	case hasNsec3:
		nsecType := "nsec3"
		shortZone := len(nsec3Sigs) == 1 && shortZone(nsec3Sigs[0])
		var optOut bool
		for _, rrT := range nsec3Sigs {
			start, end := nsec3RRToHashes(rrT)
			if !shortZone && labelDiffSmall(start, end) {
				nsecType = "secure_nsec3"
			}
			nsecSArr = append(nsecSArr, fmt.Sprintf("%s^%s", start, end))
			if rrT.Flags&1 == 1 {
				optOut = true
			}
		}
		nsecS = strings.Join(nsecSArr, "|")
		return nsecType, nsecS, optOut

	default: // both nsec and nsec3?
		var prefix []string
		var suffix []string

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
				start, end := nsec3RRToHashes(rr)
				builder = append(builder, fmt.Sprintf("%s^%s", start, end))
			}
			suffix = append(suffix, strings.Join(builder, "|"))
		}

		nsecSArr = append(append(nsecSArr, strings.Join(prefix, ",")), suffix...)

		nsecS = strings.Join(nsecSArr, "&")

		return "nsec_confusion", nsecS, false
	}
}

func checkNsecWorker(dataChan <-chan retryWrap[fieldData, empty], refeedChan chan<- retryWrap[fieldData, empty], outChan chan<- nsecMapResults, wg, retryWg *sync.WaitGroup) {
	msg := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Opcode:           dns.OpcodeQuery,
			RecursionDesired: true,
			Rcode:            dns.RcodeSuccess,
		},
		Question: []dns.Question{{
			Qclass: dns.ClassINET,
			Qtype:  dns.TypeCNAME,
		}},
	}
	msgSetSize(&msg)
	setOpt(&msg).SetDo()

	resolverWorker(dataChan, refeedChan, outChan, &msg, checkNsecQuery, wg, retryWg)
}

func zoneRandomName(zone string) string {
	var ret string
	label := string(randomLabel()[1:])
	if zone == "." {
		zone = ""
	}
	ret = label + "." + zone

	return ret
}

func checkNsecQuery(connCache *connCache, msg *dns.Msg, fd *retryWrap[fieldData, empty]) (nmr nsecMapResults, err error) {
	var nsecState, rname, mname, nsecS string
	var optOut bool
	var res *dns.Msg

	nmr.zoneID = fd.val.id

	msg.Question[0].Name = zoneRandomName(fd.val.name)

	res, err = plainResolveRandom(msg, connCache)
	if err != nil {
		return
	}

	var nsecSigs []*dns.NSEC
	var nsec3Sigs []*dns.NSEC3

	for _, rr := range res.Ns { // authority section
		switch rrT := rr.(type) {
		case *dns.NSEC:
			nsecSigs = append(nsecSigs, rrT)
		case *dns.NSEC3:
			nsec3Sigs = append(nsec3Sigs, rrT)
		}
	}

	nsecState, nsecS, optOut = getNsecState(nsecSigs, nsec3Sigs)

	if nsecState == "" { // no nsec/nsec3/nsec3param
		// fmt.Printf("continue 2: no nsec info for %s\n", fd.name)
		return
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
		msg.Extra = nil

		res, err = plainResolveRandom(msg, connCache)
		if err != nil {
			return
		}
		// fmt.Printf("checkNsecQuery err 2: nameserver %s, name %s, err no. %d: %v\n", nameserver, fd.name, i, err)

		msg.Question[0].Qtype = dns.TypeNSEC3PARAM
		msg.Extra = dnssecL

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

		if !soaFound { // unable to find SOA, skip
			// fmt.Printf("continue 3: unable to get SOA for %s\n", fd.name)
			return
		}
	}

	nmr = nsecMapResults{
		zoneID:    fd.val.id,
		success:   true,
		nsecState: nsecState,
		rname:     rname,
		mname:     mname,
		nsecS:     nsecS,
		optout:    optOut,
	}
	return
}

func checkNsecMaster(db *sql.DB, seq iter.Seq[fieldData]) {
	tablesFields := map[string]string{
		"nsec_state": "name",
		"rname":      "name",
		"mname":      "name",
	}
	namesStmts := map[string]string{
		"insert": "INSERT INTO zone_nsec_state (zone_id, nsec_state_id, rname_id, mname_id, nsec, opt_out) VALUES (?, ?, ?, ?, ?, ?)",
		"update": "UPDATE name SET nsec_mapped=TRUE WHERE id=?",
	}

	netWriter(db, seq, tablesFields, namesStmts, checkNsecWorker, checkNsecInsert)
}

func checkNsecInsert(tableMap TableMap, stmtMap StmtMap, nmr nsecMapResults) {
	zoneID := nmr.zoneID

	defer stmtMap.exec("update", zoneID)

	if !nmr.success { // fetch failure
		return
	}

	nsecStateID := tableMap.roGet("nsec_state", nmr.nsecState)
	rnameID := tableMap.get("rname", nmr.rname)
	mnameID := tableMap.get("mname", nmr.mname)

	stmtMap.exec("insert", zoneID, nsecStateID, rnameID, mnameID, nmr.nsecS, nmr.optout)
}

func checkNsec(db *sql.DB) {
	readerWriter("checking NSEC security levels", db, netZoneReader(db, "AND zone.nsec_mapped=FALSE"), checkNsecMaster)
}
