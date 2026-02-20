package main

import (
	"bufio"
	"database/sql"
	"iter"
	"os"
	"strings"
	"sync"

	"github.com/monoidic/dns"
	"golang.org/x/net/publicsuffix"
)

type tldStatus uint8

const (
	icannTLD tldStatus = iota + 1
	privateTLD
	invalidTLD
	selfTLD
)

type zoneValid struct {
	nameData  // child zone
	eTLDplus1 string
	status    tldStatus
}

type zoneMaybe struct {
	nameData
	isZone   bool
	servfail bool
	nxdomain bool
}

func validMapper(zoneChan <-chan retryWrap[nameData, empty], refeedChan chan<- retryWrap[nameData, empty], outChan chan<- zoneValid, retryWg *sync.WaitGroup) {
	for zdw := range zoneChan {
		zd := zdw.val
		if zd.name.String() == "." {
			outChan <- zoneValid{nameData: zd, status: icannTLD, eTLDplus1: "."}
			retryWg.Done()
			continue
		}

		dotless := zd.name.String()
		dotless = dotless[:len(dotless)-1]
		eTLD, icann := publicsuffix.PublicSuffix(dotless)
		var status tldStatus
		eTLDplus1 := "."
		if icann {
			status = icannTLD // ICANN TLD
		} else if strings.IndexByte(eTLD, '.') >= 0 {
			status = privateTLD // private TLD
		} else {
			status = invalidTLD // invalid
		}

		if status != invalidTLD {
			if dotless == eTLD {
				eTLDplus1 = eTLD
				status = selfTLD
			} else {
				var err error
				eTLDplus1, err = publicsuffix.EffectiveTLDPlusOne(dotless)
				if err != nil {
					status = invalidTLD
					eTLDplus1 = "."
				}
			}
		}

		outChan <- zoneValid{nameData: zd, status: status, eTLDplus1: dns.Fqdn(eTLDplus1)}
		retryWg.Done()
	}
}

func validWriter(db *sql.DB, seq iter.Seq[nameData]) {
	tablesFields := map[string]string{
		"name": "name",
	}
	namesStmts := map[string]string{
		"validation": "UPDATE name SET valid=?, valid_tried=TRUE WHERE id=?",
		"etldp1":     "UPDATE name SET etldp1_id=? WHERE id=?",
		"maybe_zone": "UPDATE name SET maybe_zone=TRUE WHERE id=? AND maybe_checked=FALSE AND is_zone=FALSE AND registered=TRUE AND valid=TRUE",
	}

	netWriter(db, seq, tablesFields, namesStmts, validMapper, validInsert)
}

func validInsert(tableMap TableMap, stmtMap StmtMap, zv zoneValid) {
	var valid bool
	switch zv.status {
	case invalidTLD:
		// valid = false
	// case icannTLD, privateTLD, selfTLD:
	default:
		valid = true
	}
	stmtMap.exec("validation", valid, zv.id)
	etldp1ID := tableMap.get("name", zv.eTLDplus1)
	stmtMap.exec("etldp1", etldp1ID, zv.id)
	stmtMap.exec("maybe_zone", etldp1ID)
}

func getTLDs(yield func(dns.Name) bool) {
	fp := check1(os.Open("misc/tld.txt"))
	defer fp.Close()

	scanner := bufio.NewScanner(fp)

	for scanner.Scan() {
		s := dns.Fqdn(strings.ToLower(scanner.Text()))

		if len(s) == 0 || strings.HasPrefix(s, "//") {
			continue
		}

		switch s[0] {
		case '*':
			s = s[2:]
		case '!':
			s = s[1:]
		}

		if !yield(mustParseName(s)) {
			return
		}
	}
}

func tldListWriter(db *sql.DB, seq iter.Seq[dns.Name]) {
	tablesFields := map[string]string{
		"name": "name",
	}
	namesStmts := map[string]string{
		"maybe_zone": "UPDATE name SET maybe_zone=TRUE WHERE id=? AND maybe_checked=FALSE AND is_zone=FALSE AND registered=TRUE AND valid=TRUE",
	}

	insertRR(db, seq, tablesFields, namesStmts, tldListInsert)
}

func tldListInsert(tableMap TableMap, stmtMap StmtMap, tld dns.Name) {
	tldID := tableMap.get("name", tld.String())
	stmtMap.exec("maybe_zone", tldID)
}

func maybeZoneWriter(db *sql.DB, seq iter.Seq[nameData]) {
	tablesFields := map[string]string{
		"name": "name",
	}
	namesStmts := map[string]string{
		"zone_status": "UPDATE name SET maybe_zone=FALSE, reg_checked=TRUE, is_zone=?, registered=? WHERE id=?",
		"servfail":    "UPDATE name SET maybe_zone=FALSE WHERE id=?",
	}

	netWriter(db, seq, tablesFields, namesStmts, maybeMapper, maybeInsert)
}

func maybeMapper(fdChan <-chan retryWrap[nameData, empty], refeedChan chan<- retryWrap[nameData, empty], outChan chan<- zoneMaybe, retryWg *sync.WaitGroup) {
	msg := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Opcode:           dns.OpcodeQuery,
			RecursionDesired: true,
			Rcode:            dns.RcodeSuccess,
		},
		Question: []dns.Question{{
			Qclass: dns.ClassINET,
			Qtype:  dns.TypeSOA,
		}},
	}
	msgSetSize(&msg)

	resolverWorker(fdChan, refeedChan, outChan, &msg, maybeZoneResolve, retryWg)
}

func maybeZoneResolve(connCache *connCache, msg *dns.Msg, fd *retryWrap[nameData, empty]) (zm zoneMaybe, err error) {
	zm.nameData = fd.val
	msg.Question[0].Name = fd.val.name
	var response *dns.Msg

	response, err = plainResolveRandom(msg, connCache)
	if err != nil {
		return
	}

	if response == nil || response.MsgHdr.Rcode == dns.RcodeServerFailure {
		zm.servfail = true
		return
	}

	if response.MsgHdr.Rcode == dns.RcodeNameError { // nxdomain
		zm.nxdomain = true
		return
	}

maybeZoneResolveL:
	for _, rr := range response.Answer {
		switch rr.(type) {
		case *dns.SOA:
			zm.isZone = true
			break maybeZoneResolveL
		}
	}

	return
}

func maybeInsert(_ TableMap, stmtMap StmtMap, zm zoneMaybe) {
	if zm.servfail {
		stmtMap.exec("servfail", zm.id)
	} else {
		stmtMap.exec("zone_status", zm.isZone, !zm.nxdomain, zm.id)
	}
}

func insertPSL(db *sql.DB) {
	readerWriter("inserting TLDs from PSL", db, getTLDs, tldListWriter)
}

func validateZones(db *sql.DB) {
	readerWriter("validating zones", db, getDbNameData(`
	SELECT name, id
	FROM name AS zone
	WHERE valid_tried=FALSE
`, db), validWriter)
}

func maybeZone(db *sql.DB) {
	readerWriter("resolving maybe-zones", db, getDbNameData(`
	SELECT name.name, name.id
	FROM name
	WHERE name.maybe_zone=TRUE
`, db), maybeZoneWriter)
}
