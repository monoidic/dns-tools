package main

import (
	"bufio"
	"database/sql"
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
	fieldData // child zone
	eTLDplus1 string
	status    tldStatus
}

type zoneMaybe struct {
	fieldData
	isZone   bool
	servfail bool
	nxdomain bool
}

func validMapper(zoneChan <-chan fieldData, outChan chan<- zoneValid, wg *sync.WaitGroup) {
	for zd := range zoneChan {
		if zd.name == "." {
			outChan <- zoneValid{fieldData: zd, status: icannTLD, eTLDplus1: "."}
			continue
		}

		dotless := zd.name[:len(zd.name)-1]
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

		outChan <- zoneValid{fieldData: zd, status: status, eTLDplus1: dns.Fqdn(eTLDplus1)}
	}

	wg.Done()
}

func validWriter(db *sql.DB, zoneChan <-chan fieldData) {
	tablesFields := map[string]string{
		"name": "name",
	}
	namesStmts := map[string]string{
		"validation": "UPDATE name SET valid=?, valid_tried=TRUE WHERE id=?",
		"etldp1":     "UPDATE name SET etldp1_id=? WHERE id=?",
		"maybe_zone": "UPDATE name SET maybe_zone=TRUE WHERE id=? AND maybe_checked=FALSE AND is_zone=FALSE AND registered=TRUE AND valid=TRUE",
	}

	netWriter(db, zoneChan, tablesFields, namesStmts, validMapper, validInsert)
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

func getTLDs(_ *sql.DB, tldChan chan<- string) {
	fp := check1(os.Open("misc/tld.txt"))

	scanner := bufio.NewScanner(fp)

	for scanner.Scan() {
		s := dns.Fqdn(strings.ToLower(scanner.Text()))

		switch s[0] {
		case '*':
			s = s[2:]
		case '!':
			s = s[1:]
		}

		tldChan <- s
	}

	check(fp.Close())
	close(tldChan)
}

func tldListWriter(db *sql.DB, tldChan <-chan string) {
	tablesFields := map[string]string{
		"name": "name",
	}
	namesStmts := map[string]string{
		"maybe_zone": "UPDATE name SET maybe_zone=TRUE WHERE id=? AND maybe_checked=FALSE AND is_zone=FALSE AND registered=TRUE AND valid=TRUE",
	}

	insertRR(db, tldChan, tablesFields, namesStmts, tldListInsert)
}

func tldListInsert(tableMap TableMap, stmtMap StmtMap, tld string) {
	tldID := tableMap.get("name", tld)
	stmtMap.exec("maybe_zone", tldID)
}

func maybeZoneWriter(db *sql.DB, fdChan <-chan fieldData) {
	tablesFields := map[string]string{
		"name": "name",
	}
	namesStmts := map[string]string{
		"zone_status": "UPDATE name SET maybe_zone=FALSE, reg_checked=TRUE, is_zone=?, registered=? WHERE id=?",
		"servfail":    "UPDATE name SET maybe_zone=FALSE WHERE id=?",
	}

	netWriter(db, fdChan, tablesFields, namesStmts, maybeMapper, maybeInsert)
}

func maybeMapper(fdChan <-chan fieldData, outChan chan<- zoneMaybe, wg *sync.WaitGroup) {
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

	resolverWorker(fdChan, outChan, msg, maybeZoneResolve, wg)
}

func maybeZoneResolve(connCache connCache, msg dns.Msg, fd fieldData) (zm zoneMaybe) {
	zm.fieldData = fd
	msg.Question[0].Name = dns.Fqdn(fd.name)
	var response *dns.Msg
	var err error

	for i := 0; i < RETRIES; i++ {
		nameserver := randomNS()
		if response, err = plainResolve(msg, connCache, nameserver); err == nil {
			break
		}
	}

	if response == nil || response.MsgHdr.Rcode == dns.RcodeServerFailure {
		zm.servfail = true
		return zm
	}

	if response.MsgHdr.Rcode == dns.RcodeNameError { // nxdomain
		zm.nxdomain = true
		return zm
	}

maybeZoneResolveL:
	for _, rr := range response.Answer {
		switch rr.(type) {
		case *dns.SOA:
			zm.isZone = true
			break maybeZoneResolveL
		}
	}

	return zm
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
	readerWriter("validating zones", db, getValidUncheckedNames, validWriter)
}

func maybeZone(db *sql.DB) {
	readerWriter("resolving maybe-zones", db, getMaybeZones, maybeZoneWriter)
}
