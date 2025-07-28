package main

import (
	"database/sql"
	"fmt"
	"iter"
	"sync"

	"github.com/monoidic/dns"
)

type regStatus struct {
	zone       dns.Name
	id         int64
	registered bool
}

func regMapper(zoneChan <-chan retryWrap[nameData, empty], refeedChan chan<- retryWrap[nameData, empty], outChan chan<- regStatus, wg, retryWg *sync.WaitGroup) {
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

	resolverWorker(zoneChan, refeedChan, outChan, &msg, regMap, wg, retryWg)
}

var regMapErr = Error{s: "regmaperr"}

func regMap(connCache *connCache, msg *dns.Msg, zd *retryWrap[nameData, empty]) (rs regStatus, err error) {
	zone := zd.val.name
	msg.Question[0].Name = zone
	registered := true

	res, err := plainResolveRandom(msg, connCache)
	if err != nil {
		// fmt.Printf("regMapper: %s\n", err)
		return
	}

	switch res.Rcode {
	case dns.RcodeSuccess:
		registered = true
	case dns.RcodeNameError: // nxdomain
		registered = false
	case dns.RcodeServerFailure: // ignore
	default:
		fmt.Printf("regMapper 2: rcode %d\n", res.Rcode)
		err = regMapErr
		return
	}

	rs = regStatus{zone: zone, id: zd.val.id, registered: registered}
	return
}

func detectUnregisteredDomains(db *sql.DB, seq iter.Seq[nameData]) {
	tablesFields := map[string]string{}
	namesStmts := map[string]string{
		"update": "UPDATE name SET reg_checked=TRUE, registered=? WHERE id=?",
	}

	netWriter(db, seq, tablesFields, namesStmts, regMapper, unregisteredWrite)
}

func unregisteredWrite(_ TableMap, stmtMap StmtMap, reg regStatus) {
	stmtMap.exec("update", reg.registered, reg.id)
}

func getUnregisteredDomains(db *sql.DB) {
	readerWriter("finding unregistered domains", db, getDbNameData(`
	SELECT name, id
	FROM name
	WHERE reg_checked=FALSE
	AND is_zone=TRUE
	AND valid=TRUE
`, db), detectUnregisteredDomains)
}
