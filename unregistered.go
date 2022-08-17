package main

import (
	"database/sql"
	"fmt"
	"math/rand"
	"sync"

	"github.com/monoidic/dns"
)

type regStatus struct {
	zone       string
	id         int64
	registered bool
}

func regMapper(zoneChan <-chan fieldData, outChan chan<- regStatus, wg *sync.WaitGroup, once *sync.Once) {
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

	resolverWorker(zoneChan, outChan, msg, regMap, wg, once)
}

func regMap(connCache connCache, msg dns.Msg, zd fieldData) regStatus {
	zone := zd.name
	msg.Question[0].Name = zone
	registered := true

loop:
	for i := 0; i < RETRIES; i++ {
		nameserver := usedNs[rand.Intn(usedNsLen)]
		res, err := plainResolve(msg, connCache, nameserver)
		if err != nil {
			// fmt.Printf("regMapper: %s\n", err)
			continue
		}

		switch res.Rcode {
		case dns.RcodeSuccess:
			registered = true
			break loop
		case dns.RcodeNameError: // nxdomain
			registered = false
			break loop
		case dns.RcodeServerFailure: // ignore
		default:
			fmt.Printf("regMapper 2: rcode %d\n", res.Rcode)
		}
	}

	return regStatus{zone: zone, id: zd.id, registered: registered}
}

func detectUnregisteredDomains(db *sql.DB, zoneChan <-chan fieldData, wg *sync.WaitGroup) {
	tablesFields := map[string]string{}
	namesStmts := map[string]string{
		"update": "UPDATE name SET reg_checked=TRUE, registered=? WHERE id=?",
	}

	netWriter(db, zoneChan, wg, tablesFields, namesStmts, regMapper, unregisteredWrite)
}

func unregisteredWrite(_ TableMap, stmtMap StmtMap, reg regStatus) {
	stmtMap.exec("update", reg.registered, reg.id)
}

func getUnregisteredDomains(db *sql.DB) {
	readerWriter("finding unregistered domains", db, getRegUncheckedZones, detectUnregisteredDomains)
	propagateUnreg(db)
}

func propagateUnreg(db *sql.DB) {
	tx := check1(db.Begin())

	var numChanges int64 = 1

	for numChanges != 0 {
		check1(tx.Exec(`
			UPDATE name
			SET registered=FALSE, reg_checked=TRUE
			FROM name_parent
			INNER JOIN name AS child ON name_parent.child_id=child.id
			INNER JOIN name AS parent ON name_parent.parent_id=parent.id
			WHERE parent.registered=FALSE
			AND child.registered=TRUE
			AND name.id=child.id
		`))

		rows := check1(tx.Query("SELECT changes()"))
		rows.Next()
		check(rows.Scan(&numChanges))
		check(rows.Close())
	}

	check(tx.Commit())
}
