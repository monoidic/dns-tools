package main

import (
	"database/sql"
	"fmt"
	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
	"math/rand"
	"sync"
)

type childParent struct {
	child      string
	childID    int64
	parentZone string
	success    bool
}

type regStatus struct {
	zone       string
	id         int64
	registered bool
}

func parentMapper(nsChan chan fieldData, outChan chan childParent, wg *sync.WaitGroup, once *sync.Once) {
	for nsd := range nsChan {
		child := nsd.name
		var dotless string
		success := true

		if child[len(child)-1] == '.' {
			dotless = child[:len(child)-1]
		} else {
			dotless = child
		}

		parent, err := publicsuffix.EffectiveTLDPlusOne(dotless)

		if err == nil {
			parent += "."
		} else {
			fmt.Printf("name %s (%s): %s\n", dotless, child, err)
			success = false
		}

		outChan <- childParent{child: child, childID: nsd.id, parentZone: parent, success: success}
	}

	wg.Done()
	wg.Wait()
	once.Do(func() { close(outChan) })
}

func childParentMap(db *sql.DB, nsChan chan fieldData, wg *sync.WaitGroup) {
	tablesFields := map[string]string{
		"name": "name",
	}
	namesStmts := map[string]string{
		"insert":     "INSERT OR IGNORE INTO zone_parent (child_id, parent_id) VALUES (?, ?)",
		"nameToZone": "UPDATE name SET is_zone=TRUE WHERE id=?",
		"setMapped":  "UPDATE name SET parent_mapped=TRUE WHERE id=?",
	}

	netWriter(db, nsChan, wg, tablesFields, namesStmts, parentMapper, parentWrite)
}

func parentWrite(tableMap TableMap, stmtMap StmtMap, nsp childParent) {
	var err error
	if nsp.success {
		parentID := tableMap["name"].get(nsp.parentZone)

		_, err = stmtMap["nameToZone"].stmt.Exec(parentID)
		check(err)

		if parentID != nsp.childID {
			_, err = stmtMap["insert"].stmt.Exec(nsp.childID, parentID)
			check(err)
		}
	}

	_, err = stmtMap["setMapped"].stmt.Exec(nsp.childID)
	check(err)

	// fmt.Printf("name %s has parent zone %s\n", nsp.name, nsp.parentZone)
}

func regMapper(zoneChan chan fieldData, outChan chan regStatus, wg *sync.WaitGroup, once *sync.Once) {
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
			//fmt.Printf("regMapper: %s\n", err)
			continue
		}

		switch res.Rcode {
		case dns.RcodeSuccess:
			registered = true
			break loop
		case dns.RcodeNameError: // nxdomain
			registered = false
			break loop
		case dns.RcodeServerFailure:
			break // ignore
		default:
			fmt.Printf("regMapper 2: rcode %d\n", res.Rcode)
		}
	}

	return regStatus{zone: zone, id: zd.id, registered: registered}

}

func detectUnregisteredDomains(db *sql.DB, zoneChan chan fieldData, wg *sync.WaitGroup) {
	tablesFields := map[string]string{}
	namesStmts := map[string]string{
		"update": "UPDATE name SET reg_checked=TRUE, registered=? WHERE id=?",
	}

	netWriter(db, zoneChan, wg, tablesFields, namesStmts, regMapper, unregisteredWrite)
}

func unregisteredWrite(tableMap TableMap, stmtMap StmtMap, reg regStatus) {
	_, err := stmtMap["update"].stmt.Exec(reg.registered, reg.id)
	check(err)
}

func getAddressDomain(db *sql.DB) {
	readerWriter("mapping names to effective domains", db, getParentCheck, childParentMap)
}

func getUnregisteredParentDomains(db *sql.DB) {
	readerWriter("finding unregistered NS address domains", db, getParentZones, detectUnregisteredDomains)
}
