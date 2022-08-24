package main

import (
	"database/sql"
	"fmt"
	"math/rand"
	"net/netip"
	"regexp"
	"strings"
	"sync"

	"github.com/monoidic/dns"
)

type arpaResults struct {
	rootID  int64
	results []arpaResult
}
type arpaResult struct {
	nxdomain bool
	name     string
	NSes     []dns.NS
}

var ptrV6Pattern = regexp.MustCompile("....")

func arpaWriter(translator func(inChan <-chan fieldData, outChan chan<- arpaResults)) writerF[fieldData] {
	return func(db *sql.DB, fdChan <-chan fieldData, wg *sync.WaitGroup) {
		tablesFields := map[string]string{
			"name":     "name",
			"rr_type":  "name",
			"rr_name":  "name",
			"rr_value": "value",
		}
		namesStmts := map[string]string{
			"delete_root": "DELETE FROM unwalked_root WHERE id=?",
			"add_root":    "INSERT INTO unwalked_root (name, ent) VALUES (?, ?)",
			"zone2rr":     "INSERT OR IGNORE INTO zone2rr (zone_id, rr_type_id, rr_name_id, rr_value_id) VALUES (?, ?, ?, ?)",
		}

		resChan := make(chan arpaResults, MIDBUFLEN)
		go translator(fdChan, resChan)

		netWriter(db, resChan, wg, tablesFields, namesStmts, arpaWorker, arpaWrite)
	}
}

func arpaV4Translate(inChan <-chan fieldData, outChan chan<- arpaResults) {
	for fd := range inChan {
		res := arpaResults{rootID: fd.id, results: make([]arpaResult, 256)}
		for i := 0; i < 256; i++ {
			res.results[i] = arpaResult{name: fmt.Sprintf("%d.%s", i, fd.name)}
		}
		outChan <- res
	}
	close(outChan)
}

func arpaV6Translate(inChan <-chan fieldData, outChan chan<- arpaResults) {
	for fd := range inChan {
		res := arpaResults{rootID: fd.id, results: make([]arpaResult, 16)}
		for i, c := range "0123456789abcdef" {
			res.results[i] = arpaResult{name: fmt.Sprintf("%c.%s", c, fd.name)}
		}
		outChan <- res
	}
	close(outChan)
}

func arpaWorker(inChan <-chan arpaResults, outChan chan<- arpaResults, wg *sync.WaitGroup, once *sync.Once) {
	msg := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Opcode:           dns.OpcodeQuery,
			RecursionDesired: true,
			Rcode:            dns.RcodeSuccess,
		},
		Question: []dns.Question{{
			Qclass: dns.ClassINET,
			Qtype:  dns.TypeNS,
		}},
	}
	msgSetSize(&msg)

	resolverWorker(inChan, outChan, msg, arpaResolve, wg, once)
}

func arpaResolve(connCache connCache, msg dns.Msg, results arpaResults) arpaResults {
	for resI, result := range results.results {
		msg.Question[0].Name = result.name
		var err error
		var response *dns.Msg

		for i := 0; i < RETRIES; i++ {
			nameserver := usedNs[rand.Intn(usedNsLen)]
			if response, err = plainResolve(msg, connCache, nameserver); err == nil {
				break
			}
		}

		if response != nil {
			for _, rr := range response.Answer {
				switch rrT := rr.(type) {
				case *dns.NS:
					normalizeRR(rrT)
					result.NSes = append(result.NSes, *rrT)
				}
			}
		}

		result.nxdomain = response.Rcode != dns.RcodeSuccess
		fmt.Printf("rcode for %s: %s\n", result.name, dns.RcodeToString[response.Rcode])
		results.results[resI] = result
	}
	return results
}

func arpaWrite(tableMap TableMap, stmtMap StmtMap, datum arpaResults) {
	stmtMap.exec("delete_root", datum.rootID)

	for _, result := range datum.results {
		if !result.nxdomain {
			fmt.Printf("new root %s\n", result.name)
			ent := len(result.NSes) == 0
			stmtMap.exec("add_root", result.name, ent)

			if !ent {
				rrTypeID := tableMap.get("rr_type", "NS")
				for _, ns := range result.NSes {
					rrNameID := tableMap.get("rr_name", ns.Hdr.Name)
					zoneID := tableMap.get("name", ns.Hdr.Name)
					rrValueID := tableMap.get("rr_value", ns.String())

					stmtMap.exec("zone2rr", zoneID, rrTypeID, rrNameID, rrValueID)
				}
			}
		}
	}
}

func ptrToIP(s string) netip.Addr {
	if strings.HasSuffix(s, ".ip6.arpa.") {
		s = s[:len(s)-len(".ip6.arpa.")]
		s = strings.ReplaceAll(s, ".", "")
		s = reverseASCII(s)
		s = strings.Join(ptrV6Pattern.FindAllString(s, -1), ":")
	} else if strings.HasSuffix(s, ".in-addr.arpa.") {
		s = s[:len(s)-len(".in-addr.arpa.")]
		s = reverseASCII(s)
	} else {
		panic(fmt.Sprintf("invalid addr: %q", s))
	}
	return netip.MustParseAddr(s)
}

func reverseASCII(s string) string {
	b := []byte(s)
	l := len(b)
	for i := 0; i < l/2; i++ {
		b[i], b[l-i-1] = b[l-i-1], b[i]
	}
	return string(b)
}

func setupArpa(db *sql.DB, root string) {
	tx := check1(db.Begin())
	check1(tx.Exec(`DELETE FROM unwalked_root`))
	check1(tx.Exec(fmt.Sprintf(`INSERT INTO unwalked_root (name) VALUES ('%s')`, root)))
	check(tx.Commit())
}

func recurseArpaV4(db *sql.DB) {
	setupArpa(db, "in-addr.arpa.")
	readerWriterRecurse("recursing through in-addr.arpa.", db, getUnqueriedArpaRoots, arpaWriter(arpaV4Translate))
}

func recurseArpaV6(db *sql.DB) {
	setupArpa(db, "ip6.arpa.")
	readerWriterRecurse("recursing through ip6.arpa.", db, getUnqueriedArpaRoots, arpaWriter(arpaV6Translate))
}
