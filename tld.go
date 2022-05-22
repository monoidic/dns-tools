package main

import (
	"bufio"
	"database/sql"
	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
	"os"
	"strings"
	"sync"
)

type tldStatus uint8

const (
	icannTLD tldStatus = iota
	privateTLD
	invalidTLD
	selfTLD
)

type zoneTLD struct {
	fieldData // child zone
	eTLD      string
	status    tldStatus
}

func tldMapper(zoneChan chan fieldData, outChan chan zoneTLD, wg *sync.WaitGroup, once *sync.Once) {
	for zd := range zoneChan {
		dotless := zd.name[:len(zd.name)-1]
		eTLD, icann := publicsuffix.PublicSuffix(dotless)
		var status tldStatus
		if icann {
			status = icannTLD // ICANN TLD
		} else if strings.IndexByte(eTLD, '.') >= 0 {
			status = privateTLD // private TLD
		} else {
			status = invalidTLD // invalid; mark child as invalid too
		}

		if status != invalidTLD && dotless == eTLD {
			status = selfTLD
		}

		outChan <- zoneTLD{fieldData: zd, eTLD: eTLD + ".", status: status}
	}

	wg.Done()
	wg.Wait()
	once.Do(func() { close(outChan) })
}

func tldWriter(db *sql.DB, zoneChan chan fieldData, wg *sync.WaitGroup) {
	tablesFields := map[string]string{
		"name": "name",
	}
	namesStmts := map[string]string{
		"nameToTLD":     "UPDATE name SET is_tld=TRUE, is_zone=TRUE WHERE id=?",
		"tldMapped":     "UPDATE name SET tld_mapped=TRUE WHERE id=?",
		"addTLDMapping": "INSERT OR IGNORE INTO zone_tld (zone_id, tld_id) VALUES (?, ?)",
		"invalidZone":   "UPDATE name SET valid=FALSE, valid_tried=TRUE WHERE id=?",
		"validZone":     "UPDATE name SET valid=TRUE, valid_tried=TRUE WHERE id=?",
	}

	netWriter(db, zoneChan, wg, tablesFields, namesStmts, tldMapper, tldInsert)
}

func tldInsert(tableMap TableMap, stmtMap StmtMap, tldD zoneTLD) {
	var err error

	zoneID := tldD.id
	switch tldD.status {
	case invalidTLD:
		_, err = stmtMap["invalidZone"].stmt.Exec(zoneID)
		check(err)

	//case icannTLD, privateTLD, selfTLD:
	default:
		tldID := tableMap["name"].get(tldD.eTLD)

		_, err = stmtMap["nameToTLD"].stmt.Exec(tldID)
		check(err)

		_, err = stmtMap["validZone"].stmt.Exec(zoneID)
		check(err)

		if tldD.status != selfTLD {
			_, err = stmtMap["addTLDMapping"].stmt.Exec(zoneID, tldID)
			check(err)
		}
	}

	_, err = stmtMap["tldMapped"].stmt.Exec(zoneID)
	check(err)
}

func getTLDs(db *sql.DB, tldChan chan string, wg *sync.WaitGroup) {
	fp, err := os.Open("lists/tld.txt")
	check(err)

	scanner := bufio.NewScanner(fp)

	for scanner.Scan() {
		s := dns.Fqdn(strings.ToLower(scanner.Text()))

		switch s[0] {
		case '*':
			s = s[2:]
		case '!':
			s = s[1:]
		}

		wg.Add(1)
		tldChan <- s
	}

	check(fp.Close())
	wg.Wait()
	close(tldChan)
}

func tldListWriter(db *sql.DB, tldChan chan string, wg *sync.WaitGroup) {
	tablesFields := map[string]string{
		"name": "name",
	}
	namesStmts := map[string]string{
		"update": "UPDATE name SET is_tld=TRUE, is_zone=TRUE, valid=TRUE, valid_tried=TRUE, tld_mapped=TRUE WHERE id=?",
	}

	insertRR(db, tldChan, wg, tablesFields, namesStmts, tldListInsert)
}

func tldListInsert(tableMap TableMap, stmtMap StmtMap, tld string) {
	tldID := tableMap["name"].get(tld)
	_, err := stmtMap["update"].stmt.Exec(tldID)
	check(err)
}

func mapZoneTLDs(db *sql.DB) {
	readerWriter("Mapping zone TLDs", db, getTLDMapZones, tldWriter)
}

func insertPSL(db *sql.DB) {
	readerWriter("inserting TLDs from PSL", db, getTLDs, tldListWriter)
}
