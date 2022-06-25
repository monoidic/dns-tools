package main

import (
	"bufio"
	"database/sql"
	"os"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

type tldStatus uint8

const (
	icannTLD tldStatus = iota
	privateTLD
	invalidTLD
	selfTLD
)

type zoneValid struct {
	fieldData // child zone
	status    tldStatus
}

func validMapper(zoneChan chan fieldData, outChan chan zoneValid, wg *sync.WaitGroup, once *sync.Once) {
	for zd := range zoneChan {
		if zd.name == "." {
			outChan <- zoneValid{fieldData: zd, status: icannTLD}
			continue
		}

		dotless := zd.name[:len(zd.name)-1]
		eTLD, icann := publicsuffix.PublicSuffix(dotless)
		var status tldStatus
		if icann {
			status = icannTLD // ICANN TLD
		} else if strings.IndexByte(eTLD, '.') >= 0 {
			status = privateTLD // private TLD
		} else {
			status = invalidTLD // invalid
		}

		if status != invalidTLD && dotless == eTLD {
			status = selfTLD
		}

		outChan <- zoneValid{fieldData: zd, status: status}
	}

	wg.Done()
	wg.Wait()
	once.Do(func() { close(outChan) })
}

func validWriter(db *sql.DB, zoneChan chan fieldData, wg *sync.WaitGroup) {
	tablesFields := map[string]string{
		"name": "name",
	}
	namesStmts := map[string]string{
		"validation": "UPDATE name SET valid=?, valid_tried=TRUE WHERE id=?",
	}

	netWriter(db, zoneChan, wg, tablesFields, namesStmts, validMapper, validInsert)
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
		"to_zone": "UPDATE name SET is_zone=TRUE WHERE id=?",
	}

	insertRR(db, tldChan, wg, tablesFields, namesStmts, tldListInsert)
}

func tldListInsert(tableMap TableMap, stmtMap StmtMap, tld string) {
	tldID := tableMap.get("name", tld)
	stmtMap.exec("to_zone", tldID)
}

func insertPSL(db *sql.DB) {
	readerWriter("inserting TLDs from PSL", db, getTLDs, tldListWriter)
}

func validateZones(db *sql.DB) {
	readerWriter("validating zones", db, getValidUncheckedNames, validWriter)
}
