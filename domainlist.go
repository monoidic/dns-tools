package main

import (
	"bufio"
	"database/sql"
	"github.com/miekg/dns"
	"io/fs"
	"os"
	"strings"
	"sync"
)

func readDomainLists(fileChan, domainChan chan string, wg *sync.WaitGroup) {
	for filename := range fileChan {
		fp, err := os.Open(filename)
		check(err)

		scanner := bufio.NewScanner(fp)

		for scanner.Scan() {
			s := dns.Fqdn(strings.ToLower(scanner.Text()))
			domainChan <- s
		}

		check(fp.Close())

		wg.Done()
	}
}

func insertDomainWorker(db *sql.DB, domainChan chan string, wg *sync.WaitGroup) {
	tablesFields := map[string]string{
		"name": "name",
	}
	namesStmts := map[string]string{
		"domain": "UPDATE name SET is_zone=TRUE WHERE id=?",
	}

	tx, err := db.Begin()
	check(err)

	tableMap := getTableMap(tablesFields, tx)
	stmtMap := getStmtMap(namesStmts, tx)

	i := CHUNKSIZE

	for rrD := range domainChan {
		if i == 0 {
			i = CHUNKSIZE

			tableMap.mx.Lock()
			stmtMap.mx.Lock()

			check(tx.Commit())
			tx, err = db.Begin()
			check(err)

			tableMap.update(tx)
			stmtMap.update(tx)

			tableMap.mx.Unlock()
			stmtMap.mx.Unlock()
		}
		i--

		domainInsert(tableMap, stmtMap, rrD)
	}

	tableMap.clear()
	stmtMap.clear()
	check(tx.Commit())
	wg.Done()
}

func domainInsert(tableMap TableMap, stmtMap StmtMap, domain string) {
	nameID := tableMap.get("name", domain)

	stmtMap.exec("domain", nameID)
}

func parseDomainLists(db *sql.DB) {
	var matches []string
	var err error
	if len(args) > 0 {
		matches = args
	} else {
		matches, err = fs.Glob(os.DirFS("."), "lists/*.txt") // */
		check(err)
	}

	fileChan := make(chan string, BUFLEN)
	domainChan := make(chan string, BUFLEN)

	var wg sync.WaitGroup

	go insertDomainWorker(db, domainChan, &wg)

	wg.Add(len(matches))

	numProcs := NUMPROCS

	for i := 0; i < numProcs; i++ {
		go readDomainLists(fileChan, domainChan, &wg)
	}

	for _, match := range matches {
		fileChan <- match
	}

	wg.Wait()
	// producers done, stop workers
	close(fileChan) // stop readZonefiles workers
	wg.Add(1)
	close(domainChan) // stop insertRRWorker
	wg.Wait()
	// all threads stopped, done
}
