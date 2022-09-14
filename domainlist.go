package main

import (
	"bufio"
	"database/sql"
	"io/fs"
	"os"
	"strings"
	"sync"

	"github.com/monoidic/dns"
)

func readDomainLists(fileChan <-chan string, domainChan chan<- string, wg *sync.WaitGroup) {
	for filename := range fileChan {
		fp := check1(os.Open(filename))

		scanner := bufio.NewScanner(fp)

		for scanner.Scan() {
			s := dns.Fqdn(strings.ToLower(scanner.Text()))
			domainChan <- s
		}

		check(fp.Close())

		wg.Done()
	}
}

func insertDomainWorker(db *sql.DB, domainChan <-chan string, wg *sync.WaitGroup) {
	tablesFields := map[string]string{
		"name": "name",
	}
	namesStmts := map[string]string{
		"maybe_zone": "UPDATE name SET maybe_zone=TRUE WHERE id=? AND maybe_checked=FALSE AND is_zone=FALSE AND registered=TRUE AND valid=TRUE",
	}

	tx := check1(db.Begin())

	tableMap := getTableMap(tablesFields, tx)
	stmtMap := getStmtMap(namesStmts, tx)

	i := CHUNKSIZE

	for rrD := range domainChan {
		if i == 0 {
			i = CHUNKSIZE

			tableMap.mx.Lock()
			stmtMap.mx.Lock()

			check(tx.Commit())
			tx = check1(db.Begin())

			tableMap.update(tx)
			stmtMap.update(tx)

			stmtMap.mx.Unlock()
			tableMap.mx.Unlock()
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

	stmtMap.exec("maybe_zone", nameID)
}

func parseDomainLists(db *sql.DB) {
	var matches []string
	if len(args) > 0 {
		matches = args
	} else {
		matches = check1(fs.Glob(os.DirFS("."), "lists/*.txt"))
	}

	fileChan := make(chan string, BUFLEN)
	domainChan := make(chan string, BUFLEN)

	var wg sync.WaitGroup

	go insertDomainWorker(db, domainChan, &wg)

	wg.Add(len(matches))

	for i := 0; i < NUMPROCS; i++ {
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
