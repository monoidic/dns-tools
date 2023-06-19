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

// parse domain list files
func readDomainLists(fileChan <-chan string, domainChan chan<- string, wg *sync.WaitGroup) {
	for filename := range fileChan {
		fp := check1(os.Open(filename))

		scanner := bufio.NewScanner(fp)

		for scanner.Scan() {
			s := dns.Fqdn(strings.ToLower(scanner.Text()))
			domainChan <- s
		}

		check(fp.Close())
	}
	wg.Done()
}

func insertDomainWorker(db *sql.DB, domainChan <-chan string) {
	tablesFields := map[string]string{
		"name": "name",
	}
	namesStmts := map[string]string{
		"maybe_zone": "UPDATE name SET maybe_zone=TRUE WHERE id=? AND maybe_checked=FALSE AND is_zone=FALSE AND registered=TRUE AND valid=TRUE",
	}

	insertRR(db, domainChan, tablesFields, namesStmts, domainInsert)
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

	go func(matches []string) {
		for _, match := range matches {
			fileChan <- match
		}
		close(fileChan)
	}(matches)

	var wg sync.WaitGroup
	wg.Add(numProcs)

	for i := 0; i < numProcs; i++ {
		go readDomainLists(fileChan, domainChan, &wg)
	}

	go closeChanWait(&wg, domainChan)

	insertDomainWorker(db, domainChan)
}
