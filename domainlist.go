package main

import (
	"bufio"
	"database/sql"
	"io/fs"
	"iter"
	"os"
	"sync"

	"github.com/monoidic/dns"
)

// parse domain list files
func readDomainLists(fileChan <-chan string, domainChan chan<- dns.Name, wg *sync.WaitGroup) {
	defer wg.Done()
	for filename := range fileChan {
		fp := check1(os.Open(filename))

		scanner := bufio.NewScanner(fp)

		for scanner.Scan() {
			s := mustParseName(dns.Fqdn(scanner.Text())).Canonical()
			domainChan <- s
		}

		check(fp.Close())
	}
}

func insertDomainWorker(db *sql.DB, seq iter.Seq[dns.Name]) {
	tablesFields := map[string]string{
		"name": "name",
	}
	namesStmts := map[string]string{
		"maybe_zone": "UPDATE name SET maybe_zone=TRUE WHERE id=? AND maybe_checked=FALSE AND is_zone=FALSE AND registered=TRUE AND valid=TRUE",
	}

	insertRR(db, seq, tablesFields, namesStmts, domainInsert)
}

func domainInsert(tableMap TableMap, stmtMap StmtMap, domain dns.Name) {
	nameID := tableMap.get("name", domain.String())

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
	domainChan := make(chan dns.Name, BUFLEN)

	go func(matches []string) {
		for _, match := range matches {
			fileChan <- match
		}
		close(fileChan)
	}(matches)

	var wg sync.WaitGroup
	wg.Add(numProcs)

	for range numProcs {
		go readDomainLists(fileChan, domainChan, &wg)
	}

	closeChanWait(&wg, domainChan)

	insertDomainWorker(db, chanToSeq(domainChan))
}
