package main

import (
	"database/sql"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/monoidic/dns"
)

type zoneData struct {
	zone, filename string
}

func readZonefiles(zoneDataChan chan zoneData, rrDataChan chan rrData, wg *sync.WaitGroup) {
	for zoneD := range zoneDataChan {
		zoneName, filename := zoneD.zone, zoneD.filename
		fp := check1(os.Open(filename))

		zp := dns.NewZoneParser(fp, zoneName, filename)
		zoneLower := strings.ToLower(zoneName)

		for rr, running := zp.Next(); running; rr, running = zp.Next() {
			switch rr.(type) {
			case *dns.NSEC, *dns.NSEC3, *dns.RRSIG:
				continue
			}

			normalizeRR(rr)

			rrValue := rr.String()

			header := rr.Header()

			// fmt.Printf("inserted %s\n", rrValue)
			rrD := rrData{
				zone:    zoneLower,
				rrValue: rrValue,
				rrType:  dns.TypeToString[header.Rrtype],
				rrName:  header.Name,
				msgtype: rrDataRegular,
			}

			if tldZone {
				rrD.parentZone = true
			}

			rrDataChan <- rrD
		}

		rrDataChan <- rrData{
			zone:    zoneLower,
			msgtype: rrDataZoneDone,
		}

		fmt.Printf("inserted %s\n", zoneName)
		check(fp.Close())
		wg.Done()
	}
}

func parseZoneFiles(db *sql.DB) {
	var matches []string
	if len(args) > 0 {
		matches = args
	} else {
		matches = check1(fs.Glob(os.DirFS("."), "zones/*.zone"))
	}

	pattern := regexp.MustCompile("zones/([a-z0-9.-]+)zone")
	rrDataChan := make(chan rrData, BUFLEN)
	zoneDataChan := make(chan zoneData, BUFLEN)
	var wg sync.WaitGroup

	go insertRRWorker(db, rrDataChan, &wg)

	wg.Add(len(matches))
	numProcs := NUMPROCS

	for i := 0; i < numProcs; i++ {
		go readZonefiles(zoneDataChan, rrDataChan, &wg)
	}

	for _, match := range matches {
		reMatch := pattern.FindAllStringSubmatch(match, 1)
		zone := reMatch[0][1]

		zoneDataChan <- zoneData{filename: match, zone: zone}
	}

	wg.Wait()
	// producers done, stop workers
	close(zoneDataChan) // stop readZonefiles workers
	wg.Add(1)
	close(rrDataChan) // stop insertRRWorker
	wg.Wait()
	// all threads stopped, done
}
