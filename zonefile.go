package main

import (
	"database/sql"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

type zoneData struct {
	zone, filename string
}

func readZonefiles(zoneDataChan <-chan zoneData, rrDataChan chan<- rrData, wg *sync.WaitGroup) {
	defer wg.Done()
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

			rrD := rrData{
				zone:       zoneLower,
				rrValue:    rrValue,
				rrType:     dns.TypeToString[header.Rrtype],
				rrName:     header.Name,
				msgtype:    rrDataRegular,
				parentZone: tldZone,
			}

			rrDataChan <- rrD
		}

		rrDataChan <- rrData{
			zone:    zoneLower,
			msgtype: rrDataZoneDone,
		}

		fmt.Printf("inserted %s\n", zoneName)
		check(fp.Close())
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

	go func(matches []string) {
		for _, match := range matches {
			reMatch := pattern.FindAllStringSubmatch(match, 1)
			zone := reMatch[0][1]

			zoneDataChan <- zoneData{filename: match, zone: zone}
		}
		close(zoneDataChan)
	}(matches)

	var wg sync.WaitGroup
	wg.Add(numProcs)

	for range numProcs {
		go readZonefiles(zoneDataChan, rrDataChan, &wg)
	}

	closeChanWait(&wg, rrDataChan)

	insertRRWorker(db, chanToSeq(rrDataChan))
}
