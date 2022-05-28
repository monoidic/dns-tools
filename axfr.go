package main

import (
	"database/sql"
	"fmt"
	"github.com/miekg/dns"
	"strings"
	"sync"
	"time"
)

// TODO this will end up with duplicates if some AXFR fails midway through;
// collect it all into memory first? (obvious issues with (parallel) big zones)
//
// use semaphores to reserve memory for transfers so new ones aren't started
// during big transfers???

// check error? (don't retry with rcode Refused/FormatError/NotAuthoritative etc)
func performAxfr(msg dns.Msg, rrDataChan chan rrData, ns string) error {
	t := new(dns.Transfer)
	msg.Id = dns.Id()
	zone := msg.Question[0].Name
	env, err := t.In(&msg, ns)
	if err != nil {
		return err
	}

	for e := range env {
		if e.Error != nil {
			return e.Error
		}

		for _, rr := range e.RR {
			switch rr.(type) {
			case *dns.NSEC, *dns.NSEC3, *dns.RRSIG:
				continue
			}

			normalizeRR(rr)
			rrValue := rr.String()
			header := rr.Header()

			rrDataChan <- rrData{
				zone:     zone,
				rrValue:  rrValue,
				rrType:   dns.TypeToString[header.Rrtype],
				rrName:   header.Name,
				msgtype:  rrDataRegular,
				selfZone: true,
			}
		}
	}

	rrDataChan <- rrData{
		zone:    zone,
		msgtype: rrDataZoneDone,
	}

	fmt.Printf("successful axfr on zone %s via ns %s\n", zone, ns)

	return nil
}

func axfrWorker(zipChan chan zoneIP, rrDataChan chan rrData, readWg, wg *sync.WaitGroup, once *sync.Once) {
	msg := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Opcode: dns.OpcodeQuery,
			Rcode:  dns.RcodeSuccess,
		},
		Question: []dns.Question{dns.Question{
			Qtype:  dns.TypeAXFR,
			Qclass: dns.ClassINET,
		}},
	}

	for zip := range zipChan {
		zone := zip.zone.name
		ns := zip.ip.name
		msg.Question[0].Name = zone

	axfrRetryLoop:
		for i := 0; i < RETRIES; i++ {
			now := time.Now()
			err := performAxfr(msg, rrDataChan, ns)
			if err == nil {
				//timeScanned := now.UTC().Format("2006/01/02 15:04")
				rrDataChan <- rrData{
					zone:    zone,
					ip:      ns[:len(ns)-3], // drop ":53" suffix
					msgtype: rrDataZoneAxfrEnd,
					scanned: now.Unix(),
				}
				break
			}

			switch errStr := err.Error(); errStr {
			case "dns: bad xfr rcode: 1", "dns: bad xfr rcode: 3", "dns: bad xfr rcode: 4", "dns: bad xfr rcode: 5", "dns: no SOA":
				break axfrRetryLoop
			default:
				// fmt.Printf("(ns=%s zone=%s) performAxfr: %T %s\n", ns, zone, err, errStr)
			}
		}

		rrDataChan <- rrData{
			zone:    zone,
			msgtype: rrDataZoneAxfrTry,
		}

		readWg.Done()
	}

	wg.Done()
	wg.Wait()

	once.Do(func() { close(rrDataChan) })
}

func publicAxfrMaster(db *sql.DB, zipChan chan zoneIP, readWg *sync.WaitGroup) {
	numProcs := 64

	rrDataChan := make(chan rrData, BUFLEN)

	var wg sync.WaitGroup
	var once sync.Once

	wg.Add(numProcs)

	for i := 0; i < numProcs; i++ {
		go axfrWorker(zipChan, rrDataChan, readWg, &wg, &once)
	}

	var dummyWg sync.WaitGroup
	dummyWg.Add(1)
	insertRRWorker(db, rrDataChan, &dummyWg)
}

func axfrWhitelist(inChan, outChan chan zoneIP, wg *sync.WaitGroup) {
	for zip := range inChan {
		if AxfrWhitelistedZoneSet[zip.zone.name] || AxfrWhitelistedIPSet[zip.ip.name] {
			wg.Done()
		} else {
			outChan <- zip
		}
	}

	close(outChan)
}

func axfrV4Only(inChan, outChan chan zoneIP, wg *sync.WaitGroup) {
	for zip := range inChan {
		if !strings.Contains(zip.ip.name, ".") { // ipv6
			wg.Done()
		} else {
			outChan <- zip
		}
	}

	close(outChan)
}

func publicAxfr(db *sql.DB) {
	fmt.Println("checking public AXFR")

	var wg sync.WaitGroup
	zipChan := make(chan zoneIP, BUFLEN)
	go zoneIPReader(db, zipChan, &wg, "AND zone.axfr_tried=FALSE")

	var whitelistedChan chan zoneIP
	var ipVersionChan chan zoneIP

	if len(AxfrWhitelistedZoneSet)+len(AxfrWhitelistedIPSet) > 0 {
		whitelistedChan = make(chan zoneIP, BUFLEN)
		go axfrWhitelist(zipChan, whitelistedChan, &wg)
	} else {
		whitelistedChan = zipChan
	}

	if !v6 {
		ipVersionChan = make(chan zoneIP, BUFLEN)
		go axfrV4Only(whitelistedChan, ipVersionChan, &wg)
	} else {
		ipVersionChan = whitelistedChan
	}

	zipFilteredChan := ipVersionChan

	publicAxfrMaster(db, zipFilteredChan, &wg)
}
