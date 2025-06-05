package main

import (
	"database/sql"
	"fmt"
	"iter"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// TODO this will end up with duplicates if some AXFR fails midway through;
// collect it all into memory first? (obvious issues with (parallel) big zones)

// use semaphores to reserve memory for transfers so new ones aren't started
// during big transfers???

// check error? (don't retry with rcode Refused/FormatError/NotAuthoritative etc)

// attempt AXFR query for a zone with a nameserver
func performAxfr(msg dns.Msg, rrDataChan chan<- rrData, ns string) error {
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

// worker that
func axfrWorker(zipChan <-chan zoneIP, rrDataChan chan<- rrData, wg *sync.WaitGroup) {
	defer wg.Done()
	msg := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Opcode: dns.OpcodeQuery,
			Rcode:  dns.RcodeSuccess,
		},
		Question: []dns.Question{{
			Qtype:  dns.TypeAXFR,
			Qclass: dns.ClassINET,
		}},
	}

	for zip := range zipChan {
		zone := zip.zone.name
		ns := zip.ip.name
		msg.Question[0].Name = zone

	axfrRetryLoop:
		for range RETRIES {
			now := time.Now()
			if err := performAxfr(msg, rrDataChan, ns); err == nil {
				start := 0
				end := len(ns) - 3 // drop :53
				if ns[0] == '[' {  // drop []
					start++
					end--
				}
				ip := ns[start:end]
				// timeScanned := now.UTC().Format("2006/01/02 15:04")
				rrDataChan <- rrData{
					zone:    zone,
					ip:      ip,
					msgtype: rrDataZoneAxfrEnd,
					scanned: now.Unix(),
				}
				break
			} else {
				switch errStr := err.Error(); errStr {
				case "dns: bad xfr rcode: 1", "dns: bad xfr rcode: 3", "dns: bad xfr rcode: 4", "dns: bad xfr rcode: 5", "dns: no SOA":
					break axfrRetryLoop
				default:
					// fmt.Printf("(ns=%s zone=%s) performAxfr: %T %s\n", ns, zone, err, errStr)
				}
			}
		}

		rrDataChan <- rrData{
			zone:    zone,
			msgtype: rrDataZoneAxfrTry,
		}
	}
}

func publicAxfrMaster(db *sql.DB, seq iter.Seq[zoneIP]) {
	numProcs := 64

	rrDataChan := make(chan rrData, BUFLEN)

	var wg sync.WaitGroup

	wg.Add(numProcs)

	ch := seqToChan(seq, BUFLEN)

	for range numProcs {
		go axfrWorker(ch, rrDataChan, &wg)
	}

	closeChanWait(&wg, rrDataChan)

	insertRRWorker(db, chanToSeq(rrDataChan))
}

// filter out whitelisted zones or nameserver IPs
func axfrWhitelist(seq iter.Seq[zoneIP]) iter.Seq[zoneIP] {
	if len(AxfrWhitelistedZoneSet)+len(AxfrWhitelistedIPSet) == 0 {
		return seq
	}

	return func(yield func(zoneIP) bool) {
		for zip := range seq {
			if !(AxfrWhitelistedZoneSet.Contains(zip.zone.name) || AxfrWhitelistedIPSet.Contains(zip.ip.name)) {
				if !yield(zip) {
					return
				}
			}
		}
	}
}

// filter out IPv6 addresses
func axfrV4Only(seq iter.Seq[zoneIP]) iter.Seq[zoneIP] {
	if v6 {
		return seq
	}

	return func(yield func(zoneIP) bool) {
		for zip := range seq {
			if strings.Contains(zip.ip.name, ".") { // ipv4
				if !yield(zip) {
					return
				}
			}
		}
	}
}

func publicAxfr(db *sql.DB) {
	fmt.Println("checking public AXFR")

	zoneIPs := zoneIPReader(db)
	zoneIPs = axfrWhitelist(zoneIPs)
	zoneIPs = axfrV4Only(zoneIPs)

	publicAxfrMaster(db, zoneIPs)
}
