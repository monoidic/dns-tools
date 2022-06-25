package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/yl2chen/cidranger"
)

type rangerEntry struct {
	subnet net.IPNet
	match  bool
}

func (entry rangerEntry) Network() net.IPNet {
	return entry.subnet
}

// 2^24 + 2^16 + 2^8 addresses
// 239 * (2^16) + 239 * 2^8 + 239 addresses
func generateInAddr(zoneChan chan string, wg *sync.WaitGroup) {
	// for a := 0; a < 256; a++ {
	for a := 1; a < 240; a++ {
		addrA := fmt.Sprintf("%d.in-addr.arpa.", a)
		wg.Add(1)
		zoneChan <- addrA
		for b := 0; b < 256; b++ {
			addrB := fmt.Sprintf("%d.%s", b, addrA)
			wg.Add(1)
			zoneChan <- addrB
			for c := 0; c < 256; c++ {
				wg.Add(1)
				zoneChan <- fmt.Sprintf("%d.%s", c, addrB)
			}
		}
	}

	wg.Wait()
	close(zoneChan)
}

func generateInAddrNets(zoneChan chan string, wg *sync.WaitGroup, netsFile, cc string) {
	fd, err := os.Open(netsFile)
	check(err)

	scanner := bufio.NewScanner(fd)
	ranger := cidranger.NewPCTrieRanger()

	for scanner.Scan() {
		text := scanner.Text()
		if strings.Contains(text, ".") { // IPv4 only here
			split := strings.SplitN(text, "\t", 2)
			if len(split) != 2 {
				panic(fmt.Sprintf("invalid line: %s", text))
			}
			_, subnet, err := net.ParseCIDR(split[1])
			check(err)
			check(ranger.Insert(rangerEntry{subnet: *subnet, match: split[0] == cc}))
		}
	}

	var ip net.IP = make([]byte, 4)
	var length int
	var containingNets []cidranger.RangerEntry

	for a := 1; a < 240; a++ {
		addrA := fmt.Sprintf("%d.in-addr.arpa.", a)
		ip[0] = byte(a)

		containingNets, err = ranger.ContainingNetworks(ip)
		check(err)

		if length = len(containingNets); length > 0 && containingNets[length-1].(rangerEntry).match {
			wg.Add(1)
			zoneChan <- addrA
		}

		for b := 0; b < 256; b++ {
			addrB := fmt.Sprintf("%d.%s", b, addrA)
			ip[1] = byte(b)
			containingNets, err = ranger.ContainingNetworks(ip)
			check(err)

			if length = len(containingNets); length > 0 && containingNets[length-1].(rangerEntry).match {
				wg.Add(1)
				zoneChan <- addrB
			}

			for c := 0; c < 256; c++ {
				ip[2] = byte(c)

				containingNets, err = ranger.ContainingNetworks(ip)
				check(err)

				if length = len(containingNets); length > 0 && containingNets[length-1].(rangerEntry).match {
					wg.Add(1)
					zoneChan <- fmt.Sprintf("%d.%s", c, addrB)
				}
			}
			ip[2] = 0
		}
		ip[1] = 0
	}

	wg.Wait()
	close(zoneChan)
	check(fd.Close())
}

func inAddrWorker(zoneChan chan string, outChan chan inAddrData, wg *sync.WaitGroup, once *sync.Once) {
	msg := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Opcode:           dns.OpcodeQuery,
			RecursionDesired: true,
			Rcode:            dns.RcodeSuccess,
		},
		Question: []dns.Question{{
			Qclass: dns.ClassINET,
			Qtype:  dns.TypeNS,
		}},
	}
	msgSetSize(&msg)

	resolverWorker(zoneChan, outChan, msg, inAddrResolve, wg, once)
}

func inAddrResolve(connCache connCache, msg dns.Msg, zone string) inAddrData {
	msg.Question[0].Name = zone
	var err error
	var NSes []string
	var response *dns.Msg

	for i := 0; i < RETRIES; i++ {
		nameserver := usedNs[rand.Intn(usedNsLen)]
		response, err = plainResolve(msg, connCache, nameserver)
		if err == nil {
			break
		}
		// fmt.Printf("inAddrResolve: %s\n", err)
	}

	if response != nil {
		for _, rr := range response.Answer {
			switch rrT := rr.(type) {
			case *dns.NS:
				NSes = append(NSes, dns.Fqdn(strings.ToLower(rrT.Ns)))
			}
		}
	}

	return inAddrData{zone: zone, NSes: NSes}
}

func inAddrWriter(db *sql.DB, zoneChan chan string, wg *sync.WaitGroup) {
	tablesFields := map[string]string{
		"name": "name",
	}
	namesStmts := map[string]string{
		"insert":     "INSERT OR IGNORE INTO zone_ns (zone_id, ns_id) VALUES (?, ?)",
		"nameToZone": "UPDATE name SET is_zone=TRUE, is_rdns=TRUE WHERE id=?",
		"nameToNS":   "UPDATE name SET is_ns=TRUE WHERE id=?",
	}

	netWriter(db, zoneChan, wg, tablesFields, namesStmts, inAddrWorker, inAddrWrite)
}

func inAddrWrite(tableMap TableMap, stmtMap StmtMap, iad inAddrData) {
	if len(iad.NSes) > 0 {
		zoneID := tableMap.get("name", iad.zone)
		stmtMap.exec("nameToZone", zoneID)

		for _, ns := range iad.NSes {
			nsID := tableMap.get("name", ns)
			stmtMap.exec("nameToNS", nsID)
			stmtMap.exec("insert", zoneID, nsID)
		}
	}
}

func getInAddrArpa(db *sql.DB) {
	fmt.Println("Checking for in-addr.arpa zones")

	var wg sync.WaitGroup
	nsChan := make(chan string, BUFLEN)

	if networksFile == "" || netCC == "" {
		go generateInAddr(nsChan, &wg)
	} else {
		go generateInAddrNets(nsChan, &wg, networksFile, netCC)
	}
	inAddrWriter(db, nsChan, &wg)
}
