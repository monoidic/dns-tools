package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"github.com/jellydator/ttlcache/v3"
	"github.com/miekg/dns"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"
)

type mxData struct {
	data       []mxDatum
	zoneID     int64
	registered bool
}

type mxDatum struct {
	address    string
	preference uint16
}

type fieldData struct {
	name string
	id   int64
}

type fdResults struct {
	fieldData
	results []string
}

type addrData struct {
	fdResults
	cnames     []cnameEntry
	registered bool
}

type cnameEntry struct {
	source, target string
}

type parentNSResults struct {
	fieldData
	nsEntries []keyValue
	ipEntries []keyValue
}

type inAddrData struct {
	zone string
	NSes []string
}

type checkUpData struct {
	ns, zone   string
	ipID       int64
	success    bool
	registered bool
}

type zoneIP struct {
	zone fieldData
	ip   fieldData
}

type connCache struct {
	// TODO merge conn and cookie caches into *ttlcache.Cache[string, hostInfo] ?
	client         *dns.Client
	udpCache       *ttlcache.Cache[string, *dns.Conn]
	tcpCache       *ttlcache.Cache[string, *dns.Conn]
	udpCookieCache *ttlcache.Cache[string, string]
	tcpCookieCache *ttlcache.Cache[string, string]
}

type Error struct {
	s string
}

func (e Error) Error() string {
	return e.s
}

func getConnCache() connCache {
	// TODO use ttlcache.WithCapacity as well?
	client := &dns.Client{Net: "udp"}

	ttlOption := ttlcache.WithTTL[string, *dns.Conn](25 * time.Second)
	tcpCacheF := connCacheLoader(client, "tcp")
	tcpCache := ttlcache.New[string, *dns.Conn](ttlOption, tcpCacheF)
	go tcpCache.Start()
	tcpCache.OnEviction(connCacheEviction)
	tcpCookieCache := getCookieCache(tcpCache, client)

	var udpCacheF ttlcache.Option[string, *dns.Conn]
	var udpCache *ttlcache.Cache[string, *dns.Conn]
	var udpCookieCache *ttlcache.Cache[string, string]

	if tcpOnly {
		client.Net = "tcp"
	} else {
		udpCacheF = connCacheLoader(client, "udp")
		udpCache = ttlcache.New[string, *dns.Conn](ttlOption, udpCacheF)
		udpCookieCache = getCookieCache(udpCache, client)
		go udpCache.Start()
		udpCache.OnEviction(connCacheEviction)
	}

	return connCache{
		client:         client,
		tcpCache:       tcpCache,
		tcpCookieCache: tcpCookieCache,
		udpCache:       udpCache,
		udpCookieCache: udpCookieCache,
	}
}

func getCookieCache(protoCache *ttlcache.Cache[string, *dns.Conn], client *dns.Client) *ttlcache.Cache[string, string] {
	cookieF := cookieFetcher(protoCache, client)
	ttlOption := ttlcache.WithTTL[string, string](5 * time.Minute)
	cache := ttlcache.New[string, string](cookieF, ttlOption)
	go cache.Start()
	return cache
}

func getNull[T any](cache *ttlcache.Cache[string, T], key string) T {
	var value T
	item := cache.Get(key)
	if item != nil {
		value = item.Value()
	}
	return value
}

func (c connCache) getUDP(hostname string) *dns.Conn {
	return getNull(c.udpCache, hostname)
}

func (c connCache) getTCP(hostname string) *dns.Conn {
	return getNull(c.tcpCache, hostname)
}

func (c connCache) getUDPCookie(hostname string) string {
	return getNull(c.udpCookieCache, hostname)
}

func (c connCache) getTCPCookie(hostname string) string {
	return getNull(c.tcpCookieCache, hostname)
}

func exchange(hostname string, msg dns.Msg, cookieCache *ttlcache.Cache[string, string], connCache *ttlcache.Cache[string, *dns.Conn], client *dns.Client) (*dns.Msg, error) {
	msg.Id = dns.Id()

	if cookie := getNull(cookieCache, hostname); cookie != "" {
		oCookie := msgAddCookie(&msg)
		oCookie.Cookie = cookie
	}

	conn := getNull(connCache, hostname)
	if conn == nil {
		return nil, Error{s: "could not connect to host"}
	}

	res, _, err := client.ExchangeWithConn(&msg, conn)
	if err != nil {
		connCache.Delete(hostname)
	} else if cookie := cookieFromMsg(*res); cookie != "" {
		cookieCache.Set(hostname, cookie, ttlcache.DefaultTTL)
	}

	return res, err
}

func (c connCache) tcpExchange(hostname string, msg dns.Msg) (*dns.Msg, error) {
	return exchange(hostname, msg, c.tcpCookieCache, c.tcpCache, c.client)
}

func (c connCache) udpExchange(hostname string, msg dns.Msg) (*dns.Msg, error) {
	return exchange(hostname, msg, c.udpCookieCache, c.udpCache, c.client)
}

func msgAddCookie(msg *dns.Msg) *dns.EDNS0_COOKIE {
	opt := setOpt(msg)
	var oCookie *dns.EDNS0_COOKIE
	for _, rr := range opt.Option {
		switch rrT := rr.(type) {
		case *dns.EDNS0_COOKIE:
			return rrT
		}
	}

	oCookie = &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE}
	opt.Option = append(opt.Option, oCookie)
	return oCookie
}

func (c connCache) clear() {
	c.tcpCache.Stop()
	c.tcpCache.DeleteAll()
	c.tcpCookieCache.Stop()
	c.tcpCookieCache.DeleteAll()

	if !tcpOnly {
		c.udpCache.Stop()
		c.udpCache.DeleteAll()
		c.udpCookieCache.Stop()
		c.udpCookieCache.DeleteAll()
	}
}

func connCacheLoader(client *dns.Client, proto string) ttlcache.Option[string, *dns.Conn] {
	return ttlcache.WithLoader[string, *dns.Conn](ttlcache.LoaderFunc[string, *dns.Conn](func(c *ttlcache.Cache[string, *dns.Conn], host string) *ttlcache.Item[string, *dns.Conn] {
		prevProto := client.Net
		client.Net = proto
		var conn *dns.Conn
		var err error

		for i := 0; i < RETRIES; i++ {
			conn, err = client.Dial(host)
			if err == nil {
				break
			}
		}

		client.Net = prevProto

		if err == nil {
			return c.Set(host, conn, ttlcache.DefaultTTL)
		}
		return nil
	}))
}

func cookieFetcher(protoCache *ttlcache.Cache[string, *dns.Conn], client *dns.Client) ttlcache.Option[string, string] {
	msg := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Opcode:           dns.OpcodeQuery,
			RecursionDesired: false,
			Rcode:            dns.RcodeSuccess,
		},
		Question: []dns.Question{},
	}

	msgSetSize(&msg)

	bufRand := make([]byte, 8)
	bufStr := make([]byte, 16)
	oRand := rand.New(rand.NewSource(rand.Int63()))

	getRandCookie := func() string {
		oRand.Read(bufRand)
		hex.Encode(bufStr, bufRand)
		return string(bufStr)
	}

	oCookie := msgAddCookie(&msg)

	return ttlcache.WithLoader[string, string](ttlcache.LoaderFunc[string, string](func(c *ttlcache.Cache[string, string], host string) *ttlcache.Item[string, string] {
		for i := 0; i < RETRIES; i++ {
			connItem := protoCache.Get(host)
			if connItem == nil {
				return nil
			}
			conn := connItem.Value()
			oCookie.Cookie = getRandCookie()

			cookie, err := fetchCookie(msg, oCookie, client, conn)

			if err != nil {
				protoCache.Delete(host)
				continue
			}

			return c.Set(host, cookie, ttlcache.DefaultTTL)
		}

		return nil
	}))
}

func fetchCookie(msg dns.Msg, oCookie *dns.EDNS0_COOKIE, client *dns.Client, conn *dns.Conn) (cookie string, err error) {
	res, _, err := client.ExchangeWithConn(&msg, conn)
	if err != nil {
		return "", err
	}

	return cookieFromMsg(*res), nil
}

func cookieFromMsg(msg dns.Msg) string {
	var optRR *dns.OPT

cookieFromMsgLoop:
	for _, rr := range msg.Extra {
		switch rrT := rr.(type) {
		case *dns.OPT:
			optRR = rrT
			break cookieFromMsgLoop
		}
	}

	if optRR == nil { // no EDNS(0) support
		return ""
	}

	for _, opt := range optRR.Option {
		switch optT := opt.(type) {
		case *dns.EDNS0_COOKIE:
			return optT.Cookie
		}
	}

	// cookies not supported/enabled
	return ""
}

func connCacheEviction(_ context.Context, _ ttlcache.EvictionReason, item *ttlcache.Item[string, *dns.Conn]) {
	item.Value().Close()
}

func plainResolve(msg dns.Msg, connCache connCache, nameserver string) (*dns.Msg, error) {
	var res *dns.Msg
	var err error
	if tcpOnly {
		res, err = connCache.tcpExchange(nameserver, msg)
	} else {
		res, err = connCache.udpExchange(nameserver, msg)
	}

	if err != nil {
		if tcpOnly {
			return nil, err
		}
		//fmt.Printf("failed to fetch response from %s over UDP: %v\n", nameserver, err)
		res, err = connCache.tcpExchange(nameserver, msg)
		if err != nil {
			//fmt.Printf("failed to fetch response from %s over TCP: %v\n", nameserver, err)
			return nil, err
		}
	}

	return res, nil
}

func setOpt(msg *dns.Msg) *dns.OPT {
	if len(msg.Extra) > 1 {
		return msg.Extra[0].(*dns.OPT)
	}

	opt := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
		},
	}

	msg.Extra = append(msg.Extra, opt)
	return opt
}
func msgSetSize(msg *dns.Msg) {
	opt := setOpt(msg)
	opt.SetUDPSize(dns.DefaultMsgSize)
}

func resolverWorker[inType, resultType any](inChan chan inType, outChan chan resultType, msg dns.Msg, processData func(c connCache, msg dns.Msg, fd inType) resultType, wg *sync.WaitGroup, once *sync.Once) {
	connCache := getConnCache()

	//t := TIMEOUT
	//client.DialTimeout = t
	//client.ReadTimeout = t
	//client.WriteTimeout = t

	for fd := range inChan {
		outChan <- processData(connCache, msg, fd)
	}

	connCache.clear()
	wg.Done()
	wg.Wait()
	once.Do(func() { close(outChan) })
}

func nsResolverWorker(inChan chan fieldData, outChan chan fdResults, wg *sync.WaitGroup, once *sync.Once) {
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

	resolverWorker(inChan, outChan, msg, nsResolve, wg, once)

}

func mxResolverWorker(inChan chan fieldData, outChan chan mxData, wg *sync.WaitGroup, once *sync.Once) {
	msg := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Opcode:           dns.OpcodeQuery,
			RecursionDesired: true,
			Rcode:            dns.RcodeSuccess,
		},
		Question: []dns.Question{{
			Qclass: dns.ClassINET,
			Qtype:  dns.TypeMX,
		}},
	}
	msgSetSize(&msg)

	resolverWorker(inChan, outChan, msg, mxResolve, wg, once)
}

func addrResolverWorker(inChan chan fieldData, outChan chan addrData, wg *sync.WaitGroup, once *sync.Once) {
	msg := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Opcode:           dns.OpcodeQuery,
			RecursionDesired: true,
			Rcode:            dns.RcodeSuccess,
		},
		Question: []dns.Question{{
			Qclass: dns.ClassINET,
		}},
	}
	msgSetSize(&msg)

	resolverWorker(inChan, outChan, msg, addrResolve, wg, once)
}

func parentCheckWorker(inChan, outChan chan childParent, wg *sync.WaitGroup, tableMap TableMap, stmtMap StmtMap, once *sync.Once) {
	msg := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Opcode:           dns.OpcodeQuery,
			RecursionDesired: true,
			Rcode:            dns.RcodeSuccess,
		},
		Question: []dns.Question{{
			Qclass: dns.ClassINET,
			Qtype:  dns.TypeSOA,
		}},
	}
	msgSetSize(&msg)

	workerInChan := make(chan childParent, BUFLEN)
	go parentCheckFilter(inChan, workerInChan, tableMap, stmtMap)

	resolverWorker(workerInChan, outChan, msg, parentCheckResolve, wg, once)
}

// bypass resolver if already in DB
func parentCheckFilter(inChan, workerInChan chan childParent, tableMap TableMap, stmtMap StmtMap) {
	tableMap.wg.Add(1)
	for cp := range inChan {
		if cp.parentGuess == "" {
			cp.resolved = true
		} else if parentID := tableMap.roGet("name", cp.parentGuess); parentID != 0 {
			cp.resolved = true
			cp.registered = true
			cp.parent.name = cp.parentGuess
			cp.parent.id = parentID
		}
		workerInChan <- cp
	}
	close(workerInChan)
	tableMap.wg.Done()

}

func checkUpWorker(inChan, outChan chan checkUpData, wg *sync.WaitGroup, once *sync.Once) {
	msg := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Opcode:           dns.OpcodeQuery,
			RecursionDesired: false,
			Rcode:            dns.RcodeSuccess,
		},
		Question: []dns.Question{{
			Qclass: dns.ClassINET,
			Qtype:  dns.TypeSOA,
		}},
	}
	msgSetSize(&msg)

	resolverWorker(inChan, outChan, msg, checkUpResolve, wg, once)
}

func rdnsWorker(inChan chan fieldData, outChan chan fdResults, wg *sync.WaitGroup, once *sync.Once) {
	msg := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Opcode:           dns.OpcodeQuery,
			RecursionDesired: true,
			Rcode:            dns.RcodeSuccess,
		},
		Question: []dns.Question{{
			Qclass: dns.ClassINET,
			Qtype:  dns.TypePTR,
		}},
	}
	msgSetSize(&msg)

	resolverWorker(inChan, outChan, msg, rdnsResolve, wg, once)
}

func parentNSResolverWorker(inChan chan fdResults, outChan chan parentNSResults, wg *sync.WaitGroup, once *sync.Once) {
	msg := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Opcode:           dns.OpcodeQuery,
			RecursionDesired: false,
			Rcode:            dns.RcodeSuccess,
		},
		Question: []dns.Question{{
			Qclass: dns.ClassINET,
			Qtype:  dns.TypeNS,
		}},
	}
	msgSetSize(&msg)

	resolverWorker(inChan, outChan, msg, parentNsResolve, wg, once)
}

func nsResolve(connCache connCache, msg dns.Msg, fd fieldData) fdResults {
	msg.Question[0].Name = dns.Fqdn(fd.name)
	var response *dns.Msg
	var results []string
	var err error

	for i := 0; i < RETRIES; i++ {
		nameserver := usedNs[rand.Intn(usedNsLen)]
		response, err = plainResolve(msg, connCache, nameserver)
		if err == nil {
			break
		}
		// fmt.Printf("nsResolve: %s\n", err)
	}

	if response != nil {
		//fmt.Printf("nsResolve response: %#v\n", response)
		for _, rr := range response.Answer {
			switch rrT := rr.(type) {
			case *dns.NS:
				results = append(results, dns.Fqdn(strings.ToLower(rrT.Ns)))
			}
		}
	}

	return fdResults{fieldData: fd, results: results}
}

func mxResolve(connCache connCache, msg dns.Msg, fd fieldData) mxData {
	msg.Question[0].Name = dns.Fqdn(fd.name)
	var response *dns.Msg
	var results []mxDatum
	var err error
	registered := true

	for i := 0; i < RETRIES; i++ {
		nameserver := usedNs[rand.Intn(usedNsLen)]
		response, err = plainResolve(msg, connCache, nameserver)
		if err == nil {
			break
		}
		//fmt.Printf("mxResolve: %s\n", err)
	}

	if response != nil {
		for _, rr := range response.Answer {
			switch rrT := rr.(type) {
			case *dns.MX:
				results = append(results, mxDatum{address: dns.Fqdn(strings.ToLower(rrT.Mx)), preference: rrT.Preference})
			}
		}
		registered = response.Rcode != dns.RcodeNameError
	}

	return mxData{data: results, zoneID: fd.id, registered: registered}
}

func addrResolve(connCache connCache, msg dns.Msg, fd fieldData) addrData {
	msg.Question[0].Name = dns.Fqdn(fd.name)
	var results []string
	var cnames []cnameEntry
	var err error
	registered := true

	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		msg.Question[0].Qtype = qtype
		var response *dns.Msg

		for i := 0; i < RETRIES; i++ {
			nameserver := usedNs[rand.Intn(usedNsLen)]
			response, err = plainResolve(msg, connCache, nameserver)
			if err == nil {
				break
			}
			// fmt.Printf("addrResolve: %s\n", err)
		}

		if response != nil {
			for _, rr := range response.Answer {
				switch rrT := rr.(type) {
				case *dns.A:
					results = append(results, rrT.A.String())
				case *dns.AAAA:
					results = append(results, rrT.AAAA.String())
				case *dns.CNAME:
					cnames = append(cnames, cnameEntry{source: strings.ToLower(rrT.Hdr.Name), target: strings.ToLower(rrT.Target)})
				}
			}

			registered = response.Rcode != dns.RcodeNameError
		}
	}

	return addrData{fdResults: fdResults{fieldData: fd, results: results}, cnames: cnames, registered: registered}
}

func parentCheckResolve(connCache connCache, msg dns.Msg, cp childParent) childParent {
	if cp.resolved { // ID fetched by parentCheckFilter or invalid/nonexistant
		return cp
	}

	msg.Question[0].Name = cp.parentGuess
	var res *dns.Msg
	var err error

	for i := 0; i < RETRIES; i++ {
		nameserver := usedNs[rand.Intn(usedNsLen)]
		res, err = plainResolve(msg, connCache, nameserver)
		if err == nil {
			break
		}
		//fmt.Printf("parentCheckResolve: %s\n", err)
	}

	if err != nil {
		return cp
	}

	var soa *dns.SOA

parentCheckSOALoop:
	for _, rrL := range [][]dns.RR{res.Ns, res.Answer} {
		for _, rr := range rrL {
			switch rrT := rr.(type) {
			case *dns.SOA:
				soa = rrT
				break parentCheckSOALoop
			}
		}
	}

	if soa != nil {
		realParent := strings.ToLower(soa.Hdr.Name)
		cp.parent.name = realParent
		cp.resolved = true
		cp.registered = res.Rcode != dns.RcodeNameError
	}

	return cp
}

func checkUpResolve(connCache connCache, msg dns.Msg, cu checkUpData) checkUpData {
	msg.Question[0].Name = dns.Fqdn(cu.zone)
	cu.registered = true

	for i := 0; i < RETRIES; i++ {
		if res, err := plainResolve(msg, connCache, cu.ns); err == nil {
			cu.registered = res.Rcode != dns.RcodeNameError
			cu.success = true
			break
		}
		//fmt.Printf("checkUpResolve: %s\n", err)
	}

	return cu
}

func rdnsResolve(connCache connCache, msg dns.Msg, fd fieldData) fdResults {
	var err error
	msg.Question[0].Name, err = dns.ReverseAddr(fd.name)
	check(err)
	var res *dns.Msg
	var results []string

	for i := 0; i < RETRIES; i++ {
		nameserver := usedNs[rand.Intn(usedNsLen)]
		res, err = plainResolve(msg, connCache, nameserver)
		if err == nil {
			break
		}
		//fmt.Printf("rdnsResolve: %s\n", err)
	}

	if res != nil {
		for _, rr := range res.Answer {
			switch rrT := rr.(type) {
			case *dns.PTR:
				results = append(results, strings.ToLower(rrT.Ptr))
			}
		}
	}

	return fdResults{fieldData: fd, results: results}
}

func parentNsResolve(connCache connCache, msg dns.Msg, fdr fdResults) parentNSResults {
	msg.Question[0].Name = dns.Fqdn(fdr.name)
	var nsResults []keyValue
	var ipResults []keyValue

	if nsLen := len(fdr.results); nsLen > 0 {
		var response *dns.Msg
		var err error
	parentNsResolveOuterLoop:
		for _, nameserver := range fdr.results {
			for i := 0; i < RETRIES; i++ {
				response, err = plainResolve(msg, connCache, nameserver)
				if err == nil {
					break parentNsResolveOuterLoop
				}
				// fmt.Printf("parentNSResolve: %s\n", err)
			}
		}

		if response != nil {
			for _, rr := range response.Ns {
				switch rrT := rr.(type) {
				case *dns.NS:
					nsResults = append(nsResults, keyValue{key: strings.ToLower(rrT.Hdr.Name), value: strings.ToLower(rrT.Ns)})
				}
			}

			for _, rr := range response.Extra {
				switch rrT := rr.(type) {
				case *dns.A:
					ipResults = append(ipResults, keyValue{key: strings.ToLower(rrT.Hdr.Name), value: rrT.A.String()})
				case *dns.AAAA:
					ipResults = append(ipResults, keyValue{key: strings.ToLower(rrT.Hdr.Name), value: rrT.AAAA.String()})
				}
			}
		}
	}

	return parentNSResults{fieldData: fdr.fieldData, nsEntries: nsResults, ipEntries: ipResults}
}

func netWriterTable[inType any, resultType any](db *sql.DB, inChan chan inType, wg *sync.WaitGroup, tablesFields, namesStmts map[string]string, workerF func(inChan chan inType, outChan chan resultType, wg *sync.WaitGroup, tableMap TableMap, stmtMap StmtMap, once *sync.Once), insertF func(tableMap TableMap, stmtMap StmtMap, datum resultType)) {
	numProcs := 64

	dataOutChan := make(chan resultType, BUFLEN)

	var once sync.Once
	var workerWg sync.WaitGroup

	tx, err := db.Begin()
	check(err)

	tableMap := getTableMap(tablesFields, tx)
	stmtMap := getStmtMap(namesStmts, tx)

	workerWg.Add(numProcs)

	for i := 0; i < numProcs; i++ {
		go workerF(inChan, dataOutChan, &workerWg, tableMap, stmtMap, &once)
	}

	i := CHUNKSIZE

	for datum := range dataOutChan {
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

		insertF(tableMap, stmtMap, datum)
		wg.Done()
	}

	tableMap.clear()
	stmtMap.clear()
	check(tx.Commit())
}

func netWriter[inType any, resultType any](db *sql.DB, inChan chan inType, wg *sync.WaitGroup, tablesFields, namesStmts map[string]string, workerF func(inChan chan inType, outChan chan resultType, wg *sync.WaitGroup, once *sync.Once), insertF func(tableMap TableMap, stmtMap StmtMap, datum resultType)) {
	netWriterTable(db, inChan, wg, tablesFields, namesStmts, func(inChan chan inType, outChan chan resultType, wg *sync.WaitGroup, _ TableMap, _ StmtMap, once *sync.Once) {
		workerF(inChan, outChan, wg, once)
	}, insertF)
}

func netNSWriter(db *sql.DB, zoneChan chan fieldData, wg *sync.WaitGroup) {
	tablesFields := map[string]string{
		"name": "name",
	}
	namesStmts := map[string]string{
		"insert":     "INSERT OR IGNORE INTO zone_ns (zone_id, ns_id) VALUES (?, ?)",
		"selfZone":   "UPDATE zone_ns SET in_self_zone=TRUE WHERE zone_id=? AND ns_id=?",
		"update":     "UPDATE name SET ns_resolved=TRUE WHERE id=?",
		"nameToNS":   "UPDATE name SET is_ns=TRUE WHERE id=?",
		"registered": "UPDATE name SET registered=TRUE, reg_checked=TRUE WHERE id=?",
	}

	netWriter(db, zoneChan, wg, tablesFields, namesStmts, nsResolverWorker, nsWrite)
}

func netIPWriter(db *sql.DB, nameChan chan fieldData, wg *sync.WaitGroup) {
	tablesFields := map[string]string{
		"ip":   "address",
		"name": "name",
	}
	namesStmts := map[string]string{
		"insert":       "INSERT OR IGNORE INTO name_ip (name_id, ip_id) VALUES (?, ?)",
		"updateNameIP": "UPDATE name_ip SET in_self_zone=TRUE WHERE name_id=? AND ip_id=?",
		"update":       "UPDATE name SET addr_resolved=TRUE, valid_tried=TRUE, reg_checked=TRUE, registered=? WHERE id=?",
		"cname":        "UPDATE name SET is_cname=TRUE, reg_checked=TRUE, registered=? WHERE id=?",
		"cnameEntry":   "INSERT OR IGNORE INTO cname (name_id, target_id) VALUES (?, ?)",
		"cname_unreg":  "UPDATE name SET reg_checked=TRUE, registered=FALSE WHERE id=?",
	}

	netWriter(db, nameChan, wg, tablesFields, namesStmts, addrResolverWorker, ipWrite)
}

func mxWriter(db *sql.DB, zoneChan chan fieldData, wg *sync.WaitGroup) {
	tablesFields := map[string]string{
		"name": "name",
	}
	namesStmts := map[string]string{
		"insert":   "INSERT OR IGNORE INTO name_mx (name_id, mx_id, preference) VALUES (?, ?, ?)",
		"nameToMX": "UPDATE name SET is_mx=TRUE WHERE id=?",
		"update":   "UPDATE name SET mx_resolved=TRUE, reg_checked=TRUE, registered=? WHERE id=?",
	}

	netWriter(db, zoneChan, wg, tablesFields, namesStmts, mxResolverWorker, mxWrite)
}

func checkUpWriter(db *sql.DB, checkChan chan checkUpData, wg *sync.WaitGroup) {
	tablesFields := map[string]string{}
	namesStmts := map[string]string{
		"update": "UPDATE ip SET responsive=? WHERE id=?",
	}

	netWriter(db, checkChan, wg, tablesFields, namesStmts, checkUpWorker, checkUpWrite)
}

func rndsWriter(db *sql.DB, ipChan chan fieldData, wg *sync.WaitGroup) {
	tablesFields := map[string]string{
		"ip":   "address",
		"name": "name",
	}
	namesStmts := map[string]string{
		"name_to_rdns": "UPDATE name SET is_rdns=TRUE WHERE id=?",
		"rdns":         "INSERT OR IGNORE INTO rdns (ip_id, name_id) VALUES(?, ?)",
		"mapped":       "UPDATE ip SET rdns_mapped=TRUE WHERE id=?",
	}

	netWriter(db, ipChan, wg, tablesFields, namesStmts, rdnsWorker, rdnsWrite)
}

func rdnsWrite(tableMap TableMap, stmtMap StmtMap, fdr fdResults) {
	ipID := fdr.id

	for _, name := range fdr.results {
		nameID := tableMap.get("name", name)

		stmtMap.exec("name_to_rdns", nameID)
		stmtMap.exec("rdns", ipID, nameID)
	}

	stmtMap.exec("mapped", ipID)
}

func nsWrite(tableMap TableMap, stmtMap StmtMap, nsd fdResults) {
	zoneID := nsd.id

	if len(nsd.results) > 0 {
		stmtMap.exec("registered", zoneID)

		for _, ns := range nsd.results {
			nsID := tableMap.get("name", ns)

			stmtMap.exec("nameToNS", nsID)
			stmtMap.exec("insert", zoneID, nsID)
			stmtMap.exec("selfZone", zoneID, nsID)
		}
	}

	stmtMap.exec("update", zoneID)
}

func ipWrite(tableMap TableMap, stmtMap StmtMap, ad addrData) {
	nameID := ad.id
	registered := ad.registered

	if len(ad.cnames) > 0 {
		fmt.Printf("cname from address %s\n", ad.name)
		stmtMap.exec("cname", registered, nameID)

		for _, entry := range ad.cnames {
			srcID := tableMap.get("name", entry.source)
			targetID := tableMap.get("name", entry.target)

			stmtMap.exec("cnameEntry", srcID, targetID)
			if !registered {
				stmtMap.exec("cname_unreg", srcID)
			}
		}
	}

	for _, ip := range ad.results {
		ipID := tableMap.get("ip", ip)

		stmtMap.exec("insert", nameID, ipID)
		stmtMap.exec("updateNameIP", nameID, ipID)
	}

	stmtMap.exec("update", registered, nameID)
}

func mxWrite(tableMap TableMap, stmtMap StmtMap, mxd mxData) {
	zoneID := mxd.zoneID

	for _, datum := range mxd.data {
		mxID := tableMap.get("name", datum.address)
		stmtMap.exec("nameToMX", mxID)
		stmtMap.exec("insert", zoneID, mxID, datum.preference)
	}

	stmtMap.exec("update", mxd.registered, zoneID)
}

func checkUpWrite(tableMap TableMap, stmtMap StmtMap, cu checkUpData) {
	stmtMap.exec("update", cu.success, cu.ipID)
}

func checkUpReader(db *sql.DB, checkChan chan checkUpData, wg *sync.WaitGroup) {
	// each NS IP and one zone it is meant to serve
	tx, err := db.Begin()
	check(err)
	rows, err := tx.Query(`
		SELECT DISTINCT ip.address, zone.name, ip.id
		FROM zone_ns
		INNER JOIN name AS zone ON zone_ns.zone_id = zone.id
		INNER JOIN name_ip ON name_ip.name_id = zone_ns.ns_id
		INNER JOIN ip ON name_ip.ip_id = ip.id
		WHERE ip.address LIKE '%.%' AND ip.resp_checked=FALSE AND zone.is_zone=TRUE
		GROUP BY ip.id
	`)
	check(err)

	for rows.Next() {
		var ip, zone string
		var ipID int64
		check(rows.Scan(&ip, &zone, &ipID))
		wg.Add(1)
		checkChan <- checkUpData{
			ns:   net.JoinHostPort(ip, "53"),
			zone: zone,
			ipID: ipID,
		}
	}

	check(rows.Close())
	check(tx.Commit())
	wg.Wait()
	close(checkChan)
}

func zoneIPReader(db *sql.DB, zipChan chan zoneIP, wg *sync.WaitGroup, extraFilter string) {
	qs := fmt.Sprintf(`
		SELECT DISTINCT zone.name, ip.address, zone.id, ip.id
		FROM zone_ns
		INNER JOIN name_ip ON zone_ns.ns_id = name_ip.name_id
		INNER JOIN ip ON name_ip.ip_id = ip.id
		INNER JOIN name AS zone ON zone_ns.zone_id = zone.id
		WHERE ip.responsive=TRUE %s
	`, extraFilter)

	tx, err := db.Begin()
	check(err)
	rows, err := tx.Query(qs)
	check(err)

	for rows.Next() {
		var zone, ip fieldData
		check(rows.Scan(&zone.name, &ip.name, &zone.id, &ip.id))
		ip.name = net.JoinHostPort(ip.name, "53")
		zipChan <- zoneIP{zone: zone, ip: ip}
		wg.Add(1)
	}

	check(rows.Close())
	check(tx.Commit())
	wg.Wait()
	close(zipChan)
}

func nsIPAdderWorker(db *sql.DB, zoneChan chan fieldData, withNSChan chan fdResults) {
	tx, err := db.Begin()
	check(err)

	nsCache := getFDCache(`
		SELECT DISTINCT ip.address || ':53', ip.id
		FROM name AS zone
		INNER JOIN zone_tld ON zone_tld.zone_id = zone.id
		INNER JOIN name AS tld ON zone_tld.tld_id = tld.id
		INNER JOIN zone_ns ON zone_ns.zone_id = tld.id
		INNER JOIN name_ip ON zone_ns.ns_id = name_ip.name_id
		INNER JOIN ip ON name_ip.ip_id = ip.id
		WHERE zone.name=?
	`, tx)

	for zd := range zoneChan {
		withNSChan <- fdResults{fieldData: zd, results: nsCache.getName(zd.name)}
	}

	close(withNSChan)
	nsCache.clear()
	check(tx.Commit())
}

func parentNSWriter(db *sql.DB, zoneChan chan fieldData, wg *sync.WaitGroup) {
	tablesFields := map[string]string{
		"name": "name",
		"ip":   "address",
	}
	namesStmts := map[string]string{
		"insertNameIP": "INSERT OR IGNORE INTO name_ip (name_id, ip_id) VALUES (?, ?)",
		"updateNameIP": "UPDATE name_ip SET in_parent_zone_glue=TRUE WHERE name_id=? AND ip_id=?",
		"insertZoneNS": "INSERT OR IGNORE INTO zone_ns (zone_id, ns_id) VALUES (?, ?)",
		"updateZoneNS": "UPDATE zone_ns SET in_parent_zone=TRUE WHERE zone_id=? AND ns_id=?",
		"nameToNS":     "UPDATE name SET is_ns=TRUE WHERE id=?",
		"registered":   "UPDATE name SET registered=TRUE, reg_checked=TRUE WHERE id=?",
		"fetched":      "UPDATE name SET glue_ns=TRUE WHERE id=?",
	}

	withNSChan := make(chan fdResults, BUFLEN)
	go nsIPAdderWorker(db, zoneChan, withNSChan)

	netWriter(db, withNSChan, wg, tablesFields, namesStmts, parentNSResolverWorker, parentNSWrite)
}

func parentNSWrite(tableMap TableMap, stmtMap StmtMap, nsr parentNSResults) {
	zoneID := nsr.id

	if len(nsr.ipEntries)+len(nsr.nsEntries) > 0 {
		stmtMap.exec("registered", zoneID)

		for _, ipEntry := range nsr.ipEntries {
			nameID := tableMap.get("name", ipEntry.key)
			ipID := tableMap.get("ip", ipEntry.value)

			stmtMap.exec("insertNameIP", nameID, ipID)
			stmtMap.exec("updateNameIP", nameID, ipID)
		}

		for _, nsEntry := range nsr.nsEntries {
			nsID := tableMap.get("name", nsEntry.key)

			stmtMap.exec("nameToNS", nsID)
			stmtMap.exec("insertZoneNS", zoneID, nsID)
			stmtMap.exec("updateZoneNS", zoneID, nsID)
		}
	}

	stmtMap.exec("fetched", zoneID)
}

func readerWriter[inType any](msg string, db *sql.DB, readerF func(db *sql.DB, inChan chan inType, wg *sync.WaitGroup), writerF func(db *sql.DB, inChan chan inType, wg *sync.WaitGroup)) {
	fmt.Println(msg)

	var wg sync.WaitGroup
	inChan := make(chan inType, BUFLEN)

	go readerF(db, inChan, &wg)
	writerF(db, inChan, &wg)
}

func resolveMX(db *sql.DB) {
	readerWriter("resolving zone MX records", db, func(db *sql.DB, zoneChan chan fieldData, wg *sync.WaitGroup) {
		netZoneReader(db, zoneChan, wg, "AND zone.mx_resolved=FALSE")
	}, mxWriter)
}

func netNS(db *sql.DB) {
	readerWriter("Adding zone NS mappings from the internet", db, func(db *sql.DB, zoneChan chan fieldData, wg *sync.WaitGroup) {
		netZoneReader(db, zoneChan, wg, "AND zone.ns_resolved=FALSE")
	}, netNSWriter)
}

func netIP(db *sql.DB) {
	readerWriter("Adding name-IP mappings from the internet", db, netResolvableReader, netIPWriter)
}

func checkUp(db *sql.DB) {
	readerWriter("Checking for active NSes", db, checkUpReader, checkUpWriter)
}

func getParentNS(db *sql.DB) {
	readerWriter("getting NS records from parent zone", db, func(db *sql.DB, zoneChan chan fieldData, wg *sync.WaitGroup) {
		netZoneReader(db, zoneChan, wg, "AND glue_ns=FALSE")
	}, parentNSWriter)
}

func rdns(db *sql.DB) {
	readerWriter("getting rDNS results for IPs", db, rdnsIPReader, rndsWriter)
}
