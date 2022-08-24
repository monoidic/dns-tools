package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/monoidic/dns"
)

type tableWorkerF[inType any, resultType any] func(inChan <-chan inType, outChan chan<- resultType, wg *sync.WaitGroup, tableMap TableMap, stmtMap StmtMap, once *sync.Once)
type netWorkerF[inType any, resultType any] func(inChan <-chan inType, outChan chan<- resultType, wg *sync.WaitGroup, once *sync.Once)
type insertF[resultType any] func(tableMap TableMap, stmtMap StmtMap, datum resultType)
type readerF[inType any] func(db *sql.DB, inChan chan<- inType, wg *sync.WaitGroup)
type readerRecurseF[inType any] func(db *sql.DB, inChan chan<- inType, anyResponsesChan chan<- bool, wg *sync.WaitGroup)
type writerF[inType any] func(db *sql.DB, inChan <-chan inType, wg *sync.WaitGroup)
type processDataF[inType any, resultType any] func(c connCache, msg dns.Msg, fd inType) resultType

type mxData struct {
	rrResults[dns.MX]
	registered bool
}

type fieldData struct {
	name string
	id   int64
}

type rrResults[rr any] struct {
	fieldData
	results []rr
}

type fdResults struct {
	fieldData
	results []string
}

type addrData struct {
	fieldData
	a          []dns.A
	aaaa       []dns.AAAA
	cname      []dns.CNAME
	registered bool
}

type parentNSResults struct {
	fieldData
	ns   []dns.NS
	a    []dns.A
	aaaa []dns.AAAA
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
	tcpCache := ttlcache.New(ttlOption, tcpCacheF)
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
		udpCache = ttlcache.New(ttlOption, udpCacheF)
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
	cache := ttlcache.New(cookieF, ttlOption)
	go cache.Start()
	return cache
}

func getNull[T any](cache *ttlcache.Cache[string, T], key string) T {
	var value T
	if item := cache.Get(key); item != nil {
		value = item.Value()
	}
	return value
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
	for _, rr := range opt.Option {
		switch rrT := rr.(type) {
		case *dns.EDNS0_COOKIE:
			return rrT
		}
	}

	oCookie := &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE}
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
			if conn, err = client.Dial(host); err == nil {
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

			if cookie, err := fetchCookie(msg, client, conn); err == nil {
				return c.Set(host, cookie, ttlcache.DefaultTTL)
			}
			protoCache.Delete(host)
		}

		return nil
	}))
}

func fetchCookie(msg dns.Msg, client *dns.Client, conn *dns.Conn) (cookie string, err error) {
	if res, _, err := client.ExchangeWithConn(&msg, conn); err == nil {
		return cookieFromMsg(*res), nil
	} else {
		return "", err
	}
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
		// fmt.Printf("failed to fetch response from %s over UDP: %v\n", nameserver, err)
		if res, err = connCache.tcpExchange(nameserver, msg); err != nil {
			// fmt.Printf("failed to fetch response from %s over TCP: %v\n", nameserver, err)
			return nil, err
		}
	}

	return res, nil
}

func setOpt(msg *dns.Msg) *dns.OPT {
	if len(msg.Extra) > 0 {
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

func resolverWorker[inType, resultType any](inChan <-chan inType, outChan chan<- resultType, msg dns.Msg, processData processDataF[inType, resultType], wg *sync.WaitGroup, once *sync.Once) {
	connCache := getConnCache()

	// t := TIMEOUT
	// client.DialTimeout = t
	// client.ReadTimeout = t
	// client.WriteTimeout = t

	for fd := range inChan {
		outChan <- processData(connCache, msg, fd)
	}

	connCache.clear()
	wg.Done()
	wg.Wait()
	once.Do(func() { close(outChan) })
}

func nsResolverWorker(inChan <-chan fieldData, outChan chan<- rrResults[dns.NS], wg *sync.WaitGroup, once *sync.Once) {
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

func mxResolverWorker(inChan <-chan fieldData, outChan chan<- mxData, wg *sync.WaitGroup, once *sync.Once) {
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

func addrResolverWorker(inChan <-chan fieldData, outChan chan<- addrData, wg *sync.WaitGroup, once *sync.Once) {
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

func parentCheckWorker(inChan <-chan childParent, outChan chan<- childParent, wg *sync.WaitGroup, tableMap TableMap, _ StmtMap, once *sync.Once) {
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

	workerInChan := make(chan childParent, MIDBUFLEN)
	go parentCheckFilter(inChan, workerInChan, tableMap)

	resolverWorker(workerInChan, outChan, msg, parentCheckResolve, wg, once)
}

// bypass resolver if already in DB
func parentCheckFilter(inChan <-chan childParent, workerInChan chan<- childParent, tableMap TableMap) {
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

func checkUpWorker(inChan <-chan checkUpData, outChan chan<- checkUpData, wg *sync.WaitGroup, once *sync.Once) {
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

func rdnsWorker(inChan <-chan fieldData, outChan chan<- rrResults[dns.PTR], wg *sync.WaitGroup, once *sync.Once) {
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

func txtWorker(inChan <-chan fieldData, outChan chan<- fdResults, wg *sync.WaitGroup, once *sync.Once) {
	msg := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Opcode:           dns.OpcodeQuery,
			RecursionDesired: true,
			Rcode:            dns.RcodeSuccess,
		},
		Question: []dns.Question{{
			Qclass: dns.ClassINET,
			Qtype:  dns.TypeTXT,
		}},
	}
	msgSetSize(&msg)

	resolverWorker(inChan, outChan, msg, txtResolve, wg, once)
}

func parentNSResolverWorker(inChan <-chan fdResults, outChan chan<- parentNSResults, wg *sync.WaitGroup, once *sync.Once) {
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

func nsecWalkResultResolver(inChan <-chan rrDBData, outChan chan<- nsecWalkResolveRes, wg *sync.WaitGroup, once *sync.Once) {
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

	resolverWorker(inChan, outChan, msg, nsecWalkResultResolve, wg, once)
}

func nsecWalkResultResolve(connCache connCache, msg dns.Msg, rrD rrDBData) (res nsecWalkResolveRes) {
	msg.Question[0].Name = rrD.rrName.name
	msg.Question[0].Qtype = dns.StringToType[rrD.rrType.name]

	var response *dns.Msg
	var err error

	for i := 0; i < RETRIES; i++ {
		nameserver := usedNs[rand.Intn(usedNsLen)]
		if response, err = plainResolve(msg, connCache, nameserver); err == nil {
			break
		}
	}

	res.rrDBData = rrD

	if response == nil {
		return res
	}

	res.results = make([]rrData, len(response.Answer))

	for i, rr := range response.Answer {
		normalizeRR(rr)
		hdr := rr.Header()
		resRRD := rrData{
			rrValue: rr.String(),
			rrType:  dns.TypeToString[hdr.Rrtype],
			rrName:  hdr.Name,
		}
		res.results[i] = resRRD
	}

	return res
}

func nsResolve(connCache connCache, msg dns.Msg, fd fieldData) rrResults[dns.NS] {
	msg.Question[0].Name = dns.Fqdn(fd.name)
	var response *dns.Msg
	var results []dns.NS
	var err error

	for i := 0; i < RETRIES; i++ {
		nameserver := usedNs[rand.Intn(usedNsLen)]
		if response, err = plainResolve(msg, connCache, nameserver); err == nil {
			break
		}
	}

	if response != nil {
		for _, rr := range response.Answer {
			switch rrT := rr.(type) {
			case *dns.NS:
				results = append(results, *rrT)
			}
		}
	}

	return rrResults[dns.NS]{fieldData: fd, results: results}
}

func mxResolve(connCache connCache, msg dns.Msg, fd fieldData) mxData {
	msg.Question[0].Name = dns.Fqdn(fd.name)
	var response *dns.Msg
	var results []dns.MX
	var err error
	registered := true

	for i := 0; i < RETRIES; i++ {
		nameserver := usedNs[rand.Intn(usedNsLen)]
		if response, err = plainResolve(msg, connCache, nameserver); err == nil {
			break
		}
	}

	if response != nil {
		for _, rr := range response.Answer {
			switch rrT := rr.(type) {
			case *dns.MX:
				normalizeRR(rrT)
				results = append(results, *rrT)
			}
		}
		registered = response.Rcode != dns.RcodeNameError
	}

	return mxData{rrResults: rrResults[dns.MX]{results: results, fieldData: fd}, registered: registered}
}

func addrResolve(connCache connCache, msg dns.Msg, fd fieldData) addrData {
	msg.Question[0].Name = dns.Fqdn(fd.name)

	var cname []dns.CNAME
	var a []dns.A
	var aaaa []dns.AAAA
	var err error
	registered := true

	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		msg.Question[0].Qtype = qtype
		var response *dns.Msg

		for i := 0; i < RETRIES; i++ {
			nameserver := usedNs[rand.Intn(usedNsLen)]
			if response, err = plainResolve(msg, connCache, nameserver); err == nil {
				break
			}
		}

		if response != nil {
			for _, rr := range response.Answer {
				switch rrT := rr.(type) {
				case *dns.A:
					normalizeRR(rrT)
					a = append(a, *rrT)
				case *dns.AAAA:
					normalizeRR(rrT)
					aaaa = append(aaaa, *rrT)
				case *dns.CNAME:
					normalizeRR(rrT)
					cname = append(cname, *rrT)
				}
			}

			registered = response.Rcode != dns.RcodeNameError
		}
	}

	return addrData{fieldData: fd, a: a, aaaa: aaaa, cname: cname, registered: registered}
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
		normalizeRR(soa)
		realParent := soa.Hdr.Name
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
	}

	return cu
}

func rdnsResolve(connCache connCache, msg dns.Msg, fd fieldData) rrResults[dns.PTR] {
	msg.Question[0].Name = check1(dns.ReverseAddr(fd.name))
	var res *dns.Msg
	var results []dns.PTR

	for i := 0; i < RETRIES; i++ {
		var err error
		nameserver := usedNs[rand.Intn(usedNsLen)]
		res, err = plainResolve(msg, connCache, nameserver)
		if err == nil {
			break
		}
	}

	if res != nil {
		for _, rr := range res.Answer {
			switch rrT := rr.(type) {
			case *dns.PTR:
				normalizeRR(rrT)
				results = append(results, *rrT)
			}
		}
	}

	return rrResults[dns.PTR]{fieldData: fd, results: results}
}

func txtResolve(connCache connCache, msg dns.Msg, fd fieldData) fdResults {
	msg.Question[0].Name = dns.Fqdn(fd.name)
	var results []string
	var res *dns.Msg

	for i := 0; i < RETRIES; i++ {
		var err error
		nameserver := usedNs[rand.Intn(usedNsLen)]
		res, err = plainResolve(msg, connCache, nameserver)
		if err == nil {
			break
		}
	}

	if res != nil {
		for _, rr := range res.Answer {
			switch rrT := rr.(type) {
			case *dns.TXT:
				results = append(results, strings.Join(rrT.Txt, ""))
			}
		}
	}
	return fdResults{fieldData: fd, results: results}
}

func parentNsResolve(connCache connCache, msg dns.Msg, fdr fdResults) parentNSResults {
	msg.Question[0].Name = dns.Fqdn(fdr.name)
	var nsResults []dns.NS
	var aResults []dns.A
	var aaaaResults []dns.AAAA

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
			}
		}

		if response != nil {
			for _, rr := range response.Ns {
				switch rrT := rr.(type) {
				case *dns.NS:
					normalizeRR(rrT)
					nsResults = append(nsResults, *rrT)
				}
			}

			for _, rr := range response.Extra {
				switch rrT := rr.(type) {
				case *dns.A:
					normalizeRR(rrT)
					aResults = append(aResults, *rrT)
				case *dns.AAAA:
					normalizeRR(rrT)
					aaaaResults = append(aaaaResults, *rrT)
				}
			}
		}
	}

	return parentNSResults{fieldData: fdr.fieldData, ns: nsResults, a: aResults, aaaa: aaaaResults}
}

func netWriterTable[inType any, resultType any](db *sql.DB, inChan <-chan inType, wg *sync.WaitGroup, tablesFields, namesStmts map[string]string, workerF tableWorkerF[inType, resultType], insertF insertF[resultType]) {
	numProcs := 64

	dataOutChan := make(chan resultType, BUFLEN)

	var once sync.Once
	var workerWg sync.WaitGroup

	tx := check1(db.Begin())

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
			tx = check1(db.Begin())

			tableMap.update(tx)
			stmtMap.update(tx)

			stmtMap.mx.Unlock()
			tableMap.mx.Unlock()
		}
		i--

		insertF(tableMap, stmtMap, datum)
		wg.Done()
	}

	tableMap.clear()
	stmtMap.clear()
	check(tx.Commit())
}

func netWriter[inType any, resultType any](db *sql.DB, inChan <-chan inType, wg *sync.WaitGroup, tablesFields, namesStmts map[string]string, workerF netWorkerF[inType, resultType], insertF insertF[resultType]) {
	netWriterTable(db, inChan, wg, tablesFields, namesStmts, func(inChan <-chan inType, outChan chan<- resultType, wg *sync.WaitGroup, _ TableMap, _ StmtMap, once *sync.Once) {
		workerF(inChan, outChan, wg, once)
	}, insertF)
}

func netNSWriter(db *sql.DB, zoneChan <-chan fieldData, wg *sync.WaitGroup) {
	tablesFields := map[string]string{
		"name":     "name",
		"rr_type":  "name",
		"rr_name":  "name",
		"rr_value": "value",
	}
	namesStmts := map[string]string{
		"insert":     "INSERT INTO zone_ns (zone_id, ns_id, in_self_zone) VALUES (?, ?, TRUE) ON CONFLICT DO UPDATE SET in_self_zone=TRUE",
		"update":     "UPDATE name SET ns_resolved=TRUE WHERE id=?",
		"registered": "UPDATE name SET registered=TRUE, reg_checked=TRUE WHERE id=?",
		"zone2rr":    "INSERT INTO zone2rr (zone_id, rr_type_id, rr_name_id, rr_value_id, inserted) VALUES (?, ?, ?, ?, TRUE) ON CONFLICT DO UPDATE SET inserted=TRUE",
	}

	netWriter(db, zoneChan, wg, tablesFields, namesStmts, nsResolverWorker, nsWrite)
}

func nsWrite(tableMap TableMap, stmtMap StmtMap, nsd rrResults[dns.NS]) {
	zoneID := nsd.id

	if len(nsd.results) > 0 {
		stmtMap.exec("registered", zoneID)
		rrTypeID := tableMap.get("rr_type", "NS")
		rrNameID := tableMap.get("rr_name", nsd.name)

		for _, ns := range nsd.results {
			normalizeRR(&ns)
			nsID := tableMap.get("name", ns.Ns)

			stmtMap.exec("insert", zoneID, nsID)

			rrValueID := tableMap.get("rr_value", ns.String())
			stmtMap.exec("zone2rr", zoneID, rrTypeID, rrNameID, rrValueID)
		}
	}

	stmtMap.exec("update", zoneID)
}

func netIPWriter(db *sql.DB, nameChan <-chan fieldData, wg *sync.WaitGroup) {
	tablesFields := map[string]string{
		"ip":   "address",
		"name": "name",
	}
	namesStmts := map[string]string{
		// TODO zone2rr
		// "zone2rr":          "INSERT OR IGNORE INTO zone2rr (zone_id, rr_type_id, rr_name_id, rr_value_id) VALUES (?, ?, ?, ?)",
		// "zone2rr_inserted": "UPDATE zone2rr SET inserted=TRUE WHERE zone_id=? AND rr_type_id=? AND rr_name_id=? AND rr_value_id=?",
		"insert":      "INSERT INTO name_ip (name_id, ip_id, in_self_zone) VALUES (?, ?, TRUE) ON CONFLICT DO UPDATE SET in_self_zone=TRUE",
		"update":      "UPDATE name SET addr_resolved=TRUE, valid_tried=TRUE, reg_checked=TRUE, registered=? WHERE id=?",
		"cname_entry": "UPDATE name SET reg_checked=TRUE, registered=?, cname_tgt_id=? WHERE id=?",
	}

	netWriter(db, nameChan, wg, tablesFields, namesStmts, addrResolverWorker, ipWrite)
}

func ipWrite(tableMap TableMap, stmtMap StmtMap, ad addrData) {
	nameID := ad.id
	registered := ad.registered

	if len(ad.cname) > 0 {
		fmt.Printf("cname from address %s\n", ad.name)

		for _, entry := range ad.cname {
			srcID := tableMap.get("name", entry.Hdr.Name)
			targetID := tableMap.get("name", entry.Target)

			stmtMap.exec("cname_entry", registered, targetID, srcID)
		}
	}

	for _, a := range ad.a {
		ipID := tableMap.get("ip", a.A.String())

		stmtMap.exec("insert", nameID, ipID)
	}

	for _, aaaa := range ad.aaaa {
		ipID := tableMap.get("ip", aaaa.AAAA.String())

		stmtMap.exec("insert", nameID, ipID)
	}

	stmtMap.exec("update", registered, nameID)
}

func mxWriter(db *sql.DB, zoneChan <-chan fieldData, wg *sync.WaitGroup) {
	tablesFields := map[string]string{
		"name":     "name",
		"rr_type":  "name",
		"rr_name":  "name",
		"rr_value": "value",
	}
	namesStmts := map[string]string{
		"zone2rr": "INSERT OR IGNORE INTO zone2rr (zone_id, rr_type_id, rr_name_id, rr_value_id) VALUES (?, ?, ?, ?)",
		"update":  "UPDATE name SET mx_resolved=TRUE, reg_checked=TRUE, registered=? WHERE id=?",
	}

	netWriter(db, zoneChan, wg, tablesFields, namesStmts, mxResolverWorker, mxWrite)
}

func mxWrite(tableMap TableMap, stmtMap StmtMap, mxd mxData) {
	zoneID := mxd.id

	if len(mxd.results) > 0 {
		rrTypeID := tableMap.get("rr_type", "MX")
		rrNameID := tableMap.get("rr_name", mxd.name)

		for _, mx := range mxd.results {
			rrValueID := tableMap.get("rr_value", mx.String())
			stmtMap.exec("zone2rr", zoneID, rrTypeID, rrNameID, rrValueID)
		}
	}

	stmtMap.exec("update", mxd.registered, zoneID)
}

func checkUpWriter(db *sql.DB, checkChan <-chan checkUpData, wg *sync.WaitGroup) {
	tablesFields := map[string]string{}
	namesStmts := map[string]string{
		"update": "UPDATE ip SET responsive=?, resp_checked=TRUE WHERE id=?",
	}

	netWriter(db, checkChan, wg, tablesFields, namesStmts, checkUpWorker, checkUpWrite)
}

func checkUpWrite(_ TableMap, stmtMap StmtMap, cu checkUpData) {
	stmtMap.exec("update", cu.success, cu.ipID)
}

func rdnsWriter(db *sql.DB, ipChan <-chan fieldData, wg *sync.WaitGroup) {
	tablesFields := map[string]string{
		"name":     "name",
		"rr_type":  "name",
		"rr_name":  "name",
		"rr_value": "value",
	}
	namesStmts := map[string]string{
		"zone2rr": "INSERT OR IGNORE INTO zone2rr (zone_id, rr_type_id, rr_name_id, rr_value_id) VALUES (?, ?, ?, ?)",
		"mapped":  "UPDATE ip SET rdns_mapped=TRUE WHERE id=?",
	}

	netWriter(db, ipChan, wg, tablesFields, namesStmts, rdnsWorker, rdnsWrite)
}

func rdnsWrite(tableMap TableMap, stmtMap StmtMap, fdr rrResults[dns.PTR]) {
	ipID := fdr.id

	if len(fdr.results) > 0 {
		rrTypeID := tableMap.get("rr_type", "PTR")

		for _, ptr := range fdr.results {
			rrNameID := tableMap.get("rr_name", ptr.Hdr.Name)
			rrValueID := tableMap.get("rr_value", ptr.String())

			stmtMap.exec("zone2rr", fdr.id, rrTypeID, rrNameID, rrValueID)
		}
	}

	stmtMap.exec("mapped", ipID)
}

func spfRRWriter(db *sql.DB, fdChan <-chan fieldData, wg *sync.WaitGroup) {
	tablesFields := map[string]string{
		"name":       "name",
		"spf_record": "value",
	}
	namesStmts := map[string]string{
		"spf":       "INSERT OR IGNORE INTO spf (name_id, spf_record_id) VALUES (?, ?)",
		"spfname":   "INSERT INTO spf_name (name_id, spf_id, spfname) VALUES (?, (SELECT id FROM spf WHERE name_id=? AND spf_record_id=?), ?) ON CONFLICT DO UPDATE SET spfname=spfname|excluded.spfname",
		"txt_tried": "UPDATE name SET txt_tried=TRUE WHERE id=?",
		"spf_valid": "UPDATE spf_record SET valid=?, any_unknown=? WHERE id=?",
	}

	netWriter(db, fdChan, wg, tablesFields, namesStmts, txtWorker, spfWrite)
}

func spfWrite(tableMap TableMap, stmtMap StmtMap, fdr fdResults) {
	nameID := fdr.id

	for _, s := range fdr.results {
		if strings.HasPrefix(s, "v=spf1") {
			recordID := tableMap.get("spf_record", s)
			stmtMap.exec("spf", nameID, recordID)

			data, err := parseSPF([]byte(s))
			stmtMap.exec("spf_valid", err == nil, data.anyUnknown, recordID)
			if err == nil {
				for _, name := range data.names {
					spfNameID := tableMap.get("name", name)
					stmtMap.exec("spfname", spfNameID, nameID, recordID, false)
				}
				for _, name := range data.spfNames {
					spfNameID := tableMap.get("name", name)
					stmtMap.exec("spfname", spfNameID, nameID, recordID, true)
				}
			}
		}
	}

	stmtMap.exec("txt_tried", nameID)
}

func checkUpReader(db *sql.DB, checkChan chan<- checkUpData, wg *sync.WaitGroup) {
	// each NS IP and one zone it is meant to serve
	tx := check1(db.Begin())
	var v4Filter string
	if !v6 {
		v4Filter = `AND ip.address LIKE '%.%'`
	}
	rows := check1(tx.Query(fmt.Sprintf(`
		SELECT DISTINCT ip.address, zone.name, ip.id
		FROM zone_ns
		INNER JOIN name AS zone ON zone_ns.zone_id = zone.id
		INNER JOIN name_ip ON name_ip.name_id = zone_ns.ns_id
		INNER JOIN ip ON name_ip.ip_id = ip.id
		WHERE ip.resp_checked=FALSE AND zone.is_zone=TRUE %s
		GROUP BY ip.id
	`, v4Filter)))

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

func zoneIPReader(db *sql.DB, zipChan chan<- zoneIP, wg *sync.WaitGroup, extraFilter string) {
	qs := fmt.Sprintf(`
		SELECT DISTINCT zone.name, ip.address, zone.id, ip.id
		FROM zone_ns
		INNER JOIN name_ip ON zone_ns.ns_id = name_ip.name_id
		INNER JOIN ip ON name_ip.ip_id = ip.id
		INNER JOIN name AS zone ON zone_ns.zone_id = zone.id
		WHERE ip.responsive=TRUE %s
	`, extraFilter)

	tx := check1(db.Begin())
	rows := check1(tx.Query(qs))

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

func nsIPAdderWorker(db *sql.DB, zoneChan <-chan fieldData, withNSChan chan<- fdResults) {
	tx := check1(db.Begin())

	nsCache := getFDCache(`
		SELECT DISTINCT ip.address || ':53', ip.id
		FROM name AS child
		INNER JOIN zone_ns ON zone_ns.zone_id = child.parent_id
		INNER JOIN name_ip ON zone_ns.ns_id = name_ip.name_id
		INNER JOIN ip ON name_ip.ip_id = ip.id
		WHERE child.name=?
	`, tx)

	for zd := range zoneChan {
		withNSChan <- fdResults{fieldData: zd, results: nsCache.getName(zd.name)}
	}

	close(withNSChan)
	nsCache.clear()
	check(tx.Commit())
}

func parentNSWriter(db *sql.DB, zoneChan <-chan fieldData, wg *sync.WaitGroup) {
	tablesFields := map[string]string{
		"name": "name",
		"ip":   "address",
	}
	namesStmts := map[string]string{
		"insert_name_ip": "INSERT INTO name_ip (name_id, ip_id, in_parent_zone_glue) VALUES (?, ?, TRUE) ON CONFLICT DO UPDATE SET in_parent_zone_glue=TRUE",
		"insert_zone_ns": "INSERT INTO zone_ns (zone_id, ns_id, in_parent_zone) VALUES (?, ?, TRUE) ON CONFLICT DO UPDATE SET in_parent_zone=TRUE",
		"name_to_ns":     "UPDATE name SET is_ns=TRUE WHERE id=?",
		"registered":     "UPDATE name SET registered=TRUE, reg_checked=TRUE WHERE id=?",
		"fetched":        "UPDATE name SET glue_ns=TRUE WHERE id=?",
	}

	withNSChan := make(chan fdResults, MIDBUFLEN)
	go nsIPAdderWorker(db, zoneChan, withNSChan)

	netWriter(db, withNSChan, wg, tablesFields, namesStmts, parentNSResolverWorker, parentNSWrite)
}

func parentNSWrite(tableMap TableMap, stmtMap StmtMap, nsr parentNSResults) {
	zoneID := nsr.id

	if len(nsr.ns) > 0 {
		stmtMap.exec("registered", zoneID)

		for _, a := range nsr.a {
			nameID := tableMap.get("name", a.Hdr.Name)
			ipID := tableMap.get("ip", a.A.String())
			stmtMap.exec("insert_name_ip", nameID, ipID)
		}

		for _, aaaa := range nsr.aaaa {
			nameID := tableMap.get("name", aaaa.Hdr.Name)
			ipID := tableMap.get("ip", aaaa.AAAA.String())
			stmtMap.exec("insert_name_ip", nameID, ipID)
		}

		for _, ns := range nsr.ns {
			nsID := tableMap.get("name", ns.Ns)
			stmtMap.exec("name_to_ns", nsID)
			stmtMap.exec("insert_zone_ns", zoneID, nsID)
		}
	}

	stmtMap.exec("fetched", zoneID)
}

func readerWriter[inType any](msg string, db *sql.DB, readerF readerF[inType], writerF writerF[inType]) {
	fmt.Println(msg)

	var wg sync.WaitGroup
	inChan := make(chan inType, BUFLEN)

	go readerF(db, inChan, &wg)
	writerF(db, inChan, &wg)
}

func netZoneReaderGen(filter string) func(*sql.DB, chan<- fieldData, *sync.WaitGroup) {
	return func(db *sql.DB, zoneChan chan<- fieldData, wg *sync.WaitGroup) {
		netZoneReader(db, zoneChan, wg, filter)
	}
}

func resolveMX(db *sql.DB) {
	readerWriter("resolving zone MX records", db, netZoneReaderGen("AND zone.mx_resolved=FALSE"), mxWriter)
}

func netNS(db *sql.DB) {
	readerWriter("Adding zone NS mappings from the internet", db, netZoneReaderGen("AND zone.ns_resolved=FALSE"), netNSWriter)
}

func netIP(db *sql.DB) {
	readerWriter("Adding name-IP mappings from the internet", db, netResolvableReader, netIPWriter)
}

func checkUp(db *sql.DB) {
	readerWriter("Checking for active NSes", db, checkUpReader, checkUpWriter)
}

func getParentNS(db *sql.DB) {
	var v4Filter string
	if !v6 {
		v4Filter = `AND ip.address LIKE '%.%'`
	}
	filter := fmt.Sprintf("AND glue_ns=FALSE %s", v4Filter)
	readerWriter("getting NS records from parent zone", db, netZoneReaderGen(filter), parentNSWriter)
}

func rdns(db *sql.DB) {
	readerWriter("getting rDNS results for IPs", db, rdnsIPReader, rdnsWriter)
}

func spf(db *sql.DB) {
	readerWriter("getting potential SPF records", db, getUnqueriedSPF, spfRRWriter)
}

func spfLinks(db *sql.DB) {
	readerWriter("getting linked SPF records", db, getUnqueriedSPFName, spfRRWriter)
}
