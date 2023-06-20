package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/monoidic/dns"
)

type tableWorkerF[inType any, resultType any] func(inChan <-chan inType, outChan chan<- resultType, wg *sync.WaitGroup, tableMap TableMap, stmtMap StmtMap)
type netWorkerF[inType any, resultType any] func(inChan <-chan inType, outChan chan<- resultType, wg *sync.WaitGroup)
type insertF[resultType any] func(tableMap TableMap, stmtMap StmtMap, datum resultType)
type readerF[inType any] func(db *sql.DB, inChan chan<- inType)
type readerRecurseF[inType any] func(db *sql.DB, inChan chan<- inType, anyResponsesChan chan<- bool)
type writerF[inType any] func(db *sql.DB, inChan <-chan inType)
type processDataF[inType any, resultType any] func(c connCache, msg dns.Msg, fd inType) resultType

type mxData struct {
	rrResults[dns.MX]
	registered bool
}

// string-ID pair for common use cases with the database
type fieldData struct {
	name string
	id   int64
}

// generic struct for an RRSET response to some query
type rrResults[rr any] struct {
	fieldData
	results []rr
}

type fdResults struct {
	fieldData
	results []string
}

type chaosResults struct { // name:value responses may have different names than the original queried name
	fieldData
	results []chaosResult
}

type chaosResult struct {
	queried    string
	resultName string
	value      string
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

// simple error struct
type Error struct {
	s string
}

func (e Error) Error() string {
	return e.s
}

// per-worker cache to reduce the number of connections to the same host made per worker
type connCache struct {
	client         *dns.Client
	udpCache       *ttlcache.Cache[string, *dns.Conn]
	tcpCache       *ttlcache.Cache[string, *dns.Conn]
	udpCookieCache *ttlcache.Cache[string, string]
	tcpCookieCache *ttlcache.Cache[string, string]
}

var chaosTXTNames = []string{
	// BIND + many others
	"version.bind.",
	"authors.bind.",
	"hostname.bind.",
	"id.server.",
	// PowerDNS
	"trustanchor.server.",
	"negativetrustanchor.server.",
	"version.pdns.",
	// CoreDNS
	"version.server.",
	// MaraDNS
	"version.maradns.",
	"numthreads.maradns.",
	"memusage.maradns.",
	"timestamp.maradns.",
	"cache-elements.maradns.",
	"0.verbose_level.maradns.",
	"1.verbose_level.maradns.",
	"2.verbose_level.maradns.",
	"3.verbose_level.maradns.",
	"4.verbose_level.maradns.",
	"5.verbose_level.maradns.",
	"6.verbose_level.maradns.",
	"7.verbose_level.maradns.",
	"8.verbose_level.maradns.",
	"9.verbose_level.maradns.",
	// MyDNS
	"version.mydns.",
	// Knot DNS
	"fortune.",
	// DNSmasq
	"cachesize.bind.",
	"insertions.bind.",
	"evictions.bind.",
	"misses.bind.",
	"hits.bind.",
	"auth.bind.",
	"servers.bind.",
	"copyright.bind.",
	// (old?) Windows DNS server peculiarity (responds to anything starting with "versio" with the version)
	"versio.",
}

// set up a connCache
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

// set up a cookie cache for connCache
func getCookieCache(protoCache *ttlcache.Cache[string, *dns.Conn], client *dns.Client) *ttlcache.Cache[string, string] {
	cookieF := cookieGen(protoCache, client)
	ttlOption := ttlcache.WithTTL[string, string](25 * time.Second)
	cache := ttlcache.New(cookieF, ttlOption)
	go cache.Start()
	return cache
}

// get a value from a cache; if it is not present, return the type's zero value
func getNull[T any](cache *ttlcache.Cache[string, T], key string) T {
	var value T
	if item := cache.Get(key); item != nil {
		value = item.Value()
	}
	return value
}

// perform DNS query to the specified hostname, using cookie and connection caches
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
	} else {
		cookie := cookieFromMsg(res) // might be empty
		cookieCache.Set(hostname, cookie, ttlcache.DefaultTTL)
	}

	return res, err
}

// perform DNS query, using caches, with TCP
func (c connCache) tcpExchange(hostname string, msg dns.Msg) (*dns.Msg, error) {
	return exchange(hostname, msg, c.tcpCookieCache, c.tcpCache, c.client)
}

// perform DNS query, using caches, with UDP
func (c connCache) udpExchange(hostname string, msg dns.Msg) (*dns.Msg, error) {
	return exchange(hostname, msg, c.udpCookieCache, c.udpCache, c.client)
}

// check for cookie option in msg, create if missing, an return the message's cookie option
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

// clean up connCache
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

// generate ttlcache.WithLoader function for a given protocol to connect to some host if a connection to a given host is not in the cache
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

// return ttlcache.WithLoader to generate a random DNS client cookie for the cookie cache in connCache
func cookieGen(protoCache *ttlcache.Cache[string, *dns.Conn], client *dns.Client) ttlcache.Option[string, string] {
	bufRand := make([]byte, 8)
	bufStr := make([]byte, 16)
	oRand := rand.New(rand.NewSource(rand.Int63()))

	getRandCookie := func() string {
		oRand.Read(bufRand)
		hex.Encode(bufStr, bufRand)
		return string(bufStr)
	}

	return ttlcache.WithLoader[string, string](ttlcache.LoaderFunc[string, string](func(c *ttlcache.Cache[string, string], host string) *ttlcache.Item[string, string] {
		return c.Set(host, getRandCookie(), ttlcache.DefaultTTL)
	}))
}

// extract cookie from response message
func cookieFromMsg(msg *dns.Msg) string {
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

// close connCache connections on cache eviction
func connCacheEviction(_ context.Context, _ ttlcache.EvictionReason, item *ttlcache.Item[string, *dns.Conn]) {
	item.Value().Close()
}

// perform basic DNS query, optionally with TCP fallback, to a namserver, while using connCache
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

// get or create OPT query to DNS message for edns0
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

// set message size OPT
func msgSetSize(msg *dns.Msg) {
	opt := setOpt(msg)
	opt.SetUDPSize(dns.DefaultMsgSize)
}

// sets up a connCache and reads in messages from inChan, passes them to the specified `processData` function, and passes the output to outChan
func resolverWorker[inType, resultType any](inChan <-chan inType, outChan chan<- resultType, msg dns.Msg, processData processDataF[inType, resultType], wg *sync.WaitGroup) {
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
}

// bypass resolver if direct parent is already in DB
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

// prints a message, creates a channel, reads entries of some type `inType` with a reader function
// from the database into the channel and sends them over a channel to writerF,
// which processes the entries and writes them back to the database
func readerWriter[inType any](msg string, db *sql.DB, readerF readerF[inType], writerF writerF[inType]) {
	fmt.Println(msg)

	inChan := make(chan inType, BUFLEN)

	go readerF(db, inChan)
	writerF(db, inChan)
}

// wrapper for netWriter for the common case of not needing to perform SQL queries within the resolver
func netWriter[inType any, resultType any](db *sql.DB, inChan <-chan inType, tablesFields, namesStmts map[string]string, workerF netWorkerF[inType, resultType], insertF insertF[resultType]) {
	netWriterTable(db, inChan, tablesFields, namesStmts, func(inChan <-chan inType, outChan chan<- resultType, wg *sync.WaitGroup, _ TableMap, _ StmtMap) {
		workerF(inChan, outChan, wg)
	}, insertF)
}

// passes data from inChan (database entries) to `workerF` workers (network resolvers), and passes the output of that (DNS responses) to `insertF`,
// which writes the results to the database
func netWriterTable[inType any, resultType any](db *sql.DB, inChan <-chan inType, tablesFields, namesStmts map[string]string, workerF tableWorkerF[inType, resultType], insertF insertF[resultType]) {
	numProcs := 64

	dataOutChan := make(chan resultType, BUFLEN)

	var workerWg sync.WaitGroup

	tx := check1(db.Begin())

	tableMap := getTableMap(tablesFields, tx)
	stmtMap := getStmtMap(namesStmts, tx)

	workerWg.Add(numProcs)

	for i := 0; i < numProcs; i++ {
		go workerF(inChan, dataOutChan, &workerWg, tableMap, stmtMap)
	}

	go closeChanWait(&workerWg, dataOutChan)

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
	}

	tableMap.clear()
	stmtMap.clear()
	check(tx.Commit())
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
	readerWriter("getting NS records from parent zone", db, netZoneReaderGen("AND glue_ns=FALSE"), parentNSWriter)
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

func dmarc(db *sql.DB) {
	readerWriter("getting potential DMARC records", db, getUnqueriedDMARCWrap, dmarcRRWriter)
}

func chaosTXT(db *sql.DB) {
	readerWriter("performing Chaosnet queries", db, getUnqueriedChaosTXT, chaosTXTWriter)
}
