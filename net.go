package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"iter"
	"math/rand"
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/miekg/dns"
)

type (
	tableWorkerF[inType, resultType, tmpType any]     func(dataChan <-chan retryWrap[inType, tmpType], refeedChan chan<- retryWrap[inType, tmpType], outChan chan<- resultType, wg, retryWg *sync.WaitGroup, tableMap TableMap, stmtMap StmtMap)
	netWorkerF[inType, resultType, tmpType any]       func(dataChan <-chan retryWrap[inType, tmpType], refeedChan chan<- retryWrap[inType, tmpType], outChan chan<- resultType, wg, retryWg *sync.WaitGroup)
	insertF[resultType any]                           func(tableMap TableMap, stmtMap StmtMap, datum resultType)
	readerRecurseF[inType any]                        func(db *sql.DB) (iter.Seq[inType], bool)
	writerF[inType any]                               func(db *sql.DB, seq iter.Seq[inType])
	processDataF[inType any, resultType, tmpType any] func(c connCache, msg dns.Msg, fd *retryWrap[inType, tmpType]) (resultType, error)
)

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
	zoneIP
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
	client      *dns.Client
	udpCache    *ttlcache.Cache[string, *dns.Conn]
	tcpCache    *ttlcache.Cache[string, *dns.Conn]
	cookieCache *ttlcache.Cache[string, string]
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
	cookieCache := getCookieCache()

	var udpCacheF ttlcache.Option[string, *dns.Conn]
	var udpCache *ttlcache.Cache[string, *dns.Conn]

	if tcpOnly {
		client.Net = "tcp"
	} else {
		udpCacheF = connCacheLoader(client, "udp")
		udpCache = ttlcache.New(ttlOption, udpCacheF)
		go udpCache.Start()
		udpCache.OnEviction(connCacheEviction)
	}

	return connCache{
		client:      client,
		cookieCache: cookieCache,
		tcpCache:    tcpCache,
		udpCache:    udpCache,
	}
}

// set up a cookie cache for connCache
func getCookieCache() *ttlcache.Cache[string, string] {
	cookieF := cookieGen()
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
	return exchange(hostname, msg, c.cookieCache, c.tcpCache, c.client)
}

// perform DNS query, using caches, with UDP
func (c connCache) udpExchange(hostname string, msg dns.Msg) (*dns.Msg, error) {
	return exchange(hostname, msg, c.cookieCache, c.udpCache, c.client)
}

// check for cookie option in msg, create if missing, and return the message's cookie option
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
	go clearTTLCache(c.tcpCache)
	go clearTTLCache(c.cookieCache)

	if !tcpOnly {
		go clearTTLCache(c.udpCache)
	}
}

func clearTTLCache[K comparable, V any](cache *ttlcache.Cache[K, V]) {
	cache.Stop()
	cache.DeleteAll()
}

// generate ttlcache.WithLoader function for a given protocol to connect to some host if a connection to a given host is not in the cache
func connCacheLoader(client *dns.Client, proto string) ttlcache.Option[string, *dns.Conn] {
	return ttlcache.WithLoader(ttlcache.LoaderFunc[string, *dns.Conn](func(c *ttlcache.Cache[string, *dns.Conn], host string) *ttlcache.Item[string, *dns.Conn] {
		prevProto := client.Net
		client.Net = proto
		var conn *dns.Conn
		var err error

		for range RETRIES {
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
func cookieGen() ttlcache.Option[string, string] {
	bufRand := make([]byte, 8)
	bufStr := make([]byte, 16)
	oRand := rand.New(rand.NewSource(rand.Int63()))

	getRandCookie := func() string {
		oRand.Read(bufRand)
		hex.Encode(bufStr, bufRand)
		return string(bufStr)
	}

	return ttlcache.WithLoader(ttlcache.LoaderFunc[string, string](func(c *ttlcache.Cache[string, string], host string) *ttlcache.Item[string, string] {
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

func plainResolveRandom(msg dns.Msg, connCache connCache) (*dns.Msg, error) {
	return plainResolve(msg, connCache, randomNS())
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

	if err != nil || res.Truncated {
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
func resolverWorker[inType, resultType, tmpType any](dataChan <-chan retryWrap[inType, tmpType], refeedChan chan<- retryWrap[inType, tmpType], outChan chan<- resultType, msg dns.Msg, processData processDataF[inType, resultType, tmpType], wg, retryWg *sync.WaitGroup) {
	connCache := getConnCache()
	defer connCache.clear()
	defer wg.Done()

	// t := TIMEOUT
	// client.DialTimeout = t
	// client.ReadTimeout = t
	// client.WriteTimeout = t

	for fd := range dataChan {
		startStage := fd.stage
		result, err := processData(connCache, msg, &fd)
		if fd.stage != startStage {
			fd.retriesLeft = RETRIES
		}
		if err == nil || fd.retriesLeft == 0 {
			outChan <- result
			retryWg.Done()
		} else {
			fd.retriesLeft--
			go func(fd retryWrap[inType, tmpType]) {
				refeedChan <- fd
			}(fd)
		}
	}
}

// prints a message, creates a channel, reads entries of some type `inType` with a reader function
// from the database into the channel and sends them over a channel to writerF,
// which processes the entries and writes them back to the database
func readerWriter[inType any](msg string, db *sql.DB, seq iter.Seq[inType], writerF writerF[inType]) {
	fmt.Println(msg)
	writerF(db, bufferedSeq(seq, MIDBUFLEN))
}

// wrapper for netWriter for the common case of not needing to perform SQL queries within the resolver
func netWriter[inType, resultType, tmpType any](db *sql.DB, seq iter.Seq[inType], tablesFields, namesStmts map[string]string, workerF netWorkerF[inType, resultType, tmpType], insertF insertF[resultType]) {
	wrappedWorkerF := func(dataChan <-chan retryWrap[inType, tmpType], refeedChan chan<- retryWrap[inType, tmpType], outChan chan<- resultType, wg, retryWg *sync.WaitGroup, _ TableMap, _ StmtMap) {
		workerF(dataChan, refeedChan, outChan, wg, retryWg)
	}
	netWriterTable(db, seq, tablesFields, namesStmts, wrappedWorkerF, insertF)
}

// passes data from inChan (database entries) to `workerF` workers (network resolvers), and passes the output of that (DNS responses) to `insertF`,
// which writes the results to the database
func netWriterTable[inType, resultType, tmpType any](db *sql.DB, seq iter.Seq[inType], tablesFields, namesStmts map[string]string, workerF tableWorkerF[inType, resultType, tmpType], insertF insertF[resultType]) {
	numProcs := 64

	dataOutChan := make(chan resultType, BUFLEN)

	var workerWg, retryWg sync.WaitGroup

	inLow, inHigh, out, stop := priorityChanGen[retryWrap[inType, tmpType]]()
	retryWrapper(bufferedSeq(seq, MIDBUFLEN), inLow, &retryWg)

	go func() {
		retryWg.Wait()
		stop()
	}()

	tx := check1(db.Begin())

	tableMap := getTableMap(tablesFields, tx)
	stmtMap := getStmtMap(namesStmts, tx)

	workerWg.Add(numProcs)

	for range numProcs {
		go workerF(out, inHigh, dataOutChan, &workerWg, &retryWg, tableMap, stmtMap)
	}

	closeChanWait(&workerWg, dataOutChan)

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

func retryWrapper[inType, resultType any](seq iter.Seq[inType], retryChan chan<- retryWrap[inType, resultType], wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		for val := range seq {
			wg.Add(1)
			retryChan <- retryWrap[inType, resultType]{
				val:         val,
				retriesLeft: RETRIES,
			}
		}
	}()
}

func resolveMX(db *sql.DB) {
	readerWriter("resolving zone MX records", db, netZoneReader(db, "AND zone.mx_resolved=FALSE"), mxWriter)
}

func netNS(db *sql.DB) {
	readerWriter("Adding zone NS mappings from the internet", db, netZoneReader(db, "AND zone.ns_resolved=FALSE"), netNSWriter)
}

func netIP(db *sql.DB) {
	readerWriter("Adding name-IP mappings from the internet", db, getDbFieldData(`
	SELECT name.name, id
	FROM name
	WHERE (is_ns=TRUE OR is_mx=TRUE) AND addr_resolved=FALSE
`, db), netIPWriter)
}

func checkUp(db *sql.DB) {
	readerWriter("Checking for active NSes", db, checkUpReader(db), checkUpWriter)
}

func getParentNS(db *sql.DB) {
	readerWriter("getting NS records from parent zone", db, parentNSReader(db), parentNSWriter)
}

func rdns(db *sql.DB) {
	readerWriter("getting rDNS results for IPs", db, getDbFieldData(`
	SELECT address, id
	FROM ip
	WHERE rdns_mapped=FALSE
`, db), rdnsWriter)
}

func spf(db *sql.DB) {
	readerWriter("getting potential SPF records", db, getDbFieldData(`
	SELECT DISTINCT name.name, name.id
	FROM name
	INNER JOIN name_mx ON name_mx.name_id=name.id
	WHERE name.spf_tried=FALSE
`, db), spfRRWriter)
}

func spfLinks(db *sql.DB) {
	readerWriter("getting linked SPF records", db, getDbFieldData(`
	SELECT DISTINCT name.name, name.id
	FROM name
	INNER JOIN spf_name ON spf_name.name_id=name.id
	WHERE spf_name.spfname=TRUE AND name.spf_tried=FALSE
`, db), spfRRWriter)
}

func dmarc(db *sql.DB) {
	readerWriter("getting potential DMARC records", db, getUnqueriedDMARC(db), dmarcRRWriter)
}

func chaosTXT(db *sql.DB) {
	readerWriter("performing Chaosnet queries", db, getUnqueriedChaosTXT(db), chaosTXTWriter)
}
