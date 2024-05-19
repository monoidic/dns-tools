package main

import (
	"database/sql"
	"fmt"
	"iter"
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v3"
)

type rrF[rrType any] func(tableMap TableMap, stmtMap StmtMap, rrD rrType)

var initStmts = []string{
	`
	CREATE TABLE IF NOT EXISTS name
	(
		id            INTEGER PRIMARY KEY,
		name          TEXT UNIQUE NOT NULL,
		is_ns         INTEGER NOT NULL DEFAULT FALSE,
		is_mx         INTEGER NOT NULL DEFAULT FALSE,
		is_zone       INTEGER NOT NULL DEFAULT FALSE,
		is_rdns       INTEGER NOT NULL DEFAULT FALSE,
		cname_tgt_id  INTEGER REFERENCES name(id),
		parent_id     INTEGER REFERENCES name(id),
		etldp1_id     INTEGER REFERENCES name(id),
		registered    INTEGER NOT NULL DEFAULT TRUE,
		reg_checked   INTEGER NOT NULL DEFAULT FALSE,
		nsec_mapped   INTEGER NOT NULL DEFAULT FALSE,
		nsec_walked   INTEGER NOT NULL DEFAULT FALSE,
		mx_resolved   INTEGER NOT NULL DEFAULT FALSE,
		ns_resolved   INTEGER NOT NULL DEFAULT FALSE,
		glue_ns       INTEGER NOT NULL DEFAULT FALSE, -- for zones; glue NS has been fetched from parent zone
		addr_resolved INTEGER NOT NULL DEFAULT FALSE,
		spf_tried     INTEGER NOT NULL DEFAULT FALSE,
		dmarc_tried   INTEGER NOT NULL DEFAULT FALSE, -- so that '_dmarc.${name}' does not need to be stored
		axfr_tried    INTEGER NOT NULL DEFAULT FALSE,
		valid         INTEGER NOT NULL DEFAULT TRUE,  -- has valid parent zone chain/TLD
		valid_tried   INTEGER NOT NULL DEFAULT FALSE, -- validation has been verified
		parent_mapped INTEGER NOT NULL DEFAULT FALSE,
		maybe_zone    INTEGER NOT NULL DEFAULT FALSE,
		maybe_checked INTEGER NOT NULL DEFAULT FALSE,
		inserted      INTEGER NOT NULL DEFAULT FALSE
	)
	`,
	`
	CREATE TABLE IF NOT EXISTS ip
	(
		id           INTEGER PRIMARY KEY,
		address      TEXT UNIQUE NOT NULL,
		rdns_mapped  INTEGER NOT NULL DEFAULT FALSE,
		responsive   INTEGER NOT NULL DEFAULT TRUE,
		ch_resolved  INTEGER NOT NULL DEFAULT FALSE, -- Chaosnet class records, e.g version.bind
		resp_checked INTEGER NOT NULL DEFAULT FALSE
	)
	`,
	`
	CREATE TABLE IF NOT EXISTS rdns
	(
		id      INTEGER PRIMARY KEY,
		ip_id   INTEGER NOT NULL REFERENCES ip(id),
		name_id INTEGER NOT NULL REFERENCES name(id),
		UNIQUE(ip_id, name_id)
	)
	`,
	`
	CREATE TABLE IF NOT EXISTS zone_ns
	(
		id             INTEGER PRIMARY KEY,
		zone_id        INTEGER NOT NULL REFERENCES name(id),
		ns_id          INTEGER NOT NULL REFERENCES name(id),
		in_parent_zone INTEGER NOT NULL DEFAULT FALSE,
		in_self_zone   INTEGER NOT NULL DEFAULT FALSE,
		UNIQUE(zone_id, ns_id)
	)
	`,
	`
	CREATE TABLE IF NOT EXISTS name_mx
	(
		id         INTEGER PRIMARY KEY,
		name_id    INTEGER NOT NULL REFERENCES name(id),
		mx_id      INTEGER NOT NULL REFERENCES name(id),
		preference INTEGER NOT NULL,
		UNIQUE(name_id, mx_id)
	)
	`,
	`
	CREATE TABLE IF NOT EXISTS name_ip
	(
		id                  INTEGER PRIMARY KEY,
		name_id             INTEGER NOT NULL REFERENCES name(id),
		ip_id               INTEGER NOT NULL REFERENCES ip(id),
		in_parent_zone_glue INTEGER NOT NULL DEFAULT FALSE,
		in_self_zone        INTEGER NOT NULL DEFAULT FALSE,
		UNIQUE(name_id, ip_id)
	)
	`,
	`
	CREATE TABLE IF NOT EXISTS axfrable_ns
	(
		id        INTEGER PRIMARY KEY,
		ip_id     INTEGER NOT NULL REFERENCES ip(id),
		zone_id   INTEGER NOT NULL REFERENCES name(id),
		scan_time INTEGER NOT NULL DEFAULT 0,
		UNIQUE(ip_id, zone_id)
	)
	`,
	`
	CREATE TABLE IF NOT EXISTS spf
	(
		id            INTEGER PRIMARY KEY,
		name_id       INTEGER NOT NULL REFERENCES name(id),
		spf_record_id INTEGER NOT NULL REFERENCES spf_record(id),
		duplicate     INTEGER NOT NULL DEFAULT FALSE,
		UNIQUE(name_id, spf_record_id)
	)
	`,
	`
	CREATE TABLE IF NOT EXISTS spf_record
	(
		id          INTEGER PRIMARY KEY,
		value       TEXT UNIQUE NOT NULL,
		valid       INTEGER NOT NULL DEFAULT TRUE,
		error       TEXT, -- if valid == false, explain why
		any_unknown INTEGER NOT NULL DEFAULT FALSE -- any unknown modifiers
	)
	`,
	`
	CREATE TABLE IF NOT EXISTS spf_name -- for DNS names scraped from the SPF record
	(
		id      INTEGER PRIMARY KEY,
		spf_record_id  INTEGER NOT NULL REFERENCES spf_record(id),
		name_id INTEGER NOT NULL REFERENCES name(id),
		spfname INTEGER NOT NULL, -- bool, indicates names with additional spf records to fetch
		UNIQUE(spf_record_id, name_id)
	)
	`,
	`
	CREATE TABLE IF NOT EXISTS dmarc_record
	(
		id    INTEGER PRIMARY KEY,
		value TEXT UNIQUE NOT NULL,
		valid INTEGER NOT NULL DEFAULT TRUE,
		error TEXT -- if valid == false, explain why
	)
	`,
	`
	CREATE TABLE IF NOT EXISTS dmarc
	(
		id              INTEGER PRIMARY KEY,
		name_id         INTEGER NOT NULL REFERENCES name(id),
		dmarc_record_id INTEGER NOT NULL REFERENCES dmarc_record(id),
		duplicate       INTEGER NOT NULL DEFAULT FALSE,
		UNIQUE(name_id, dmarc_record_id)
	)
	`,
	`
	CREATE TABLE IF NOT EXISTS rr_type
	(
		id   INTEGER PRIMARY KEY,
		name TEXT UNIQUE NOT NULL
	)
	`,
	`
	CREATE TABLE IF NOT EXISTS rr_name
	(
		id   INTEGER PRIMARY KEY,
		name TEXT UNIQUE NOT NULL
	)
	`,
	`
	CREATE TABLE IF NOT EXISTS rr_value
	(
		id    INTEGER PRIMARY KEY,
		value TEXT UNIQUE NOT NULL
	)
	`,
	`
	CREATE TABLE IF NOT EXISTS zone2rr
	(
		id          INTEGER PRIMARY KEY,
		parsed      INTEGER NOT NULL DEFAULT FALSE,
		zone_id     INTEGER NOT NULL REFERENCES name(id),
		rr_type_id  INTEGER NOT NULL REFERENCES rr_type(id),
		rr_name_id  INTEGER NOT NULL REFERENCES rr_name(id),
		rr_value_id INTEGER NOT NULL REFERENCES rr_value(id),
		inserted    INTEGER NOT NULL DEFAULT FALSE,
		from_parent INTEGER NOT NULL DEFAULT FALSE,
		from_self   INTEGER NOT NULL DEFAULT FALSE,
		poison      INTEGER NOT NULL DEFAULT FALSE,
		UNIQUE(zone_id, rr_type_id, rr_name_id, rr_value_id)
	)
	`,
	`
	CREATE TABLE IF NOT EXISTS rname
	(
		id   INTEGER PRIMARY KEY,
		name TEXT UNIQUE NOT NULL
	)
	`,
	`
	CREATE TABLE IF NOT EXISTS mname
	(
		id   INTEGER PRIMARY KEY,
		name TEXT UNIQUE NOT NULL
	)
	`,
	`
	CREATE TABLE IF NOT EXISTS nsec_state
	(
		id   INTEGER PRIMARY KEY,
		name TEXT UNIQUE NOT NULL
	)
	`,
	`
	CREATE TABLE IF NOT EXISTS zone_nsec_state
	(
		id            INTEGER PRIMARY KEY,
		zone_id       INTEGER NOT NULL REFERENCES name(id),
		nsec_state_id INTEGER NOT NULL REFERENCES nsec_state(id),
		rname_id      INTEGER NOT NULL REFERENCES rname(id),
		mname_id      INTEGER NOT NULL REFERENCES mname(id),
		nsec          TEXT NOT NULL
	)
	`,
	`
	CREATE TABLE IF NOT EXISTS zone_walk_res
	(
		id         INTEGER PRIMARY KEY,
		zone_id    INTEGER NOT NULL REFERENCES name(id),
		rr_name_id INTEGER NOT NULL REFERENCES rr_name(id),
		rr_type_id INTEGER NOT NULL REFERENCES rr_type(id),
		queried    INTEGER NOT NULL DEFAULT FALSE,
		UNIQUE(zone_id, rr_name_id, rr_type_id)
	)
	`,
	`
	INSERT OR IGNORE INTO nsec_state (id, name) VALUES
	(1, 'unknown'       ),
	(2, 'secure_nsec'   ),
	(3, 'plain_nsec'    ),
	(4, 'nsec3'         ),
	(5, 'nsec_confusion')
	`,
	`
	CREATE TABLE IF NOT EXISTS unwalked_root
	(
		id   INTEGER PRIMARY KEY,
		name TEXT UNIQUE NOT NULL,
		ent  INTEGER NOT NULL DEFAULT FALSE
	)
	`,
	`
	CREATE TABLE IF NOT EXISTS chaos_query
	(
		id      INTEGER PRIMARY KEY,
		name_id INTEGER NOT NULL REFERENCES name(id), -- e.g version.bind.
		ip_id   INTEGER NOT NULL REFERENCES ip(id),
		UNIQUE(name_id, ip_id)
	)
	`,
	`
	CREATE TABLE IF NOT EXISTS chaos_response_value
	(
		id    INTEGER PRIMARY KEY,
		value TEXT UNIQUE NOT NULL
	)
	`,
	`
	CREATE TABLE IF NOT EXISTS chaos_response
	(
		id                      INTEGER PRIMARY KEY,
		chaos_query_id          INTEGER NOT NULL REFERENCES chaos_query(id),
		name_id                 INTEGER NOT NULL REFERENCES name(id), -- name in response may not match name in query
		chaos_response_value_id INTEGER NOT NULL REFERENCES chaos_response_value(id),
		UNIQUE(chaos_query_id, chaos_response_value_id)
	)
	`,
}

type tableData struct {
	fieldName string
	cache     *ttlcache.Cache[string, int64]
	loader    ttlcache.Option[string, int64]
	roLoader  ttlcache.Option[string, int64]
	cleanup   func()
}

type stmtData struct {
	stmt  *sql.Stmt
	query string
}
type msgtype uint8

const (
	rrDataRegular msgtype = iota + 1
	rrDataZoneDone
	rrDataZoneAxfrEnd
	rrDataZoneAxfrTry
)

type rrData struct {
	zone    string
	rrValue string
	rrType  string
	rrName  string
	ip      string
	scanned int64

	msgtype
	parentZone bool
	selfZone   bool
}

type StmtMap struct {
	data map[string]*stmtData
	mx   *sync.RWMutex
	wg   *sync.WaitGroup
}

type TableMap struct {
	data map[string]*tableData
	mx   *sync.RWMutex
	wg   *sync.WaitGroup
}

type FDCache struct {
	cache   *ttlcache.Cache[string, []fieldData]
	loader  ttlcache.Option[string, []fieldData]
	cleanup func()
	qs      string
}

type rrDBData struct {
	id         int64
	rrType     fieldData
	rrName     fieldData
	rrValue    fieldData
	fromParent bool
	fromSelf   bool
}

type nsecWalkResolveRes struct {
	rrDBData
	results []rrData
}

func initDb(db *sql.DB) {
	tx := check1(db.Begin())

	for _, stmt := range initStmts {
		check1(tx.Exec(stmt))
	}

	check(tx.Commit())
}

func getFDCLoader(qs string, tx *sql.Tx) (ttlcache.Option[string, []fieldData], func()) {
	stmt := check1(tx.Prepare(qs))

	cacheF := ttlcache.WithLoader[string, []fieldData](ttlcache.LoaderFunc[string, []fieldData](func(c *ttlcache.Cache[string, []fieldData], zone string) *ttlcache.Item[string, []fieldData] {
		rows := check1(stmt.Query(zone))

		var ret []fieldData

		for rows.Next() {
			var fd fieldData
			check(rows.Scan(&fd.name, &fd.id))
			ret = append(ret, fd)
		}

		return c.Set(zone, ret, 0)
	}))

	cleanup := func() {
		check(stmt.Close())
	}

	return cacheF, cleanup
}

func getFDCache(qs string, tx *sql.Tx) *FDCache {
	getF, cleanup := getFDCLoader(qs, tx)
	cache := ttlcache.New(
		ttlcache.WithTTL[string, []fieldData](1 * time.Minute),
	)

	go cache.Start()

	return &FDCache{cache: cache, cleanup: cleanup, qs: qs, loader: getF}
}

func (fdc *FDCache) clear() {
	fdc.cleanup()
	fdc.cache.Stop()
	fdc.cache.DeleteAll()
}

func (fdc *FDCache) getName(zone string) []string {
	fds := fdc.cache.Get(zone, fdc.loader).Value()
	names := make([]string, 0, len(fds))
	for _, fd := range fds {
		names = append(names, fd.name)
	}

	return names
}

func getTableMap(m map[string]string, tx *sql.Tx) TableMap {
	tableMap := make(map[string]*tableData)

	for tableName, fieldName := range m {
		getF, rwCleanup := createInsertF(tx, tableName, fieldName)
		roGetF, roCleanup := createROGetF(tx, tableName, fieldName)

		cleanup := func() {
			rwCleanup()
			roCleanup()
		}

		cache := ttlcache.New(
			ttlcache.WithTTL[string, int64](1 * time.Minute),
		)

		go cache.Start()

		tableMap[tableName] = &tableData{
			fieldName: fieldName,
			cache:     cache,
			cleanup:   cleanup,
			loader:    getF,
			roLoader:  roGetF,
		}
	}

	return TableMap{
		data: tableMap,
		mx:   new(sync.RWMutex),
		wg:   new(sync.WaitGroup),
	}
}

func (tableMap TableMap) update(tx *sql.Tx) {
	// needs lock to be locked externally

	for tableName, td := range tableMap.data {
		td.cleanup()
		var rwCleanup, roCleanup func()
		td.loader, rwCleanup = createInsertF(tx, tableName, td.fieldName)
		td.roLoader, roCleanup = createROGetF(tx, tableName, td.fieldName)
		td.cleanup = func() {
			rwCleanup()
			roCleanup()
		}
	}
}

func (tableMap TableMap) get(table, key string) int64 {
	tableMap.mx.RLock()

	td := tableMap.data[table]
	ret := td.cache.Get(key, td.loader).Value()

	tableMap.mx.RUnlock()

	return ret
}

func (tableMap TableMap) roGet(table, key string) int64 {
	var ret int64

	tableMap.mx.RLock()

	td := tableMap.data[table]
	if item := td.cache.Get(key, td.roLoader); item != nil {
		ret = item.Value()
	}

	tableMap.mx.RUnlock()

	return ret
}

func (tableMap TableMap) clear() {
	tableMap.wg.Wait()
	tableMap.mx.Lock()
	for _, td := range tableMap.data {
		td.cleanup()
		td.cache.Stop()
		td.cache.DeleteAll()
	}
	// tableMap.mx.Unlock()
}

func getStmtMap(m map[string]string, tx *sql.Tx) StmtMap {
	stmtMap := make(map[string]*stmtData)

	for name, query := range m {
		stmt := check1(tx.Prepare(query))
		stmtMap[name] = &stmtData{stmt: stmt, query: query}
	}

	return StmtMap{
		data: stmtMap,
		mx:   new(sync.RWMutex),
		wg:   new(sync.WaitGroup),
	}
}

// needs lock to be locked externally
func (stmtMap StmtMap) update(tx *sql.Tx) {
	for _, std := range stmtMap.data {
		check(std.stmt.Close())
		std.stmt = check1(tx.Prepare(std.query))
	}
}

func (stmtMap StmtMap) exec(ident string, args ...any) {
	stmtMap.mx.RLock()

	check1(stmtMap.data[ident].stmt.Exec(args...))

	stmtMap.mx.RUnlock()
}

func (stmtMap StmtMap) clear() {
	stmtMap.wg.Wait()
	stmtMap.mx.Lock()
	for _, std := range stmtMap.data {
		check(std.stmt.Close())
	}
	// stmtMap.mx.Unlock()
}

func createInsertF(tx *sql.Tx, tableName string, valueName string) (ttlcache.Option[string, int64], func()) {
	selectStmt := check1(tx.Prepare(fmt.Sprintf("SELECT id FROM %s WHERE %s=? LIMIT 1", tableName, valueName)))
	insertStmt := check1(tx.Prepare(fmt.Sprintf("INSERT INTO %s (%s) VALUES (?)", tableName, valueName)))

	cacheF := ttlcache.WithLoader[string, int64](ttlcache.LoaderFunc[string, int64](func(c *ttlcache.Cache[string, int64], arg string) *ttlcache.Item[string, int64] {
		rows := check1(selectStmt.Query(arg))

		var lastID int64

		if rows.Next() {
			check(rows.Scan(&lastID))
		} else {
			res := check1(insertStmt.Exec(arg))
			lastID = check1(res.LastInsertId())
		}

		check(rows.Close())
		return c.Set(arg, lastID, 0)
	}))
	cleanupF := func() {
		check(selectStmt.Close())
		check(insertStmt.Close())
	}

	return cacheF, cleanupF
}

func createROGetF(tx *sql.Tx, tableName string, valueName string) (ttlcache.Option[string, int64], func()) {
	selectStmt := check1(tx.Prepare(fmt.Sprintf("SELECT id FROM %s WHERE %s=? LIMIT 1", tableName, valueName)))

	cacheF := ttlcache.WithLoader[string, int64](ttlcache.LoaderFunc[string, int64](func(c *ttlcache.Cache[string, int64], arg string) *ttlcache.Item[string, int64] {
		rows := check1(selectStmt.Query(arg))

		var item *ttlcache.Item[string, int64]

		var lastID int64

		if rows.Next() {
			check(rows.Scan(&lastID))
			item = c.Set(arg, lastID, 0)
		}

		check(rows.Close())
		return item
	}))
	cleanupF := func() {
		check(selectStmt.Close())
	}

	return cacheF, cleanupF
}

func insertRR[rrType any](db *sql.DB, seq iter.Seq[rrType], tablesFields, namesStmts map[string]string, rrF rrF[rrType]) {
	tx := check1(db.Begin())

	tableMap := getTableMap(tablesFields, tx)
	stmtMap := getStmtMap(namesStmts, tx)

	i := CHUNKSIZE

	for rrD := range bufferedSeq(seq, MIDBUFLEN) {
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

		rrF(tableMap, stmtMap, rrD)
	}

	tableMap.clear()
	stmtMap.clear()
	check(tx.Commit())
}

func getZone2RR(filter string, db *sql.DB) iter.Seq[rrDBData] {
	return func(yield func(rrDBData) bool) {
		tx := check1(db.Begin())
		rows := check1(tx.Query(fmt.Sprintf(`
		SELECT
			zone2rr.id, zone2rr.from_parent, zone2rr.from_self,
			rr_type.name, rr_type.id,
			rr_name.name, rr_name.id,
			rr_value.value, rr_value.id
		FROM zone2rr
		INNER JOIN rr_type ON zone2rr.rr_type_id=rr_type.id
		INNER JOIN rr_name ON zone2rr.rr_name_id=rr_name.id
		INNER JOIN rr_value ON zone2rr.rr_value_id=rr_value.id
		WHERE zone2rr.parsed=FALSE AND %s
	`, filter)))

		for rows.Next() {
			var ad rrDBData
			check(rows.Scan(
				&ad.id, &ad.fromParent, &ad.fromSelf,
				&ad.rrType.name, &ad.rrType.id,
				&ad.rrName.name, &ad.rrName.id,
				&ad.rrValue.name, &ad.rrValue.id,
			))
			if !yield(ad) {
				break
			}
		}

		check(rows.Close())
		check(tx.Commit())
	}
}

func getUnqueriedNsecRes(db *sql.DB) iter.Seq[rrDBData] {
	return func(yield func(rrDBData) bool) {
		tx := check1(db.Begin())
		rows := check1(tx.Query(`
		SELECT
			zone_walk_res.zone_id, zone_walk_res.id,
			rr_name.name, rr_name.id,
			rr_type.name, rr_type.id
		FROM zone_walk_res
		INNER JOIN rr_type ON zone_walk_res.rr_type_id=rr_type.id
		INNER JOIN rr_name ON zone_walk_res.rr_name_id=rr_name.id
		WHERE zone_walk_res.queried=FALSE
	`))

		for rows.Next() {
			rrD := rrDBData{fromSelf: true}
			check(rows.Scan(
				&rrD.rrValue.id, &rrD.id,
				&rrD.rrName.name, &rrD.rrName.id,
				&rrD.rrType.name, &rrD.rrType.id,
			))
			if !yield(rrD) {
				break
			}
		}

		check(rows.Close())
		check(tx.Commit())
	}
}

func getUnqueriedArpaRoots(db *sql.DB) (iter.Seq[fieldData], bool) {
	tx := check1(db.Begin())
	rows := check1(tx.Query(`
		SELECT id, name
		FROM unwalked_root
	`))

	anyResponses := rows.Next()
	return func(yield func(fieldData) bool) {
		if anyResponses {
			var fd fieldData
			check(rows.Scan(&fd.id, &fd.name))
			_ = yield(fd)
			for rows.Next() {
				var fd fieldData
				check(rows.Scan(&fd.id, &fd.name))
				if !yield(fd) {
					break
				}
			}
		}

		check(rows.Close())
		check(tx.Commit())
	}, anyResponses
}

func readerWriterRecurse[inType any](msg string, db *sql.DB, readerF readerRecurseF[inType], writerF writerF[inType]) {
	fmt.Println(msg)

	seq, anyResponses := readerF(db)
	for anyResponses {
		writerF(db, seq)
		seq, anyResponses = readerF(db)
	}

	_, stop := iter.Pull(seq)
	stop()
}

func extractNSRR(db *sql.DB) {
	readerWriter("extracting NS results from RR", db, getZone2RR("rr_type.name='NS'", db), insertNSRR)
}

func extractIPRR(db *sql.DB) {
	readerWriter("extracting IP results from RR", db, getZone2RR("(rr_type.name='A' OR rr_type.name='AAAA')", db), insertIPRR)
}

func extractMXRR(db *sql.DB) {
	readerWriter("extracting MX results from RR", db, getZone2RR("rr_type.name='MX'", db), insertMXRR)
}

func extractPTRRR(db *sql.DB) {
	readerWriter("extracting PTR results from RR", db, getZone2RR("rr_type.name='PTR'", db), insertPTRRR)
}
