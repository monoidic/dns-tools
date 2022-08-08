package main

import (
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/monoidic/dns"
)

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
		is_cname      INTEGER NOT NULL DEFAULT FALSE,
		registered    INTEGER NOT NULL DEFAULT TRUE,
		reg_checked   INTEGER NOT NULL DEFAULT FALSE,
		nsec_mapped   INTEGER NOT NULL DEFAULT FALSE,
		nsec_walked   INTEGER NOT NULL DEFAULT FALSE,
		mx_resolved   INTEGER NOT NULL DEFAULT FALSE,
		ns_resolved   INTEGER NOT NULL DEFAULT FALSE,
		glue_ns       INTEGER NOT NULL DEFAULT FALSE, -- for zones; glue NS has been fetched from parent zone
		addr_resolved INTEGER NOT NULL DEFAULT FALSE,
		axfr_tried    INTEGER NOT NULL DEFAULT FALSE,
		valid         INTEGER NOT NULL DEFAULT TRUE,  -- has valid parent zone chain/TLD
		valid_tried   INTEGER NOT NULL DEFAULT FALSE, -- validation has been verified
		parent_mapped INTEGER NOT NULL DEFAULT FALSE,
		maybe_zone    INTEGER NOT NULL DEFAULT FALSE,
		inserted      INTEGER NOT NULL DEFAULT FALSE
	)
	`,
	`
	CREATE TABLE IF NOT EXISTS cname
	(
		id        INTEGER PRIMARY KEY,
		name_id   INTEGER UNIQUE NOT NULL REFERENCES name(id),
		target_id INTEGER NOT NULL REFERENCES name(id)
	)
	`,
	`
	CREATE TABLE IF NOT EXISTS ip
	(
		id           INTEGER PRIMARY KEY,
		address      TEXT UNIQUE NOT NULL,
		rdns_mapped  INTEGER NOT NULL DEFAULT FALSE,
		responsive   INTEGER NOT NULL DEFAULT TRUE,
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
	CREATE TABLE IF NOT EXISTS name_parent
	(
		id          INTEGER PRIMARY KEY,
		child_id    INTEGER UNIQUE NOT NULL REFERENCES name(id),
		parent_id   INTEGER NOT NULL REFERENCES name(id)
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
}

type keyValue struct {
	key, value string
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
	rrDataRegular msgtype = iota
	rrDataZoneDone
	rrDataZoneAxfrEnd
	rrDataZoneAxfrTry
)

type rrData struct {
	zone    string
	rrValue string
	rrType  string
	rrName  string

	ip string
	msgtype
	scanned int64

	parentZone bool
	selfZone   bool
}

type StmtMap struct {
	data map[string]*stmtData
	mx   *sync.RWMutex
	once *sync.Once
	wg   *sync.WaitGroup
}

type TableMap struct {
	data map[string]*tableData
	mx   *sync.RWMutex
	once *sync.Once
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
		once: new(sync.Once),
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
	item := td.cache.Get(key, td.roLoader)
	if item != nil {
		ret = item.Value()
	}

	tableMap.mx.RUnlock()

	return ret
}

func (tableMap TableMap) clear() {
	tableMap.wg.Wait()
	tableMap.mx.Lock()
	tableMap.once.Do(func() {
		for _, td := range tableMap.data {
			td.cleanup()
			td.cache.Stop()
			td.cache.DeleteAll()
		}
	})
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
		once: new(sync.Once),
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

func (stmtMap StmtMap) exec(table string, args ...any) {
	stmtMap.mx.RLock()

	check1(stmtMap.data[table].stmt.Exec(args...))

	stmtMap.mx.RUnlock()
}

func (stmtMap StmtMap) clear() {
	stmtMap.wg.Wait()
	stmtMap.mx.Lock()
	stmtMap.once.Do(func() {
		for _, std := range stmtMap.data {
			check(std.stmt.Close())
		}
	})
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

func insertRRWorker(db *sql.DB, rrDataChan chan rrData, wg *sync.WaitGroup) {
	tablesFields := map[string]string{
		"name":     "name",
		"rr_type":  "name",
		"rr_name":  "name",
		"rr_value": "value",
		"ip":       "address",
	}
	namesStmts := map[string]string{
		"insert":           "INSERT OR IGNORE INTO zone2rr (zone_id, rr_type_id, rr_name_id, rr_value_id) VALUES (?, ?, ?, ?)",
		"update":           "UPDATE name SET inserted=TRUE, is_zone=TRUE WHERE id=?",
		"vulnNS":           "INSERT OR IGNORE INTO axfrable_ns (ip_id, zone_id) VALUES (?, ?)",
		"vulnTime":         "UPDATE axfrable_ns SET scan_time=? WHERE ip_id=? AND zone_id=?",
		"axfrTried":        "UPDATE name SET axfr_tried=TRUE WHERE id=?",
		"self_parent_zone": "UPDATE zone2rr SET from_self=from_self|?, from_parent=from_parent|? WHERE zone_id=? AND rr_type_id=? AND rr_name_id=? AND rr_value_id=?",
	}

	tx := check1(db.Begin())

	tableMap := getTableMap(tablesFields, tx)
	stmtMap := getStmtMap(namesStmts, tx)

	i := CHUNKSIZE

	for rrD := range rrDataChan {
		if i == 0 {
			i = CHUNKSIZE

			tableMap.mx.Lock()
			stmtMap.mx.Lock()

			check(tx.Commit())
			tx = check1(db.Begin())

			tableMap.update(tx)
			stmtMap.update(tx)

			tableMap.mx.Unlock()
			stmtMap.mx.Unlock()
		}
		i--

		switch rrD.msgtype {
		case rrDataRegular:
			zoneID := tableMap.get("name", rrD.zone)
			rrTypeID := tableMap.get("rr_type", rrD.rrType)
			rrNameID := tableMap.get("rr_name", rrD.rrName)
			rrValueID := tableMap.get("rr_value", rrD.rrValue)

			stmtMap.exec("insert", zoneID, rrTypeID, rrNameID, rrValueID)

			if rrD.selfZone || rrD.parentZone {
				stmtMap.exec("self_parent_zone", rrD.selfZone, rrD.parentZone, zoneID, rrTypeID, rrNameID, rrValueID)
			}

		case rrDataZoneDone:
			zoneID := tableMap.get("name", rrD.zone)

			stmtMap.exec("update", zoneID)

		case rrDataZoneAxfrEnd:
			ipID := tableMap.get("ip", rrD.ip)
			zoneID := tableMap.get("name", rrD.zone)

			stmtMap.exec("vulnNS", ipID, zoneID)
			stmtMap.exec("vulnTime", rrD.scanned, ipID, zoneID)
			stmtMap.exec("update", zoneID)

		case rrDataZoneAxfrTry:
			zoneID := tableMap.get("name", rrD.zone)

			stmtMap.exec("axfrTried", zoneID)
		}
	}

	tableMap.clear()
	stmtMap.clear()
	check(tx.Commit())

	wg.Done()
}

func insertNSRR(db *sql.DB, rrChan chan rrDBData, wg *sync.WaitGroup) {
	tablesFields := map[string]string{
		"name": "name",
	}
	namesStmts := map[string]string{
		"insert":          "INSERT OR IGNORE INTO zone_ns (zone_id, ns_id) VALUES (?, ?)",
		"set_zone":        "UPDATE name SET is_zone=TRUE WHERE id=?",
		"set_ns":          "UPDATE name SET is_ns=TRUE WHERE id=?",
		"set_parent_self": "UPDATE zone_ns SET in_parent_zone=in_parent_zone|?, in_self_zone=in_self_zone|? WHERE zone_id=? AND ns_id=?",
		"set_glue":        "UPDATE name SET glue_ns=TRUE WHERE id=?",
		"set_checked":     "UPDATE name SET reg_checked=TRUE WHERE id=?",
		"parsed":          "UPDATE zone2rr SET parsed=TRUE WHERE id=?",
	}

	insertRR(db, rrChan, wg, tablesFields, namesStmts, nsRRF)
}

func insertIPRR(db *sql.DB, rrChan chan rrDBData, wg *sync.WaitGroup) {
	tablesFields := map[string]string{
		"name": "name",
		"ip":   "address",
	}
	namesStmts := map[string]string{
		"name_ip":          "INSERT OR IGNORE INTO name_ip (name_id, ip_id) VALUES (?, ?)",
		"parent_self_zone": "UPDATE name_ip SET in_parent_zone_glue=in_parent_zone_glue|?, in_self_zone=in_self_zone|? WHERE name_id=? AND ip_id=?",
		"parsed":           "UPDATE zone2rr SET parsed=TRUE WHERE id=?",
	}

	insertRR(db, rrChan, wg, tablesFields, namesStmts, ipRRF)
}

func insertMXRR(db *sql.DB, rrChan chan rrDBData, wg *sync.WaitGroup) {
	tablesFields := map[string]string{
		"name": "name",
	}
	namesStmts := map[string]string{
		"name_mx": "INSERT OR IGNORE INTO name_mx (name_id, mx_id, preference) VALUES (?, ?, ?)",
		"set_mx":  "UPDATE name SET is_mx=TRUE WHERE id=?",
		"parsed":  "UPDATE zone2rr SET parsed=TRUE WHERE id=?",
	}

	insertRR(db, rrChan, wg, tablesFields, namesStmts, mxRRF)
}

func mxRRF(tableMap TableMap, stmtMap StmtMap, ad rrDBData) {
	rr := check1(dns.NewRR(ad.rrValue.name))

	mxRR := rr.(*dns.MX)

	nameID := tableMap.get("name", ad.rrName.name)
	mxID := tableMap.get("name", mxRR.Mx)

	stmtMap.exec("set_mx", mxID)
	stmtMap.exec("name_mx", nameID, mxID, mxRR.Preference)
	stmtMap.exec("parsed", ad.id)
}

func ipRRF(tableMap TableMap, stmtMap StmtMap, ad rrDBData) {
	rr := check1(dns.NewRR(ad.rrValue.name))

	var ip string
	switch rrT := rr.(type) {
	case *dns.A:
		ip = rrT.A.String()
	case *dns.AAAA:
		ip = rrT.AAAA.String()
	default:
		panic(fmt.Sprintf("invalid IP type: %T\n", rr))
	}

	nameID := tableMap.get("name", ad.rrName.name)
	ipID := tableMap.get("ip", ip)

	stmtMap.exec("name_ip", nameID, ipID)

	if ad.fromParent || ad.fromSelf {
		stmtMap.exec("parent_self_zone", ad.fromParent, ad.fromSelf, nameID, ipID)
	}

	stmtMap.exec("parsed", ad.id)
}

func nsRRF(tableMap TableMap, stmtMap StmtMap, ad rrDBData) {
	rr := check1(dns.NewRR(ad.rrValue.name))
	nsRR := rr.(*dns.NS)

	zoneID := tableMap.get("name", ad.rrName.name)
	nsID := tableMap.get("name", nsRR.Ns)

	stmtMap.exec("set_zone", zoneID)
	stmtMap.exec("set_ns", nsID)
	stmtMap.exec("insert", zoneID, nsID)

	if ad.fromParent || ad.fromSelf {
		stmtMap.exec("set_parent_self", ad.fromParent, ad.fromSelf, zoneID, nsID)

		if ad.fromParent {
			parentID := tableMap.get("name", nsRR.Hdr.Name)
			stmtMap.exec("set_glue", zoneID)
			stmtMap.exec("set_checked", parentID)
		}
	}

	stmtMap.exec("parsed", ad.id)
}

func insertRR[rrType any](db *sql.DB, rrChan chan rrType, wg *sync.WaitGroup, tablesFields, namesStmts map[string]string, rrF func(tableMap TableMap, stmtMap StmtMap, rrD rrType)) {
	tx := check1(db.Begin())

	tableMap := getTableMap(tablesFields, tx)
	stmtMap := getStmtMap(namesStmts, tx)

	i := CHUNKSIZE

	for rrD := range rrChan {
		if i == 0 {
			i = CHUNKSIZE

			tableMap.mx.Lock()
			stmtMap.mx.Lock()

			check(tx.Commit())
			tx = check1(db.Begin())

			tableMap.update(tx)
			stmtMap.update(tx)

			tableMap.mx.Unlock()
			stmtMap.mx.Unlock()
		}
		i--

		rrF(tableMap, stmtMap, rrD)

		wg.Done()
	}

	tableMap.clear()
	stmtMap.clear()
	check(tx.Commit())
}

func getWalkableZones(db *sql.DB, zoneChan chan fieldData, wg *sync.WaitGroup) {
	getDbFieldData(`
		SELECT DISTINCT zone.name, zone.id
		FROM name AS zone
		INNER JOIN zone_nsec_state ON zone_nsec_state.zone_id = zone.id
		INNER JOIN nsec_state ON zone_nsec_state.nsec_state_id = nsec_state.id
		WHERE nsec_state.name='plain_nsec'
		AND zone.nsec_walked=FALSE
		AND zone.inserted=FALSE
	`, db, zoneChan, wg)
}

func getParentCheck(db *sql.DB, dataChan chan fieldData, wg *sync.WaitGroup) {
	getDbFieldData(`
		SELECT name, id
		FROM name
		WHERE
		parent_mapped=FALSE
		AND valid=TRUE
	`, db, dataChan, wg)
}

func getRegUncheckedZones(db *sql.DB, zoneChan chan fieldData, wg *sync.WaitGroup) {
	getDbFieldData(`
		SELECT name, id
		FROM name
		WHERE reg_checked=FALSE
		AND is_zone=TRUE
		AND valid=TRUE
	`, db, zoneChan, wg)
}

func getValidUncheckedNames(db *sql.DB, zoneChan chan fieldData, wg *sync.WaitGroup) {
	getDbFieldData(`
		SELECT name, id
		FROM name AS zone
		WHERE valid_tried=FALSE
	`, db, zoneChan, wg)
}

func netZoneReader(db *sql.DB, zoneChan chan fieldData, wg *sync.WaitGroup, extraFilter string) {
	qs := fmt.Sprintf(`
		SELECT zone.name, zone.id
		FROM name AS zone
		WHERE zone.is_zone=TRUE %s
	`, extraFilter)
	getDbFieldData(qs, db, zoneChan, wg)
}

func netResolvableReader(db *sql.DB, nsChan chan fieldData, wg *sync.WaitGroup) {
	getDbFieldData(`
		SELECT name.name, id
		FROM name
		WHERE (is_ns=TRUE OR is_mx=TRUE) AND addr_resolved=FALSE
	`, db, nsChan, wg)
}

func rdnsIPReader(db *sql.DB, ipChan chan fieldData, wg *sync.WaitGroup) {
	getDbFieldData(`
		SELECT address, id
		FROM ip
		WHERE rdns_mapped=FALSE
	`, db, ipChan, wg)
}

func getDbFieldData(qs string, db *sql.DB, dataChan chan fieldData, wg *sync.WaitGroup) {
	tx := check1(db.Begin())
	rows := check1(tx.Query(qs))

	for rows.Next() {
		var fd fieldData
		check(rows.Scan(&fd.name, &fd.id))
		wg.Add(1)
		dataChan <- fd
	}

	check(rows.Close())
	check(tx.Commit())
	wg.Wait()
	close(dataChan)
}

func getZone2RR(filter string, db *sql.DB, dataChan chan rrDBData, wg *sync.WaitGroup) {
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
		wg.Add(1)
		dataChan <- ad
	}

	check(rows.Close())
	check(tx.Commit())
	wg.Wait()
	close(dataChan)
}

func getUnqueriedNsecRes(db *sql.DB, dataChan chan rrDBData, wg *sync.WaitGroup) {
	tx := check1(db.Begin())
	rows := check1(tx.Query(`
		SELECT zone_walk_res.zone_id, zone_walk_res.id, rr_name.name, rr_name.id, rr_type.name, rr_type.id
		FROM zone_walk_res
		INNER JOIN rr_type ON zone_walk_res.rr_type_id=rr_type.id
		INNER JOIN rr_name ON zone_walk_res.rr_name_id=rr_name.id
		WHERE zone_walk_res.queried=FALSE
	`))

	for rows.Next() {
		rrD := rrDBData{fromSelf: true}
		check(rows.Scan(&rrD.rrValue.id, &rrD.id, &rrD.rrName.name, &rrD.rrName.id, &rrD.rrType.name, &rrD.rrType.id))
		wg.Add(1)
		dataChan <- rrD
	}

	check(rows.Close())
	check(tx.Commit())
	wg.Wait()
	close(dataChan)
}

func extractNSRR(db *sql.DB) {
	readerWriter("extracting NS results from RR", db, func(db *sql.DB, rrChan chan rrDBData, wg *sync.WaitGroup) {
		getZone2RR("rr_type.name='NS'", db, rrChan, wg)
	}, insertNSRR)
}

func extractIPRR(db *sql.DB) {
	readerWriter("extracting IP results from RR", db, func(db *sql.DB, rrChan chan rrDBData, wg *sync.WaitGroup) {
		getZone2RR("(rr_type.name='A' OR rr_type.name='AAAA')", db, rrChan, wg)
	}, insertIPRR)
}

func extractMXRR(db *sql.DB) {
	readerWriter("extracting MX results from RR", db, func(db *sql.DB, rrChan chan rrDBData, wg *sync.WaitGroup) {
		getZone2RR("rr_type.name='MX'", db, rrChan, wg)
	}, insertMXRR)
}
