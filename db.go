package main

import (
	"database/sql"
	_ "embed"
	"fmt"
	"iter"
	"strings"
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/monoidic/dns"
)

type rrF[rrType any] func(tsm *TableStmtMap, rrD rrType)

//go:embed db_init.sql
var initStmtsRaw string

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
	zone    dns.Name
	rrValue string
	rrType  string
	rrName  dns.Name
	ip      string

	msgtype
	parentZone bool
	selfZone   bool
}

type TableStmtMap struct {
	tableMap map[string]*tableData
	stmtMap  map[string]*stmtData
	mx       sync.RWMutex
	tx       *sql.Tx
}

type rrDBData struct {
	id         int64
	rrType     fieldData
	rrName     nameData
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

	for stmt := range strings.SplitSeq(initStmtsRaw, ";\n") {
		check1(tx.Exec(stmt))
	}

	check(tx.Commit())
}

func getTableStmtMap(tablesFields, namesStmts map[string]string, tx *sql.Tx) *TableStmtMap {
	return &TableStmtMap{
		tableMap: getTableMap(tablesFields, tx),
		stmtMap:  getStmtMap(namesStmts, tx),
		tx:       tx,
	}
}

func (tsm *TableStmtMap) update(tx *sql.Tx) {
	// needs lock to be locked externally
	tsm.tx = tx

	for tableName, td := range tsm.tableMap {
		td.cleanup()
		var rwCleanup, roCleanup func()
		td.loader, rwCleanup = createInsertF(tx, tableName, td.fieldName)
		td.roLoader, roCleanup = createROGetF(tx, tableName, td.fieldName)
		td.cleanup = func() {
			rwCleanup()
			roCleanup()
		}
	}

	for _, std := range tsm.stmtMap {
		check(std.stmt.Close())
		std.stmt = check1(tx.Prepare(std.query))
	}
}

func (tsm *TableStmtMap) get(table, key string) int64 {
	tsm.mx.RLock()
	defer tsm.mx.RUnlock()

	td := tsm.tableMap[table]
	ret := td.cache.Get(key, td.loader).Value()

	return ret
}

func (tsm *TableStmtMap) roGet(table, key string) int64 {
	var ret int64

	tsm.mx.RLock()
	defer tsm.mx.RUnlock()

	td := tsm.tableMap[table]
	if item := td.cache.Get(key, td.roLoader); item != nil {
		ret = item.Value()
	}

	return ret
}

func (tsm *TableStmtMap) clear() {
	tsm.mx.Lock()
	defer tsm.mx.Unlock()

	for _, td := range tsm.tableMap {
		td.cleanup()
		td.cache.Stop()
		td.cache.DeleteAll()
	}

	for _, std := range tsm.stmtMap {
		check(std.stmt.Close())
	}
}

func (tsm *TableStmtMap) exec(ident string, args ...any) {
	tsm.mx.RLock()
	defer tsm.mx.RUnlock()
	check1(tsm.stmtMap[ident].stmt.Exec(args...))
}

func getTableMap(m map[string]string, tx *sql.Tx) map[string]*tableData {
	tableMap := make(map[string]*tableData, len(m))

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

	return tableMap
}

func getStmtMap(m map[string]string, tx *sql.Tx) map[string]*stmtData {
	stmtMap := make(map[string]*stmtData, len(m))

	for name, query := range m {
		stmt := check1(tx.Prepare(query))
		stmtMap[name] = &stmtData{stmt: stmt, query: query}
	}

	return stmtMap
}

func createInsertF(tx *sql.Tx, tableName string, valueName string) (ttlcache.Option[string, int64], func()) {
	selectStmt := check1(tx.Prepare(fmt.Sprintf("SELECT id FROM %s WHERE %s=? LIMIT 1", tableName, valueName)))
	insertStmt := check1(tx.Prepare(fmt.Sprintf("INSERT INTO %s (%s) VALUES (?)", tableName, valueName)))

	cacheF := ttlcache.WithLoader(ttlcache.LoaderFunc[string, int64](func(c *ttlcache.Cache[string, int64], arg string) *ttlcache.Item[string, int64] {
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

	cacheF := ttlcache.WithLoader(ttlcache.LoaderFunc[string, int64](func(c *ttlcache.Cache[string, int64], arg string) *ttlcache.Item[string, int64] {
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

	tsm := getTableStmtMap(tablesFields, namesStmts, tx)

	i := CHUNKSIZE

	for rrD := range bufferedSeq(seq, MIDBUFLEN) {
		if i == 0 {
			i = CHUNKSIZE

			tsm.mx.Lock()

			check(tx.Commit())
			tx = check1(db.Begin())

			tsm.update(tx)

			tsm.mx.Unlock()
		}
		i--

		rrF(tsm, rrD)
	}

	tsm.clear()
	check(tx.Commit())
}

func getZone2RR(filter string, db *sql.DB) iter.Seq[rrDBData] {
	return func(yield func(rrDBData) bool) {
		qs := fmt.Sprintf(`
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
		`, filter)
		tx := check1(db.Begin())
		defer tx.Commit()
		rows := check1(tx.Query(qs))
		defer rows.Close()

		for rows.Next() {
			var ad rrDBData
			var rrName string
			check(rows.Scan(
				&ad.id, &ad.fromParent, &ad.fromSelf,
				&ad.rrType.name, &ad.rrType.id,
				&rrName, &ad.rrName.id,
				&ad.rrValue.name, &ad.rrValue.id,
			))
			ad.rrName.name = mustParseName(rrName)
			if !yield(ad) {
				return
			}
		}
	}
}

func getUnqueriedNsecRes(db *sql.DB) iter.Seq[rrDBData] {
	return func(yield func(rrDBData) bool) {
		tx := check1(db.Begin())
		defer tx.Commit()
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
		defer rows.Close()

		for rows.Next() {
			rrD := rrDBData{fromSelf: true}
			var rrName string
			check(rows.Scan(
				&rrD.rrValue.id, &rrD.id,
				&rrName, &rrD.rrName.id,
				&rrD.rrType.name, &rrD.rrType.id,
			))
			rrD.rrName.name = mustParseName(rrName)
			if !yield(rrD) {
				return
			}
		}
	}
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

func extractZoneNsIP(db *sql.DB) {
	readerWriter("mapping zone to NS IP mappings", db, zoneNsIpReader(db), insertZoneNsIp)
}

func extractZoneNsIPGlue(db *sql.DB) {
	readerWriter("mapping zone to parent NS IP mappings", db, zoneNsIpParentReader(db), insertZoneNsIpGlue)
}
