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
)

type rrF[rrType any] func(tableMap TableMap, stmtMap StmtMap, rrD rrType)

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

	for _, stmt := range strings.Split(initStmtsRaw, ";\n") {
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

	defer func() {
		check(rows.Close())
		check(tx.Commit())
	}()

	anyResponses := rows.Next()
	// do this silly dance to get anyResponses to indicate lack of responses before accessing iterator
	return func(yield func(fieldData) bool) {
		if anyResponses {
			var fd fieldData
			check(rows.Scan(&fd.id, &fd.name))
			if !yield(fd) {
				return
			}
			for rows.Next() {
				check(rows.Scan(&fd.id, &fd.name))
				if !yield(fd) {
					break
				}
			}
		}
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
