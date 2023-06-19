package main

import (
	"database/sql"
	"fmt"
)

func getDbFieldData(qs string, db *sql.DB, dataChan chan<- fieldData) {
	tx := check1(db.Begin())
	rows := check1(tx.Query(qs))

	for rows.Next() {
		var fd fieldData
		check(rows.Scan(&fd.name, &fd.id))
		dataChan <- fd
	}

	check(rows.Close())
	check(tx.Commit())
	close(dataChan)
}

func netResolvableReader(db *sql.DB, nsChan chan<- fieldData) {
	getDbFieldData(`
		SELECT name.name, id
		FROM name
		WHERE (is_ns=TRUE OR is_mx=TRUE) AND addr_resolved=FALSE
	`, db, nsChan)
}

func rdnsIPReader(db *sql.DB, ipChan chan<- fieldData) {
	getDbFieldData(`
		SELECT address, id
		FROM ip
		WHERE rdns_mapped=FALSE
	`, db, ipChan)
}

func getUnqueriedSPFName(db *sql.DB, fdChan chan<- fieldData) {
	getDbFieldData(`
		SELECT DISTINCT name.name, name.id
		FROM name
		INNER JOIN spf_name ON spf_name.name_id=name.id
		WHERE spf_name.spfname=TRUE AND name.spf_tried=FALSE
	`, db, fdChan)
}

func getMaybeZones(db *sql.DB, fdChan chan<- fieldData) {
	getDbFieldData(`
		SELECT name.name, name.id
		FROM name
		WHERE name.maybe_zone=TRUE
	`, db, fdChan)
}

func getWalkableZones(db *sql.DB, zoneChan chan<- fieldData) {
	getDbFieldData(`
		SELECT DISTINCT zone.name, zone.id
		FROM name AS zone
		INNER JOIN zone_nsec_state ON zone_nsec_state.zone_id = zone.id
		INNER JOIN nsec_state ON zone_nsec_state.nsec_state_id = nsec_state.id
		WHERE nsec_state.name='plain_nsec'
		AND zone.nsec_walked=FALSE
		AND zone.inserted=FALSE
	`, db, zoneChan)
}

func getParentCheck(db *sql.DB, dataChan chan<- fieldData) {
	getDbFieldData(`
		SELECT name, id
		FROM name
		WHERE
		parent_mapped=FALSE
		AND valid=TRUE
	`, db, dataChan)
}

func getRegUncheckedZones(db *sql.DB, zoneChan chan<- fieldData) {
	getDbFieldData(`
		SELECT name, id
		FROM name
		WHERE reg_checked=FALSE
		AND is_zone=TRUE
		AND valid=TRUE
	`, db, zoneChan)
}

func getValidUncheckedNames(db *sql.DB, zoneChan chan<- fieldData) {
	getDbFieldData(`
		SELECT name, id
		FROM name AS zone
		WHERE valid_tried=FALSE
	`, db, zoneChan)
}

func getUnqueriedSPF(db *sql.DB, fdChan chan<- fieldData) {
	getDbFieldData(`
		SELECT DISTINCT name.name, name.id
		FROM name
		INNER JOIN name_mx ON name_mx.name_id=name.id
		WHERE name.spf_tried=FALSE
	`, db, fdChan)
}

func getUnqueriedDMARC(db *sql.DB, fdChan chan<- fieldData) {
	getDbFieldData(`
		SELECT DISTINCT name.name, name.id
		FROM name
		INNER JOIN name_mx ON name_mx.name_id=name.id
		WHERE name.dmarc_tried=FALSE
	`, db, fdChan)
}

// wrapper that prepends `_dmarc.` to the name while keeping the id the same
func getUnqueriedDMARCWrap(db *sql.DB, fdChan chan<- fieldData) {
	midChan := make(chan fieldData, BUFLEN)
	go getUnqueriedDMARC(db, midChan)
	for fd := range midChan {
		fd.name = "_dmarc." + fd.name
		fdChan <- fd
	}
	close(fdChan)
}

func getUnqueriedChaosTXT(db *sql.DB, ipChan chan<- fieldData) {
	var v4Filter string
	if !v6 {
		v4Filter = `AND ip.address LIKE '%.%'`
	}
	filter := fmt.Sprintf(`
		SELECT address, id
		FROM ip
		WHERE ch_resolved=FALSE %s
	`, v4Filter)
	getDbFieldData(filter, db, ipChan)
}

func netZoneReader(db *sql.DB, zoneChan chan<- fieldData, extraFilter string) {
	qs := fmt.Sprintf(`
		SELECT zone.name, zone.id
		FROM name AS zone
		WHERE zone.is_zone=TRUE %s
	`, extraFilter)
	getDbFieldData(qs, db, zoneChan)
}

// returns a writerF compatible function to read DNS names and database IDs matching some filter
func netZoneReaderGen(filter string) func(*sql.DB, chan<- fieldData) {
	return func(db *sql.DB, zoneChan chan<- fieldData) {
		netZoneReader(db, zoneChan, filter)
	}
}
