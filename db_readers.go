package main

import (
	"database/sql"
	"fmt"
	"iter"
)

func getDbFieldData(qs string, db *sql.DB) iter.Seq[fieldData] {
	return func(yield func(fieldData) bool) {
		tx := check1(db.Begin())
		rows := check1(tx.Query(qs))

		for rows.Next() {
			var fd fieldData
			check(rows.Scan(&fd.name, &fd.id))
			if !yield(fd) {
				break
			}
		}

		check(rows.Close())
		check(tx.Commit())
	}
}

// wrapper that prepends `_dmarc.` to the name while keeping the id the same
func getUnqueriedDMARC(db *sql.DB) iter.Seq[fieldData] {
	return func(yield func(fieldData) bool) {
		for fd := range getDbFieldData(`
		SELECT DISTINCT name.name, name.id
		FROM name
		INNER JOIN name_mx ON name_mx.name_id=name.id
		WHERE name.dmarc_tried=FALSE
	`, db) {
			fd.name = "_dmarc." + fd.name
			if !yield(fd) {
				return
			}
		}
	}
}

func getUnqueriedChaosTXT(db *sql.DB) iter.Seq[fieldData] {
	var v4Filter string
	if !v6 {
		v4Filter = `AND ip.address LIKE '%.%'`
	}
	filter := fmt.Sprintf(`
		SELECT address, id
		FROM ip
		WHERE ch_resolved=FALSE %s
	`, v4Filter)

	return getDbFieldData(filter, db)
}

func netZoneReader(db *sql.DB, extraFilter string) iter.Seq[fieldData] {
	qs := fmt.Sprintf(`
		SELECT zone.name, zone.id
		FROM name AS zone
		WHERE zone.is_zone=TRUE %s
	`, extraFilter)
	return getDbFieldData(qs, db)
}
