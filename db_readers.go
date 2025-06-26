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
		WHERE ch_resolved=FALSE
		AND ip.responsive=TRUE
		%s
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

func zoneNsIpReader(db *sql.DB) iter.Seq[zoneIP] {
	return func(yield func(zoneIP) bool) {
		qs := `
		SELECT DISTINCT zone.name, ip.address, zone.id, ip.id
		FROM zone_ns
		INNER JOIN name AS zone ON zone_ns.zone_id = zone.id
		INNER JOIN name_ip ON zone_ns.ns_id = name_ip.name_id
		INNER JOIN ip ON name_ip.ip_id = ip.id
		WHERE zone.is_zone=TRUE
	`

		tx := check1(db.Begin())
		rows := check1(tx.Query(qs))

		for rows.Next() {
			var zip zoneIP
			check(rows.Scan(&zip.zone.name, &zip.ip.name, &zip.zone.id, &zip.ip.id))
			if !yield(zip) {
				break
			}
		}

		check(rows.Close())
		check(tx.Commit())
	}
}

func zoneNsIpParentReader(db *sql.DB) iter.Seq[zoneIP] {
	return func(yield func(zoneIP) bool) {
		qs := `
		SELECT DISTINCT zone.name, ip.address, zone.id, ip.id
		FROM name AS zone
		INNER JOIN name AS parent ON zone.parent_id=parent.id
		INNER JOIN zone_ns ON zone_ns.zone_id=parent.id
		INNER JOIN name_ip ON name_ip.name_id=zone_ns.ns_id 
		INNER JOIN ip ON name_ip.ip_id = ip.id
		WHERE zone.is_zone=TRUE AND parent.is_zone=TRUE
		AND ip.responsive=TRUE
	`

		tx := check1(db.Begin())
		rows := check1(tx.Query(qs))

		for rows.Next() {
			var zip zoneIP
			check(rows.Scan(&zip.zone.name, &zip.ip.name, &zip.zone.id, &zip.ip.id))
			if !yield(zip) {
				break
			}
		}

		check(rows.Close())
		check(tx.Commit())
	}
}

func parentNSReader(db *sql.DB) iter.Seq[zoneIP] {
	return func(yield func(zoneIP) bool) {
		qs := `
		SELECT DISTINCT zone.name, ip.address, zone.id, ip.id
		FROM zone_ns_ip_glue
		INNER JOIN name AS zone ON zone_ns_ip_glue.zone_id=zone.id
		INNER JOIN ip ON zone_ns_ip_glue.ip_id=ip.id
		WHERE zone_ns_ip_glue.fetched=FALSE
		AND ip.responsive=TRUE
	`

		tx := check1(db.Begin())
		rows := check1(tx.Query(qs))

		for rows.Next() {
			var zip zoneIP
			check(rows.Scan(&zip.zone.name, &zip.ip.name, &zip.zone.id, &zip.ip.id))
			if !yield(zip) {
				break
			}
		}

		check(rows.Close())
		check(tx.Commit())
	}
}
