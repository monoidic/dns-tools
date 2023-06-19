package main

import (
	"database/sql"
	"fmt"

	"github.com/monoidic/dns"
)

func insertRRWorker(db *sql.DB, rrDataChan <-chan rrData) {
	tablesFields := map[string]string{
		"name":     "name",
		"rr_type":  "name",
		"rr_name":  "name",
		"rr_value": "value",
		"ip":       "address",
	}
	namesStmts := map[string]string{
		"insert":           "INSERT OR IGNORE INTO zone2rr (zone_id, rr_type_id, rr_name_id, rr_value_id, poison) VALUES (?, ?, ?, ?, ?)",
		"update":           "UPDATE name SET inserted=TRUE, is_zone=TRUE WHERE id=?",
		"vuln_ns":          "INSERT INTO axfrable_ns (ip_id, zone_id, scan_time) VALUES (?, ?, ?) ON CONFLICT DO UPDATE SET scan_time=excluded.scan_time",
		"axfr_tried":       "UPDATE name SET axfr_tried=TRUE WHERE id=?",
		"self_parent_zone": "UPDATE zone2rr SET from_self=from_self|?, from_parent=from_parent|? WHERE zone_id=? AND rr_type_id=? AND rr_name_id=? AND rr_value_id=?",
	}

	insertRR(db, rrDataChan, tablesFields, namesStmts, insertRRW)
}

func insertRRW(tableMap TableMap, stmtMap StmtMap, rrD rrData) {
	switch rrD.msgtype {
	case rrDataRegular:
		zoneID := tableMap.get("name", rrD.zone)
		rrTypeID := tableMap.get("rr_type", rrD.rrType)
		rrNameID := tableMap.get("rr_name", rrD.rrName)
		rrValueID := tableMap.get("rr_value", rrD.rrValue)

		poison := !dns.IsSubDomain(rrD.zone, rrD.rrName)

		stmtMap.exec("insert", zoneID, rrTypeID, rrNameID, rrValueID, poison)

		if rrD.selfZone || rrD.parentZone {
			stmtMap.exec("self_parent_zone", rrD.selfZone, rrD.parentZone, zoneID, rrTypeID, rrNameID, rrValueID)
		}

	case rrDataZoneDone:
		zoneID := tableMap.get("name", rrD.zone)

		stmtMap.exec("update", zoneID)

	case rrDataZoneAxfrEnd:
		ipID := tableMap.get("ip", rrD.ip)
		zoneID := tableMap.get("name", rrD.zone)

		stmtMap.exec("vuln_ns", ipID, zoneID, rrD.scanned)
		stmtMap.exec("update", zoneID)

	case rrDataZoneAxfrTry:
		zoneID := tableMap.get("name", rrD.zone)

		stmtMap.exec("axfr_tried", zoneID)
	}
}

func insertNSRR(db *sql.DB, rrChan <-chan rrDBData) {
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

	insertRR(db, rrChan, tablesFields, namesStmts, nsRRF)
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

func insertIPRR(db *sql.DB, rrChan <-chan rrDBData) {
	tablesFields := map[string]string{
		"name": "name",
		"ip":   "address",
	}
	namesStmts := map[string]string{
		"name_ip":          "INSERT OR IGNORE INTO name_ip (name_id, ip_id) VALUES (?, ?)",
		"parent_self_zone": "UPDATE name_ip SET in_parent_zone_glue=in_parent_zone_glue|?, in_self_zone=in_self_zone|? WHERE name_id=? AND ip_id=?",
		"parsed":           "UPDATE zone2rr SET parsed=TRUE WHERE id=?",
	}

	insertRR(db, rrChan, tablesFields, namesStmts, ipRRF)
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

func insertMXRR(db *sql.DB, rrChan <-chan rrDBData) {
	tablesFields := map[string]string{
		"name": "name",
	}
	namesStmts := map[string]string{
		"name_mx": "INSERT OR IGNORE INTO name_mx (name_id, mx_id, preference) VALUES (?, ?, ?)",
		"set_mx":  "UPDATE name SET is_mx=TRUE WHERE id=?",
		"parsed":  "UPDATE zone2rr SET parsed=TRUE WHERE id=?",
	}

	insertRR(db, rrChan, tablesFields, namesStmts, mxRRF)
}

func mxRRF(tableMap TableMap, stmtMap StmtMap, ad rrDBData) {
	rr := check1(dns.NewRR(ad.rrValue.name))

	mxRR := rr.(*dns.MX)
	normalizeRR(mxRR)

	nameID := tableMap.get("name", ad.rrName.name)
	mxID := tableMap.get("name", mxRR.Mx)

	stmtMap.exec("set_mx", mxID)
	stmtMap.exec("name_mx", nameID, mxID, mxRR.Preference)
	stmtMap.exec("parsed", ad.id)
}

func insertPTRRR(db *sql.DB, rrChan <-chan rrDBData) {
	tablesFields := map[string]string{
		"ip":   "address",
		"name": "name",
	}
	namesStmts := map[string]string{
		"name_to_rdns": "UPDATE name SET is_rdns=TRUE WHERE id=?",
		"rdns":         "INSERT OR IGNORE INTO rdns (ip_id, name_id) VALUES(?, ?)",
		"mapped":       "UPDATE ip SET rdns_mapped=TRUE WHERE id=?",
		"parsed":       "UPDATE zone2rr SET parsed=TRUE WHERE id=?",
	}

	insertRR(db, rrChan, tablesFields, namesStmts, ptrRRF)
}

func ptrRRF(tableMap TableMap, stmtMap StmtMap, ad rrDBData) {
	if ip, err := ptrToIP(ad.rrName.name); err != nil {
		rr := check1(dns.NewRR(ad.rrValue.name))
		ptrRR := rr.(*dns.PTR)
		normalizeRR(ptrRR)

		ipString := ip.String()
		ipID := tableMap.get("ip", ipString)
		ptrID := tableMap.get("name", ptrRR.Ptr)

		stmtMap.exec("rdns", ipID, ptrID)
		stmtMap.exec("name_to_rdns", ptrID)
		stmtMap.exec("mapped", ipID)
	}

	stmtMap.exec("parsed", ad.id)
}
