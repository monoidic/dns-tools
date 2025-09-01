package main

import (
	"database/sql"
	"fmt"
	"iter"

	"github.com/monoidic/dns"
)

func insertRRWorker(db *sql.DB, seq iter.Seq[rrData]) {
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
		"vuln_ns":          "UPDATE zone_ns_ip SET axfrable=TRUE WHERE ip_id=? AND zone_id=?",
		"axfr_tried":       "UPDATE zone_ns_ip SET axfr_tried=TRUE WHERE ip_id=? AND zone_id=?",
		"self_parent_zone": "UPDATE zone2rr SET from_self=from_self|?, from_parent=from_parent|? WHERE zone_id=? AND rr_type_id=? AND rr_name_id=? AND rr_value_id=?",
	}

	insertRR(db, seq, tablesFields, namesStmts, insertRRW)
}

func insertRRW(tableMap TableMap, stmtMap StmtMap, rrD rrData) {
	switch rrD.msgtype {
	case rrDataRegular:
		zoneID := tableMap.get("name", rrD.zone.String())
		rrTypeID := tableMap.get("rr_type", rrD.rrType)
		rrNameID := tableMap.get("rr_name", rrD.rrName.String())
		rrValueID := tableMap.get("rr_value", rrD.rrValue)

		poison := !dns.IsSubDomain(rrD.zone, rrD.rrName)

		stmtMap.exec("insert", zoneID, rrTypeID, rrNameID, rrValueID, poison)

		if rrD.selfZone || rrD.parentZone {
			stmtMap.exec("self_parent_zone", rrD.selfZone, rrD.parentZone, zoneID, rrTypeID, rrNameID, rrValueID)
		}

	case rrDataZoneDone:
		zoneID := tableMap.get("name", rrD.zone.String())

		stmtMap.exec("update", zoneID)

	case rrDataZoneAxfrEnd:
		ipID := tableMap.get("ip", rrD.ip)
		zoneID := tableMap.get("name", rrD.zone.String())

		stmtMap.exec("vuln_ns", ipID, zoneID)
		stmtMap.exec("update", zoneID)

	case rrDataZoneAxfrTry:
		ipID := tableMap.get("ip", rrD.ip)
		zoneID := tableMap.get("name", rrD.zone.String())

		stmtMap.exec("axfr_tried", ipID, zoneID)
	}
}

func insertNSRR(db *sql.DB, seq iter.Seq[rrDBData]) {
	tablesFields := map[string]string{
		"name": "name",
	}
	namesStmts := map[string]string{
		"insert":          "INSERT OR IGNORE INTO zone_ns (zone_id, ns_id) VALUES (?, ?)",
		"set_zone":        "UPDATE name SET is_zone=TRUE WHERE id=?",
		"set_ns":          "UPDATE name SET is_ns=TRUE WHERE id=?",
		"set_parent_self": "UPDATE zone_ns SET in_parent_zone=in_parent_zone|?, in_self_zone=in_self_zone|? WHERE zone_id=? AND ns_id=?",
		"set_checked":     "UPDATE name SET reg_checked=TRUE WHERE id=?",
		"parsed":          "UPDATE zone2rr SET parsed=TRUE WHERE id=?",
	}

	insertRR(db, seq, tablesFields, namesStmts, nsRRF)
}

func nsRRF(tableMap TableMap, stmtMap StmtMap, ad rrDBData) {
	rr := check1(dns.NewRR(ad.rrValue.name))
	nsRR := rr.(*dns.NS)

	zoneID := tableMap.get("name", ad.rrName.name.String())
	nsID := tableMap.get("name", nsRR.Ns.String())

	stmtMap.exec("set_zone", zoneID)
	stmtMap.exec("set_ns", nsID)
	stmtMap.exec("insert", zoneID, nsID)

	if ad.fromParent || ad.fromSelf {
		stmtMap.exec("set_parent_self", ad.fromParent, ad.fromSelf, zoneID, nsID)

		if ad.fromParent {
			parentID := tableMap.get("name", nsRR.Hdr.Name.String())
			stmtMap.exec("set_checked", parentID)
		}
	}

	stmtMap.exec("parsed", ad.id)
}

func insertIPRR(db *sql.DB, seq iter.Seq[rrDBData]) {
	tablesFields := map[string]string{
		"name": "name",
		"ip":   "address",
	}
	namesStmts := map[string]string{
		"name_ip":          "INSERT OR IGNORE INTO name_ip (name_id, ip_id) VALUES (?, ?)",
		"parent_self_zone": "UPDATE name_ip SET in_parent_zone_glue=in_parent_zone_glue|?, in_self_zone=in_self_zone|? WHERE name_id=? AND ip_id=?",
		"parsed":           "UPDATE zone2rr SET parsed=TRUE WHERE id=?",
	}

	insertRR(db, seq, tablesFields, namesStmts, ipRRF)
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

	nameID := tableMap.get("name", ad.rrName.name.String())
	ipID := tableMap.get("ip", ip)

	stmtMap.exec("name_ip", nameID, ipID)

	if ad.fromParent || ad.fromSelf {
		stmtMap.exec("parent_self_zone", ad.fromParent, ad.fromSelf, nameID, ipID)
	}

	stmtMap.exec("parsed", ad.id)
}

func insertMXRR(db *sql.DB, seq iter.Seq[rrDBData]) {
	tablesFields := map[string]string{
		"name": "name",
	}
	namesStmts := map[string]string{
		"name_mx": "INSERT OR IGNORE INTO name_mx (name_id, mx_id, preference) VALUES (?, ?, ?)",
		"set_mx":  "UPDATE name SET is_mx=TRUE WHERE id=?",
		"parsed":  "UPDATE zone2rr SET parsed=TRUE WHERE id=?",
	}

	insertRR(db, seq, tablesFields, namesStmts, mxRRF)
}

func mxRRF(tableMap TableMap, stmtMap StmtMap, ad rrDBData) {
	rr := check1(dns.NewRR(ad.rrValue.name))
	defer stmtMap.exec("parsed", ad.id)

	mxRR := rr.(*dns.MX)
	dns.Canonicalize(mxRR)

	nameID := tableMap.get("name", ad.rrName.name.String())
	mxID := tableMap.get("name", mxRR.Mx.String())

	stmtMap.exec("set_mx", mxID)
	stmtMap.exec("name_mx", nameID, mxID, mxRR.Preference)
}

func insertPTRRR(db *sql.DB, seq iter.Seq[rrDBData]) {
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

	insertRR(db, seq, tablesFields, namesStmts, ptrRRF)
}

func ptrRRF(tableMap TableMap, stmtMap StmtMap, ad rrDBData) {
	if ip, err := ptrToIP(ad.rrName.name); err != nil {
		rr := check1(dns.NewRR(ad.rrValue.name))
		ptrRR := rr.(*dns.PTR)
		dns.Canonicalize(ptrRR)

		ipString := ip.String()
		ipID := tableMap.get("ip", ipString)
		ptrID := tableMap.get("name", ptrRR.Ptr.String())

		stmtMap.exec("rdns", ipID, ptrID)
		stmtMap.exec("name_to_rdns", ptrID)
		stmtMap.exec("mapped", ipID)
	}

	stmtMap.exec("parsed", ad.id)
}

func insertZoneNsIp(db *sql.DB, seq iter.Seq[zoneIP]) {
	tablesFields := map[string]string{}
	namesStmts := map[string]string{
		"zone_ns_ip": "INSERT OR IGNORE INTO zone_ns_ip (zone_id, ip_id) VALUES(?, ?)",
	}
	insertRR(db, seq, tablesFields, namesStmts, zoneNsIpRRF)
}

func insertZoneNsIpGlue(db *sql.DB, seq iter.Seq[zoneIP]) {
	tablesFields := map[string]string{}
	namesStmts := map[string]string{
		"zone_ns_ip": "INSERT OR IGNORE INTO zone_ns_ip_glue (zone_id, ip_id) VALUES(?, ?)",
	}
	insertRR(db, seq, tablesFields, namesStmts, zoneNsIpRRF)
}

func zoneNsIpRRF(_tableMap TableMap, stmtMap StmtMap, zip zoneIP) {
	stmtMap.exec("zone_ns_ip", zip.zone.id, zip.ip.id)
}
