package main

import (
	"database/sql"
	"fmt"
	"iter"
	"net"
	"strings"
	"sync"

	"github.com/monoidic/dns"
)

// `netWriter` wrapper for MX queries
func mxWriter(db *sql.DB, seq iter.Seq[nameData]) {
	tablesFields := map[string]string{
		"name":     "name",
		"rr_type":  "name",
		"rr_name":  "name",
		"rr_value": "value",
	}
	namesStmts := map[string]string{
		"zone2rr": "INSERT OR IGNORE INTO zone2rr (zone_id, rr_type_id, rr_name_id, rr_value_id) VALUES (?, ?, ?, ?)",
		"update":  "UPDATE name SET mx_resolved=TRUE, reg_checked=TRUE, registered=? WHERE id=?",
	}

	netWriter(db, seq, tablesFields, namesStmts, mxResolverWorker, mxWrite)
}

// `insertF` for MX
func mxWrite(tableMap TableMap, stmtMap StmtMap, mxd mxData) {
	zoneID := mxd.id
	defer stmtMap.exec("update", mxd.registered, zoneID)

	if len(mxd.results) > 0 {
		rrTypeID := tableMap.get("rr_type", "MX")
		rrNameID := tableMap.get("rr_name", mxd.name.String())

		for _, mx := range mxd.results {
			rrValueID := tableMap.get("rr_value", mx.String())
			stmtMap.exec("zone2rr", zoneID, rrTypeID, rrNameID, rrValueID)
		}
	}
}

// `netWriter` wrapper for checking for active nameservers
func checkUpWriter(db *sql.DB, seq iter.Seq[checkUpData]) {
	tablesFields := map[string]string{}
	namesStmts := map[string]string{
		"update": "UPDATE ip SET responsive=?, resp_checked=TRUE WHERE id=?",
	}

	netWriter(db, seq, tablesFields, namesStmts, checkUpWorker, checkUpWrite)
}

// `insertF` for active nameservers
func checkUpWrite(_ TableMap, stmtMap StmtMap, cu checkUpData) {
	stmtMap.exec("update", cu.success, cu.ipID)
}

// `netWriter` wrapper for PTR queries
func rdnsWriter(db *sql.DB, seq iter.Seq[fieldData]) {
	tablesFields := map[string]string{
		"name":     "name",
		"rr_type":  "name",
		"rr_name":  "name",
		"rr_value": "value",
	}
	namesStmts := map[string]string{
		"zone2rr": "INSERT OR IGNORE INTO zone2rr (zone_id, rr_type_id, rr_name_id, rr_value_id) VALUES (?, ?, ?, ?)",
		"mapped":  "UPDATE ip SET rdns_mapped=TRUE WHERE id=?",
	}

	netWriter(db, seq, tablesFields, namesStmts, rdnsWorker, rdnsWrite)
}

// `insertF` for PTR
func rdnsWrite(tableMap TableMap, stmtMap StmtMap, fdr rrFdResults[dns.PTR]) {
	ipID := fdr.id
	defer stmtMap.exec("mapped", ipID)

	if len(fdr.results) == 0 {
		return
	}
	rrTypeID := tableMap.get("rr_type", "PTR")

	for _, ptr := range fdr.results {
		rrNameID := tableMap.get("rr_name", ptr.Hdr.Name.String())
		rrValueID := tableMap.get("rr_value", ptr.String())

		stmtMap.exec("zone2rr", fdr.id, rrTypeID, rrNameID, rrValueID)
	}
}

// `readerF` for SPF TXT queries
func spfRRWriter(db *sql.DB, seq iter.Seq[nameData]) {
	tablesFields := map[string]string{
		"name":       "name",
		"spf_record": "value",
	}
	namesStmts := map[string]string{
		"spf":           "INSERT OR IGNORE INTO spf (name_id, spf_record_id) VALUES (?, ?)",
		"spfname":       "INSERT INTO spf_name (name_id, spf_record_id, spfname) VALUES (?, ?, ?) ON CONFLICT DO UPDATE SET spfname=spfname|excluded.spfname",
		"spf_tried":     "UPDATE name SET spf_tried=TRUE WHERE id=?",
		"spf_valid":     "UPDATE spf_record SET valid=?, any_unknown=?, error=? WHERE id=?",
		"spf_duplicate": "UPDATE spf SET duplicate=TRUE WHERE name_id=? AND spf_record_id=?",
	}

	netWriter(db, seq, tablesFields, namesStmts, txtWorker, spfWrite)
}

// `insertF` for SPF TXT
func spfWrite(tableMap TableMap, stmtMap StmtMap, fdr fdResults) {
	nameID := fdr.id
	defer stmtMap.exec("spf_tried", nameID)

	var spfRecords []string

	for _, s := range fdr.results {
		if strings.HasPrefix(s, "v=spf1") {
			spfRecords = append(spfRecords, s)
		}
	}

	for _, s := range spfRecords {
		recordID := tableMap.get("spf_record", s)
		stmtMap.exec("spf", nameID, recordID)
		if len(spfRecords) > 1 {
			stmtMap.exec("spf_duplicate", nameID, recordID)
		}

		data, err := parseSPF([]byte(s))
		err_s := ""
		if err != nil {
			err_s = err.Error()
		}
		stmtMap.exec("spf_valid", err == nil, data.anyUnknown, err_s, recordID)
		if err == nil {
			for i, list := range [][]string{data.names, data.spfNames} {
				spfName := i == 1
				for _, name := range list {
					spfNameID := tableMap.get("name", name)
					stmtMap.exec("spfname", spfNameID, recordID, spfName)
				}
			}
		}
	}
}

// `netWriter` wrapper for DMARC TXT queries
func dmarcRRWriter(db *sql.DB, seq iter.Seq[nameData]) {
	tablesFields := map[string]string{
		"name":         "name",
		"dmarc_record": "value",
	}
	namesStmts := map[string]string{
		"dmarc":           "INSERT OR IGNORE INTO dmarc (name_id, dmarc_record_id) VALUES (?, ?)",
		"dmarc_tried":     "UPDATE name SET dmarc_tried=TRUE WHERE id=?",
		"dmarc_duplicate": "UPDATE dmarc SET duplicate=TRUE WHERE name_id=? AND dmarc_record_id=?",
		"dmarc_valid":     "UPDATE dmarc_record SET valid=?, error=? WHERE id=?",
	}

	netWriter(db, seq, tablesFields, namesStmts, txtWorker, dmarcWrite)
}

// `insertF` for DMARC TXT
func dmarcWrite(tableMap TableMap, stmtMap StmtMap, fdr fdResults) {
	nameID := fdr.id // ID with no '_dmarc.'
	defer stmtMap.exec("dmarc_tried", nameID)

	var dmarcRecords []string

	for _, s := range fdr.results {
		if strings.HasPrefix(s, "v=DMARC1") {
			dmarcRecords = append(dmarcRecords, s)
		}
	}

	for _, s := range dmarcRecords {
		recordID := tableMap.get("dmarc_record", s)
		stmtMap.exec("dmarc", nameID, recordID)
		if len(dmarcRecords) > 1 {
			stmtMap.exec("dmarc_duplicate", nameID, recordID)
		}
		if _, err := parseDmarc(s); err != nil {
			stmtMap.exec("dmarc_valid", false, err.Error(), recordID)
		}
	}
}

func chaosTXTWriter(db *sql.DB, seq iter.Seq[fieldData]) {
	tablesFields := map[string]string{
		"name":                 "name",
		"chaos_response_value": "value",
	}
	namesStmts := map[string]string{
		"chaos_query":    "INSERT OR IGNORE INTO chaos_query (name_id, ip_id) VALUES (?, ?)",
		"chaos_response": "INSERT OR IGNORE INTO chaos_response (chaos_query_id, chaos_response_value_id, name_id) VALUES ((SELECT id FROM chaos_query WHERE name_id=? AND ip_id=?), ?, ?)",
		"chaos_queried":  "UPDATE ip SET ch_resolved=TRUE WHERE id=?",
	}

	netWriter(db, seq, tablesFields, namesStmts, chaosTXTWorker, chaosTXTWrite)
}

// `insertF` for Chaosnet TXT
func chaosTXTWrite(tableMap TableMap, stmtMap StmtMap, chr chaosResults) {
	ipID := chr.id
	defer stmtMap.exec("chaos_queried", ipID)

	for _, result := range chr.results {
		queriedNameID := tableMap.get("name", result.queried.String())
		resultNameID := tableMap.get("name", result.resultName.String())
		responseID := tableMap.get("chaos_response_value", result.value)

		stmtMap.exec("chaos_query", queriedNameID, ipID)
		stmtMap.exec("chaos_response", queriedNameID, ipID, responseID, resultNameID)
	}
}

// `readerF` for checking for active nameservers
func checkUpReader(db *sql.DB) iter.Seq[checkUpData] {
	return func(yield func(checkUpData) bool) {
		// each NS IP and one zone it is meant to serve
		tx := check1(db.Begin())
		var v4Filter string
		if !v6 {
			v4Filter = `AND ip.address LIKE '%.%'`
		}
		rows := check1(tx.Query(fmt.Sprintf(`
		SELECT DISTINCT ip.address, zone.name, ip.id
		FROM zone_ns
		INNER JOIN name AS zone ON zone_ns.zone_id = zone.id
		INNER JOIN name_ip ON name_ip.name_id = zone_ns.ns_id
		INNER JOIN ip ON name_ip.ip_id = ip.id
		WHERE ip.resp_checked=FALSE AND zone.is_zone=TRUE %s
		GROUP BY ip.id
	`, v4Filter)))

		for rows.Next() {
			var ip, zone string
			var ipID int64
			check(rows.Scan(&ip, &zone, &ipID))
			if !yield(checkUpData{
				ns:   net.JoinHostPort(ip, "53"),
				zone: mustParseName(zone),
				ipID: ipID,
			}) {
				break
			}
		}

		check(rows.Close())
		check(tx.Commit())
	}
}

// `readerF` for A/AAAA
func zoneIPReader(db *sql.DB) iter.Seq[zoneIP] {
	return func(yield func(zoneIP) bool) {
		qs := `
		SELECT zone.name, ip.address
		FROM zone_ns_ip
		INNER JOIN name AS zone ON zone_ns_ip.zone_id=zone.id
		INNER JOIN ip ON zone_ns_ip.ip_id = ip.id
		WHERE ip.responsive=TRUE AND zone_ns_ip.axfr_tried=FALSE
	`

		tx := check1(db.Begin())
		rows := check1(tx.Query(qs))

		for rows.Next() {
			var zip zoneIP
			var zoneName string
			check(rows.Scan(&zoneName, &zip.ip.name))
			zip.zone.name = mustParseName(zoneName)
			zip.ip.name = net.JoinHostPort(zip.ip.name, "53")
			if !yield(zip) {
				break
			}
		}

		check(rows.Close())
		check(tx.Commit())
	}
}

// `readerF` for fetching NS glue records from parent zones
func parentNSWriter(db *sql.DB, seq iter.Seq[zoneIP]) {
	tablesFields := map[string]string{
		"name": "name",
		"ip":   "address",
	}
	namesStmts := map[string]string{
		"insert_name_ip": "INSERT INTO name_ip (name_id, ip_id, in_parent_zone_glue) VALUES (?, ?, TRUE) ON CONFLICT DO UPDATE SET in_parent_zone_glue=TRUE",
		"insert_zone_ns": "INSERT INTO zone_ns (zone_id, ns_id, in_parent_zone) VALUES (?, ?, TRUE) ON CONFLICT DO UPDATE SET in_parent_zone=TRUE",
		"name_to_ns":     "UPDATE name SET is_ns=TRUE WHERE id=?",
		"registered":     "UPDATE name SET registered=TRUE, reg_checked=TRUE WHERE id=?",
		"fetched":        "UPDATE zone_ns_ip_glue SET fetched=TRUE WHERE zone_ns_ip_glue.zone_id=? AND zone_ns_ip_glue.ip_id=?",
	}

	netWriter(db, seq, tablesFields, namesStmts, parentNSResolverWorker, parentNSWrite)
}

// `insertF` for NS glue records from parent zone
func parentNSWrite(tableMap TableMap, stmtMap StmtMap, nsr parentNSResults) {
	zoneID := nsr.zone.id
	ipID := nsr.ip.id

	defer stmtMap.exec("fetched", zoneID, ipID)

	if len(nsr.ns) == 0 {
		return
	}

	stmtMap.exec("registered", zoneID)

	for _, a := range nsr.a {
		nameID := tableMap.get("name", a.Hdr.Name.String())
		ipID := tableMap.get("ip", a.A.String())
		stmtMap.exec("insert_name_ip", nameID, ipID)
	}

	for _, aaaa := range nsr.aaaa {
		nameID := tableMap.get("name", aaaa.Hdr.Name.String())
		ipID := tableMap.get("ip", aaaa.AAAA.String())
		stmtMap.exec("insert_name_ip", nameID, ipID)
	}

	for _, ns := range nsr.ns {
		nsID := tableMap.get("name", ns.Ns.String())
		stmtMap.exec("name_to_ns", nsID)
		stmtMap.exec("insert_zone_ns", zoneID, nsID)
	}
}

// `netWriter` wrapper for NS queries
func netNSWriter(db *sql.DB, seq iter.Seq[nameData]) {
	tablesFields := map[string]string{
		"name":     "name",
		"rr_type":  "name",
		"rr_name":  "name",
		"rr_value": "value",
	}
	namesStmts := map[string]string{
		"insert":     "INSERT INTO zone_ns (zone_id, ns_id, in_self_zone) VALUES (?, ?, TRUE) ON CONFLICT DO UPDATE SET in_self_zone=TRUE",
		"update":     "UPDATE name SET ns_resolved=TRUE WHERE id=?",
		"registered": "UPDATE name SET registered=TRUE, reg_checked=TRUE WHERE id=?",
		"zone2rr":    "INSERT INTO zone2rr (zone_id, rr_type_id, rr_name_id, rr_value_id, inserted) VALUES (?, ?, ?, ?, TRUE) ON CONFLICT DO UPDATE SET inserted=TRUE",
	}

	netWriter(db, seq, tablesFields, namesStmts, nsResolverWorker, nsWrite)
}

// `insertF` for NS
func nsWrite(tableMap TableMap, stmtMap StmtMap, nsd rrResults[dns.NS]) {
	zoneID := nsd.id
	defer stmtMap.exec("update", zoneID)

	if len(nsd.results) == 0 {
		return
	}

	stmtMap.exec("registered", zoneID)
	rrTypeID := tableMap.get("rr_type", "NS")
	rrNameID := tableMap.get("rr_name", nsd.name.String())

	for _, ns := range nsd.results {
		dns.Canonicalize(&ns)
		nsID := tableMap.get("name", ns.Ns.String())

		stmtMap.exec("insert", zoneID, nsID)

		rrValueID := tableMap.get("rr_value", ns.String())
		stmtMap.exec("zone2rr", zoneID, rrTypeID, rrNameID, rrValueID)
	}
}

// `netWriter` wrapper for A/AAAA queries
func netIPWriter(db *sql.DB, seq iter.Seq[nameData]) {
	tablesFields := map[string]string{
		"ip":   "address",
		"name": "name",
	}
	namesStmts := map[string]string{
		// TODO zone2rr
		// "zone2rr":          "INSERT OR IGNORE INTO zone2rr (zone_id, rr_type_id, rr_name_id, rr_value_id) VALUES (?, ?, ?, ?)",
		// "zone2rr_inserted": "UPDATE zone2rr SET inserted=TRUE WHERE zone_id=? AND rr_type_id=? AND rr_name_id=? AND rr_value_id=?",
		"insert":      "INSERT INTO name_ip (name_id, ip_id, in_self_zone) VALUES (?, ?, TRUE) ON CONFLICT DO UPDATE SET in_self_zone=TRUE",
		"update":      "UPDATE name SET addr_resolved=TRUE, reg_checked=TRUE, registered=? WHERE id=?",
		"cname_entry": "UPDATE name SET reg_checked=TRUE, registered=?, cname_tgt_id=? WHERE id=?",
	}

	netWriter(db, seq, tablesFields, namesStmts, addrResolverWorker, ipWrite)
}

// `insertF` for A/AAAA
func ipWrite(tableMap TableMap, stmtMap StmtMap, ad addrData) {
	nameID := ad.id
	registered := ad.registered
	defer stmtMap.exec("update", registered, nameID)

	if len(ad.cname) > 0 {
		fmt.Printf("cname from address %s\n", ad.name)
		finalRegistered, loop := cnameChainFinalEntry(ad.cname)

		for _, entry := range ad.cname {
			srcID := tableMap.get("name", entry.Hdr.Name.String())
			targetID := tableMap.get("name", entry.Target.String())
			entryRegistered := registered || loop
			if !entryRegistered {
				entryRegistered = entry.Hdr.Name != finalRegistered
			}

			stmtMap.exec("cname_entry", entryRegistered, targetID, srcID)
		}
	}

	for _, a := range ad.a {
		ipID := tableMap.get("ip", a.A.String())

		stmtMap.exec("insert", nameID, ipID)
	}

	for _, aaaa := range ad.aaaa {
		ipID := tableMap.get("ip", aaaa.AAAA.String())

		stmtMap.exec("insert", nameID, ipID)
	}
}

// `resolverWorker` wrapper to check if a given host is responsive
func checkUpWorker(inChan <-chan retryWrap[checkUpData, empty], refeedChan chan<- retryWrap[checkUpData, empty], outChan chan<- checkUpData, retryWg *sync.WaitGroup) {
	msg := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Opcode: dns.OpcodeQuery,
			Rcode:  dns.RcodeSuccess,
		},
		Question: []dns.Question{{
			Qclass: dns.ClassINET,
			Qtype:  dns.TypeSOA,
		}},
	}
	msgSetSize(&msg)

	resolverWorker(inChan, refeedChan, outChan, &msg, checkUpResolve, retryWg)
}

// `resolverWorker` wrapper to perform PTR queries
func rdnsWorker(inChan <-chan retryWrap[fieldData, empty], refeedChan chan<- retryWrap[fieldData, empty], outChan chan<- rrFdResults[dns.PTR], retryWg *sync.WaitGroup) {
	msg := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Opcode:           dns.OpcodeQuery,
			RecursionDesired: true,
			Rcode:            dns.RcodeSuccess,
		},
		Question: []dns.Question{{
			Qclass: dns.ClassINET,
			Qtype:  dns.TypePTR,
		}},
	}
	msgSetSize(&msg)

	resolverWorker(inChan, refeedChan, outChan, &msg, rdnsResolve, retryWg)
}

// `resolverWorker` wrapper to perform TXT queries
func txtWorker(inChan <-chan retryWrap[nameData, empty], refeedChan chan<- retryWrap[nameData, empty], outChan chan<- fdResults, retryWg *sync.WaitGroup) {
	msg := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Opcode:           dns.OpcodeQuery,
			RecursionDesired: true,
			Rcode:            dns.RcodeSuccess,
		},
		Question: []dns.Question{{
			Qclass: dns.ClassINET,
			Qtype:  dns.TypeTXT,
		}},
	}
	msgSetSize(&msg)

	resolverWorker(inChan, refeedChan, outChan, &msg, txtResolve, retryWg)
}

// `resolverWorker` wrapper to perform Chaosnet TXT queries
func chaosTXTWorker(inChan <-chan retryWrap[fieldData, chaosResults], refeedChan chan<- retryWrap[fieldData, chaosResults], outChan chan<- chaosResults, retryWg *sync.WaitGroup) {
	msg := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Opcode: dns.OpcodeQuery,
			Rcode:  dns.RcodeSuccess,
		},
		Question: []dns.Question{{
			Qclass: dns.ClassCHAOS,
			Qtype:  dns.TypeTXT,
		}},
	}
	msgSetSize(&msg)

	resolverWorker(inChan, refeedChan, outChan, &msg, chaosTXTResolve, retryWg)
}

// `resolverWorker` wrapper to perform NS queries on a parent zone for glue records
func parentNSResolverWorker(inChan <-chan retryWrap[zoneIP, empty], refeedChan chan<- retryWrap[zoneIP, empty], outChan chan<- parentNSResults, retryWg *sync.WaitGroup) {
	msg := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Opcode: dns.OpcodeQuery,
			Rcode:  dns.RcodeSuccess,
		},
		Question: []dns.Question{{
			Qclass: dns.ClassINET,
			Qtype:  dns.TypeNS,
		}},
	}
	msgSetSize(&msg)

	resolverWorker(inChan, refeedChan, outChan, &msg, parentNsResolve, retryWg)
}

// `resolverWorker` wrapper to query for arbitrary name:rrtype pairs received from NSEC walking results
func nsecWalkResultResolver(inChan <-chan retryWrap[rrDBData, empty], refeedChan chan<- retryWrap[rrDBData, empty], outChan chan<- nsecWalkResolveRes, retryWg *sync.WaitGroup) {
	msg := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Opcode:           dns.OpcodeQuery,
			RecursionDesired: true,
			Rcode:            dns.RcodeSuccess,
		},
		Question: []dns.Question{{
			Qclass: dns.ClassINET,
		}},
	}
	msgSetSize(&msg)

	resolverWorker(inChan, refeedChan, outChan, &msg, nsecWalkResultResolve, retryWg)
}

// `processsData` function
func nsecWalkResultResolve(connCache *connCache, msg *dns.Msg, rrD *retryWrap[rrDBData, empty]) (res nsecWalkResolveRes, err error) {
	msg.Question[0].Name = rrD.val.rrName.name
	msg.Question[0].Qtype = dns.StringToType[rrD.val.rrType.name]
	res.rrDBData = rrD.val

	var response *dns.Msg

	response, err = plainResolveRandom(msg, connCache)
	if err != nil {
		return
	}

	if response == nil {
		return
	}

	res.results = make([]rrData, len(response.Answer))

	for i, rr := range response.Answer {
		dns.Canonicalize(rr)
		hdr := rr.Header()
		resRRD := rrData{
			rrValue: rr.String(),
			rrType:  dns.TypeToString[hdr.Rrtype],
			rrName:  hdr.Name,
		}
		res.results[i] = resRRD
	}

	return
}

// `processsData` function
func nsResolve(connCache *connCache, msg *dns.Msg, fd *retryWrap[nameData, empty]) (rrR rrResults[dns.NS], err error) {
	msg.Question[0].Name = fd.val.name
	var response *dns.Msg
	rrR.nameData = fd.val

	response, err = plainResolveRandom(msg, connCache)
	if err != nil {
		return
	}

	if response != nil {
		for _, rr := range response.Answer {
			switch rrT := rr.(type) {
			case *dns.NS:
				rrR.results = append(rrR.results, *rrT)
			}
		}
	}

	return
}

// `processsData` function
func mxResolve(connCache *connCache, msg *dns.Msg, fd *retryWrap[nameData, empty]) (mxd mxData, err error) {
	msg.Question[0].Name = fd.val.name
	var response *dns.Msg
	var results []dns.MX
	registered := true

	response, err = plainResolveRandom(msg, connCache)
	if err != nil {
		return
	}

	if response != nil {
		for _, rr := range response.Answer {
			switch rrT := rr.(type) {
			case *dns.MX:
				dns.Canonicalize(rrT)
				results = append(results, *rrT)
			}
		}
		registered = response.Rcode != dns.RcodeNameError
	}

	mxd = mxData{rrResults: rrResults[dns.MX]{results: results, nameData: fd.val}, registered: registered}
	return
}

// `processsData` function
func addrResolve(connCache *connCache, msg *dns.Msg, fd *retryWrap[nameData, addrData]) (ad addrData, err error) {
	msg.Question[0].Name = fd.val.name

	qTypes := []dns.Type{dns.TypeA, dns.TypeAAAA}

	for i := fd.stage; i < len(qTypes); i++ {
		fd.stage = i
		qtype := qTypes[i]
		msg.Question[0].Qtype = qtype
		var response *dns.Msg

		response, err = plainResolveRandom(msg, connCache)
		if err != nil {
			if fd.retriesLeft == 0 {
				// try next qtype
				fd.retriesLeft = retries
				err = nil
				continue
			}
			return
		}

		for _, rr := range response.Answer {
			switch rrT := rr.(type) {
			case *dns.A:
				dns.Canonicalize(rrT)
				fd.tmp.a = append(fd.tmp.a, *rrT)
			case *dns.AAAA:
				dns.Canonicalize(rrT)
				fd.tmp.aaaa = append(fd.tmp.aaaa, *rrT)
			case *dns.CNAME:
				dns.Canonicalize(rrT)
				fd.tmp.cname = append(fd.tmp.cname, *rrT)
			}
		}

		fd.tmp.registered = response.Rcode != dns.RcodeNameError
	}
	ad = fd.tmp
	ad.nameData = fd.val

	return
}

// `processsData` function
func parentCheckResolve(connCache *connCache, msg *dns.Msg, cpIn *retryWrap[childParent, empty]) (cp childParent, err error) {
	cp = cpIn.val

	msg.Question[0].Name = cp.parentGuess
	var res *dns.Msg

	res, err = plainResolveRandom(msg, connCache)
	if err != nil {
		return
	}

	var soa *dns.SOA

parentCheckSOALoop:
	for _, rrL := range [][]dns.RR{res.Ns, res.Answer} {
		for _, rr := range rrL {
			switch rrT := rr.(type) {
			case *dns.SOA:
				soa = rrT
				break parentCheckSOALoop
			}
		}
	}

	if soa != nil {
		dns.Canonicalize(soa)
		realParent := soa.Hdr.Name
		cp.parent.name = realParent
		cp.resolved = true
		cp.registered = res.Rcode != dns.RcodeNameError
	}

	return
}

// `processsData` function
func checkUpResolve(connCache *connCache, msg *dns.Msg, cuIn *retryWrap[checkUpData, empty]) (cu checkUpData, err error) {
	cu = cuIn.val
	msg.Question[0].Name = cu.zone
	cu.registered = true

	res, err := plainResolve(msg, connCache, cu.ns)
	if err == nil {
		cu.registered = res.Rcode != dns.RcodeNameError
		cu.success = true
	}

	return
}

// `processsData` function
func rdnsResolve(connCache *connCache, msg *dns.Msg, fd *retryWrap[fieldData, empty]) (rrR rrFdResults[dns.PTR], err error) {
	if addr, err := dns.ReverseAddr(fd.val.name); err == nil {
		msg.Question[0].Name = addr
	} else {
		fmt.Printf("fd.val.name = %q\n", fd.val.name)
		panic(err)
	}
	var res *dns.Msg
	var results []dns.PTR

	res, err = plainResolveRandom(msg, connCache)
	if err != nil {
		return
	}

	if res != nil {
		for _, rr := range res.Answer {
			switch rrT := rr.(type) {
			case *dns.PTR:
				dns.Canonicalize(rrT)
				results = append(results, *rrT)
			}
		}
	}

	rrR = rrFdResults[dns.PTR]{fieldData: fd.val, results: results}
	return
}

// `processsData` function
func txtResolve(connCache *connCache, msg *dns.Msg, fd *retryWrap[nameData, empty]) (fdR fdResults, err error) {
	msg.Question[0].Name = fd.val.name
	var results []string
	var res *dns.Msg

	res, err = plainResolveRandom(msg, connCache)
	if err != nil {
		return
	}

	if res != nil {
		for _, rr := range res.Answer {
			switch rrT := rr.(type) {
			case *dns.TXT:
				results = append(results, rrT.Txt.BareString())
			}
		}
	}

	fdR = fdResults{nameData: fd.val, results: results}
	return
}

func chaosTXTResolve(connCache *connCache, msg *dns.Msg, fd *retryWrap[fieldData, chaosResults]) (cr chaosResults, err error) {
	nameserver := net.JoinHostPort(fd.val.name, "53")

	for i := fd.stage; i < len(chaosTXTNames); i++ {
		fd.stage = i
		name := chaosTXTNames[i]
		msg.Question[0].Name = name
		var res *dns.Msg

		res, err = plainResolve(msg, connCache, nameserver)
		if err != nil {
			if fd.retriesLeft == 0 {
				// skip to next entry
				fd.retriesLeft = retries
				err = nil
				continue
			}
			return
		}

		for _, rr := range res.Answer {
			switch rrT := rr.(type) {
			case *dns.TXT:
				fd.tmp.results = append(fd.tmp.results, chaosResult{
					queried:    name,
					resultName: rrT.Hdr.Name.Canonical(),
					value:      rrT.Txt.String(),
				})
			}
		}
	}

	cr = fd.tmp
	cr.fieldData = fd.val

	return
}

// `processsData` function
func parentNsResolve(connCache *connCache, msg *dns.Msg, fdr *retryWrap[zoneIP, empty]) (pr parentNSResults, err error) {
	msg.Question[0].Name = fdr.val.zone.name

	nameserver := net.JoinHostPort(fdr.val.ip.name, "53")
	var response *dns.Msg

	response, err = plainResolve(msg, connCache, nameserver)
	if err != nil {
		return
	}

	for _, rr := range response.Ns {
		switch rrT := rr.(type) {
		case *dns.NS:
			dns.Canonicalize(rrT)
			pr.ns = append(pr.ns, *rrT)
		}
	}

	for _, rr := range response.Extra {
		switch rrT := rr.(type) {
		case *dns.A:
			dns.Canonicalize(rrT)
			pr.a = append(pr.a, *rrT)
		case *dns.AAAA:
			dns.Canonicalize(rrT)
			pr.aaaa = append(pr.aaaa, *rrT)
		}
	}

	pr.zoneIP = fdr.val

	return
}

// `resolverWorker` wrapper to perform NS queries
func nsResolverWorker(dataChan <-chan retryWrap[nameData, empty], refeedChan chan<- retryWrap[nameData, empty], outChan chan<- rrResults[dns.NS], retryWg *sync.WaitGroup) {
	msg := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Opcode:           dns.OpcodeQuery,
			RecursionDesired: true,
			Rcode:            dns.RcodeSuccess,
		},
		Question: []dns.Question{{
			Qclass: dns.ClassINET,
			Qtype:  dns.TypeNS,
		}},
	}
	msgSetSize(&msg)

	resolverWorker(dataChan, refeedChan, outChan, &msg, nsResolve, retryWg)
}

// `resolverWorker` wrapper to perform MX queries
func mxResolverWorker(dataChan <-chan retryWrap[nameData, empty], refeedChan chan<- retryWrap[nameData, empty], outChan chan<- mxData, retryWg *sync.WaitGroup) {
	msg := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Opcode:           dns.OpcodeQuery,
			RecursionDesired: true,
			Rcode:            dns.RcodeSuccess,
		},
		Question: []dns.Question{{
			Qclass: dns.ClassINET,
			Qtype:  dns.TypeMX,
		}},
	}
	msgSetSize(&msg)

	resolverWorker(dataChan, refeedChan, outChan, &msg, mxResolve, retryWg)
}

// `resolverWorker` wrapper to perform A/AAAA queries
func addrResolverWorker(dataChan <-chan retryWrap[nameData, addrData], refeedChan chan<- retryWrap[nameData, addrData], outChan chan<- addrData, retryWg *sync.WaitGroup) {
	msg := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Opcode:           dns.OpcodeQuery,
			RecursionDesired: true,
			Rcode:            dns.RcodeSuccess,
		},
		Question: []dns.Question{{
			Qclass: dns.ClassINET,
		}},
	}
	msgSetSize(&msg)

	resolverWorker(dataChan, refeedChan, outChan, &msg, addrResolve, retryWg)
}

// `resolverWorker` wrapper to query for zone parents
func parentCheckWorker(dataChan <-chan retryWrap[childParent, empty], refeedChan chan<- retryWrap[childParent, empty], outChan chan<- childParent, retryWg *sync.WaitGroup, tableMap TableMap, _ StmtMap) {
	msg := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Opcode:           dns.OpcodeQuery,
			RecursionDesired: true,
			Rcode:            dns.RcodeSuccess,
		},
		Question: []dns.Question{{
			Qclass: dns.ClassINET,
			Qtype:  dns.TypeSOA,
		}},
	}
	msgSetSize(&msg)

	resolverWorker(dataChan, refeedChan, outChan, &msg, parentCheckResolve, retryWg)
}
