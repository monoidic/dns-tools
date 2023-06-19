package main

import (
	"database/sql"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/monoidic/dns"
)

// `netWriter` wrapper for MX queries
func mxWriter(db *sql.DB, zoneChan <-chan fieldData) {
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

	netWriter(db, zoneChan, tablesFields, namesStmts, mxResolverWorker, mxWrite)
}

// `insertF` for MX
func mxWrite(tableMap TableMap, stmtMap StmtMap, mxd mxData) {
	zoneID := mxd.id

	if len(mxd.results) > 0 {
		rrTypeID := tableMap.get("rr_type", "MX")
		rrNameID := tableMap.get("rr_name", mxd.name)

		for _, mx := range mxd.results {
			rrValueID := tableMap.get("rr_value", mx.String())
			stmtMap.exec("zone2rr", zoneID, rrTypeID, rrNameID, rrValueID)
		}
	}

	stmtMap.exec("update", mxd.registered, zoneID)
}

// `netWriter` wrapper for checking for active nameservers
func checkUpWriter(db *sql.DB, checkChan <-chan checkUpData) {
	tablesFields := map[string]string{}
	namesStmts := map[string]string{
		"update": "UPDATE ip SET responsive=?, resp_checked=TRUE WHERE id=?",
	}

	netWriter(db, checkChan, tablesFields, namesStmts, checkUpWorker, checkUpWrite)
}

// `insertF` for active nameservers
func checkUpWrite(_ TableMap, stmtMap StmtMap, cu checkUpData) {
	stmtMap.exec("update", cu.success, cu.ipID)
}

// `netWriter` wrapper for PTR queries
func rdnsWriter(db *sql.DB, ipChan <-chan fieldData) {
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

	netWriter(db, ipChan, tablesFields, namesStmts, rdnsWorker, rdnsWrite)
}

// `insertF` for PTR
func rdnsWrite(tableMap TableMap, stmtMap StmtMap, fdr rrResults[dns.PTR]) {
	ipID := fdr.id

	if len(fdr.results) > 0 {
		rrTypeID := tableMap.get("rr_type", "PTR")

		for _, ptr := range fdr.results {
			rrNameID := tableMap.get("rr_name", ptr.Hdr.Name)
			rrValueID := tableMap.get("rr_value", ptr.String())

			stmtMap.exec("zone2rr", fdr.id, rrTypeID, rrNameID, rrValueID)
		}
	}

	stmtMap.exec("mapped", ipID)
}

// `readerF` for SPF TXT queries
func spfRRWriter(db *sql.DB, fdChan <-chan fieldData) {
	tablesFields := map[string]string{
		"name":       "name",
		"spf_record": "value",
	}
	namesStmts := map[string]string{
		"spf":           "INSERT OR IGNORE INTO spf (name_id, spf_record_id) VALUES (?, ?)",
		"spfname":       "INSERT INTO spf_name (name_id, spf_id, spfname) VALUES (?, (SELECT id FROM spf WHERE name_id=? AND spf_record_id=?), ?) ON CONFLICT DO UPDATE SET spfname=spfname|excluded.spfname",
		"spf_tried":     "UPDATE name SET spf_tried=TRUE WHERE id=?",
		"spf_valid":     "UPDATE spf_record SET valid=?, any_unknown=?, error=? WHERE id=?",
		"spf_duplicate": "UPDATE spf SET duplicate=TRUE WHERE name_id=? AND spf_record_id=?",
	}

	netWriter(db, fdChan, tablesFields, namesStmts, txtWorker, spfWrite)
}

// `insertF` for SPF TXT
func spfWrite(tableMap TableMap, stmtMap StmtMap, fdr fdResults) {
	nameID := fdr.id

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
					stmtMap.exec("spfname", spfNameID, nameID, recordID, spfName)
				}
			}
		}
	}

	stmtMap.exec("spf_tried", nameID)
}

// `netWriter` wrapper for DMARC TXT queries
func dmarcRRWriter(db *sql.DB, fdChan <-chan fieldData) {
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

	netWriter(db, fdChan, tablesFields, namesStmts, txtWorker, dmarcWrite)
}

// `insertF` for DMARC TXT
func dmarcWrite(tableMap TableMap, stmtMap StmtMap, fdr fdResults) {
	nameID := fdr.id // ID with no '_dmarc.'

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

	stmtMap.exec("dmarc_tried", nameID)
}

func chaosTXTWriter(db *sql.DB, fdChan <-chan fieldData) {
	tablesFields := map[string]string{
		"name":                 "name",
		"chaos_response_value": "value",
	}
	namesStmts := map[string]string{
		"chaos_query":    "INSERT OR IGNORE INTO chaos_query (name_id, ip_id) VALUES (?, ?)",
		"chaos_response": "INSERT OR IGNORE INTO chaos_response (chaos_query_id, chaos_response_value_id, name_id) VALUES ((SELECT id FROM chaos_query WHERE name_id=? AND ip_id=?), ?, ?)",
		"chaos_queried":  "UPDATE ip SET ch_resolved=TRUE WHERE id=?",
	}

	netWriter(db, fdChan, tablesFields, namesStmts, chaosTXTWorker, chaosTXTWrite)
}

// `insertF` for Chaosnet TXT
func chaosTXTWrite(tableMap TableMap, stmtMap StmtMap, chr chaosResults) {
	ipID := chr.id

	for _, result := range chr.results {
		queriedNameID := tableMap.get("name", result.queried)
		resultNameID := tableMap.get("name", result.resultName)
		responseID := tableMap.get("chaos_response_value", result.value)

		stmtMap.exec("chaos_query", queriedNameID, ipID)
		stmtMap.exec("chaos_response", queriedNameID, ipID, responseID, resultNameID)
	}

	stmtMap.exec("chaos_queried", ipID)
}

// `readerF` for checking for active nameservers
func checkUpReader(db *sql.DB, checkChan chan<- checkUpData) {
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
		checkChan <- checkUpData{
			ns:   net.JoinHostPort(ip, "53"),
			zone: zone,
			ipID: ipID,
		}
	}

	check(rows.Close())
	check(tx.Commit())
	close(checkChan)
}

// `readerF` for A/AAAA
func zoneIPReader(db *sql.DB, zipChan chan<- zoneIP, extraFilter string) {
	qs := fmt.Sprintf(`
		SELECT DISTINCT zone.name, ip.address, zone.id, ip.id
		FROM zone_ns
		INNER JOIN name_ip ON zone_ns.ns_id = name_ip.name_id
		INNER JOIN ip ON name_ip.ip_id = ip.id
		INNER JOIN name AS zone ON zone_ns.zone_id = zone.id
		WHERE ip.responsive=TRUE %s
	`, extraFilter)

	tx := check1(db.Begin())
	rows := check1(tx.Query(qs))

	for rows.Next() {
		var zone, ip fieldData
		check(rows.Scan(&zone.name, &ip.name, &zone.id, &ip.id))
		ip.name = net.JoinHostPort(ip.name, "53")
		zipChan <- zoneIP{zone: zone, ip: ip}
	}

	check(rows.Close())
	check(tx.Commit())
	close(zipChan)
}

// helper function to add parent zone NS IPs for fetching glue records from parent zones
func nsIPAdderWorker(db *sql.DB, zoneChan <-chan fieldData, withNSChan chan<- fdResults) {
	tx := check1(db.Begin())

	var v4Filter string
	if !v6 {
		v4Filter = `AND ip.address LIKE '%.%'`
	}

	nsCache := getFDCache(fmt.Sprintf(`
		SELECT DISTINCT ip.address || ':53', ip.id
		FROM name AS child
		INNER JOIN zone_ns ON zone_ns.zone_id = child.parent_id
		INNER JOIN name_ip ON zone_ns.ns_id = name_ip.name_id
		INNER JOIN ip ON name_ip.ip_id = ip.id
		WHERE child.name=? %s
	`, v4Filter), tx)

	for zd := range zoneChan {
		withNSChan <- fdResults{fieldData: zd, results: nsCache.getName(zd.name)}
	}

	close(withNSChan)
	nsCache.clear()
	check(tx.Commit())
}

// `readerF` for fetching NS glue records from parent zones
func parentNSWriter(db *sql.DB, zoneChan <-chan fieldData) {
	tablesFields := map[string]string{
		"name": "name",
		"ip":   "address",
	}
	namesStmts := map[string]string{
		"insert_name_ip": "INSERT INTO name_ip (name_id, ip_id, in_parent_zone_glue) VALUES (?, ?, TRUE) ON CONFLICT DO UPDATE SET in_parent_zone_glue=TRUE",
		"insert_zone_ns": "INSERT INTO zone_ns (zone_id, ns_id, in_parent_zone) VALUES (?, ?, TRUE) ON CONFLICT DO UPDATE SET in_parent_zone=TRUE",
		"name_to_ns":     "UPDATE name SET is_ns=TRUE WHERE id=?",
		"registered":     "UPDATE name SET registered=TRUE, reg_checked=TRUE WHERE id=?",
		"fetched":        "UPDATE name SET glue_ns=TRUE WHERE id=?",
	}

	withNSChan := make(chan fdResults, MIDBUFLEN)
	go nsIPAdderWorker(db, zoneChan, withNSChan)

	netWriter(db, withNSChan, tablesFields, namesStmts, parentNSResolverWorker, parentNSWrite)
}

// `insertF` for NS glue records from parent zone
func parentNSWrite(tableMap TableMap, stmtMap StmtMap, nsr parentNSResults) {
	zoneID := nsr.id

	if len(nsr.ns) > 0 {
		stmtMap.exec("registered", zoneID)

		for _, a := range nsr.a {
			nameID := tableMap.get("name", a.Hdr.Name)
			ipID := tableMap.get("ip", a.A.String())
			stmtMap.exec("insert_name_ip", nameID, ipID)
		}

		for _, aaaa := range nsr.aaaa {
			nameID := tableMap.get("name", aaaa.Hdr.Name)
			ipID := tableMap.get("ip", aaaa.AAAA.String())
			stmtMap.exec("insert_name_ip", nameID, ipID)
		}

		for _, ns := range nsr.ns {
			nsID := tableMap.get("name", ns.Ns)
			stmtMap.exec("name_to_ns", nsID)
			stmtMap.exec("insert_zone_ns", zoneID, nsID)
		}
	}

	stmtMap.exec("fetched", zoneID)
}

// `netWriter` wrapper for NS queries
func netNSWriter(db *sql.DB, zoneChan <-chan fieldData) {
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

	netWriter(db, zoneChan, tablesFields, namesStmts, nsResolverWorker, nsWrite)
}

// `insertF` for NS
func nsWrite(tableMap TableMap, stmtMap StmtMap, nsd rrResults[dns.NS]) {
	zoneID := nsd.id

	if len(nsd.results) > 0 {
		stmtMap.exec("registered", zoneID)
		rrTypeID := tableMap.get("rr_type", "NS")
		rrNameID := tableMap.get("rr_name", nsd.name)

		for _, ns := range nsd.results {
			normalizeRR(&ns)
			nsID := tableMap.get("name", ns.Ns)

			stmtMap.exec("insert", zoneID, nsID)

			rrValueID := tableMap.get("rr_value", ns.String())
			stmtMap.exec("zone2rr", zoneID, rrTypeID, rrNameID, rrValueID)
		}
	}

	stmtMap.exec("update", zoneID)
}

// `netWriter` wrapper for A/AAAA queries
func netIPWriter(db *sql.DB, nameChan <-chan fieldData) {
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

	netWriter(db, nameChan, tablesFields, namesStmts, addrResolverWorker, ipWrite)
}

// `insertF` for A/AAAA
func ipWrite(tableMap TableMap, stmtMap StmtMap, ad addrData) {
	nameID := ad.id
	registered := ad.registered

	if len(ad.cname) > 0 {
		fmt.Printf("cname from address %s\n", ad.name)
		finalRegistered, loop := cnameChainFinalEntry(ad.cname)

		for _, entry := range ad.cname {
			srcID := tableMap.get("name", entry.Hdr.Name)
			targetID := tableMap.get("name", entry.Target)
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

	stmtMap.exec("update", registered, nameID)
}

// `resolverWorker` wrapper to check if a given host is responsive
func checkUpWorker(inChan <-chan checkUpData, outChan chan<- checkUpData, wg *sync.WaitGroup) {
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

	resolverWorker(inChan, outChan, msg, checkUpResolve, wg)
}

// `resolverWorker` wrapper to perform PTR queries
func rdnsWorker(inChan <-chan fieldData, outChan chan<- rrResults[dns.PTR], wg *sync.WaitGroup) {
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

	resolverWorker(inChan, outChan, msg, rdnsResolve, wg)
}

// `resolverWorker` wrapper to perform TXT queries
func txtWorker(inChan <-chan fieldData, outChan chan<- fdResults, wg *sync.WaitGroup) {
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

	resolverWorker(inChan, outChan, msg, txtResolve, wg)
}

// `resolverWorker` wrapper to perform Chaosnet TXT queries
func chaosTXTWorker(inChan <-chan fieldData, outChan chan<- chaosResults, wg *sync.WaitGroup) {
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

	resolverWorker(inChan, outChan, msg, chaosTXTResolve, wg)
}

// `resolverWorker` wrapper to perform NS queries on a parent zone for glue records
func parentNSResolverWorker(inChan <-chan fdResults, outChan chan<- parentNSResults, wg *sync.WaitGroup) {
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

	resolverWorker(inChan, outChan, msg, parentNsResolve, wg)
}

// `resolverWorker` wrapper to query for arbitrary name:rrtype pairs received from NSEC walking results
func nsecWalkResultResolver(inChan <-chan rrDBData, outChan chan<- nsecWalkResolveRes, wg *sync.WaitGroup) {
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

	resolverWorker(inChan, outChan, msg, nsecWalkResultResolve, wg)
}

// `processsData` function
func nsecWalkResultResolve(connCache connCache, msg dns.Msg, rrD rrDBData) (res nsecWalkResolveRes) {
	msg.Question[0].Name = rrD.rrName.name
	msg.Question[0].Qtype = dns.StringToType[rrD.rrType.name]

	var response *dns.Msg
	var err error

	for i := 0; i < RETRIES; i++ {
		nameserver := randomNS()
		if response, err = plainResolve(msg, connCache, nameserver); err == nil {
			break
		}
	}

	res.rrDBData = rrD

	if response == nil {
		return res
	}

	res.results = make([]rrData, len(response.Answer))

	for i, rr := range response.Answer {
		normalizeRR(rr)
		hdr := rr.Header()
		resRRD := rrData{
			rrValue: rr.String(),
			rrType:  dns.TypeToString[hdr.Rrtype],
			rrName:  hdr.Name,
		}
		res.results[i] = resRRD
	}

	return res
}

// `processsData` function
func nsResolve(connCache connCache, msg dns.Msg, fd fieldData) rrResults[dns.NS] {
	msg.Question[0].Name = dns.Fqdn(fd.name)
	var response *dns.Msg
	var results []dns.NS
	var err error

	for i := 0; i < RETRIES; i++ {
		nameserver := randomNS()
		if response, err = plainResolve(msg, connCache, nameserver); err == nil {
			break
		}
	}

	if response != nil {
		for _, rr := range response.Answer {
			switch rrT := rr.(type) {
			case *dns.NS:
				results = append(results, *rrT)
			}
		}
	}

	return rrResults[dns.NS]{fieldData: fd, results: results}
}

// `processsData` function
func mxResolve(connCache connCache, msg dns.Msg, fd fieldData) mxData {
	msg.Question[0].Name = dns.Fqdn(fd.name)
	var response *dns.Msg
	var results []dns.MX
	var err error
	registered := true

	for i := 0; i < RETRIES; i++ {
		nameserver := randomNS()
		if response, err = plainResolve(msg, connCache, nameserver); err == nil {
			break
		}
	}

	if response != nil {
		for _, rr := range response.Answer {
			switch rrT := rr.(type) {
			case *dns.MX:
				normalizeRR(rrT)
				results = append(results, *rrT)
			}
		}
		registered = response.Rcode != dns.RcodeNameError
	}

	return mxData{rrResults: rrResults[dns.MX]{results: results, fieldData: fd}, registered: registered}
}

// `processsData` function
func addrResolve(connCache connCache, msg dns.Msg, fd fieldData) addrData {
	msg.Question[0].Name = dns.Fqdn(fd.name)

	var cname []dns.CNAME
	var a []dns.A
	var aaaa []dns.AAAA
	var err error
	registered := true

	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		msg.Question[0].Qtype = qtype
		var response *dns.Msg

		for i := 0; i < RETRIES; i++ {
			nameserver := randomNS()
			if response, err = plainResolve(msg, connCache, nameserver); err == nil {
				break
			}
		}

		if response != nil {
			for _, rr := range response.Answer {
				switch rrT := rr.(type) {
				case *dns.A:
					normalizeRR(rrT)
					a = append(a, *rrT)
				case *dns.AAAA:
					normalizeRR(rrT)
					aaaa = append(aaaa, *rrT)
				case *dns.CNAME:
					normalizeRR(rrT)
					cname = append(cname, *rrT)
				}
			}

			registered = response.Rcode != dns.RcodeNameError
		}
	}

	return addrData{fieldData: fd, a: a, aaaa: aaaa, cname: cname, registered: registered}
}

// `processsData` function
func parentCheckResolve(connCache connCache, msg dns.Msg, cp childParent) childParent {
	if cp.resolved { // ID fetched by parentCheckFilter or invalid/nonexistant
		return cp
	}

	msg.Question[0].Name = cp.parentGuess
	var res *dns.Msg
	var err error

	for i := 0; i < RETRIES; i++ {
		nameserver := randomNS()
		res, err = plainResolve(msg, connCache, nameserver)
		if err == nil {
			break
		}
	}

	if err != nil {
		return cp
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
		normalizeRR(soa)
		realParent := soa.Hdr.Name
		cp.parent.name = realParent
		cp.resolved = true
		cp.registered = res.Rcode != dns.RcodeNameError
	}

	return cp
}

// `processsData` function
func checkUpResolve(connCache connCache, msg dns.Msg, cu checkUpData) checkUpData {
	msg.Question[0].Name = dns.Fqdn(cu.zone)
	cu.registered = true

	for i := 0; i < RETRIES; i++ {
		if res, err := plainResolve(msg, connCache, cu.ns); err == nil {
			cu.registered = res.Rcode != dns.RcodeNameError
			cu.success = true
			break
		}
	}

	return cu
}

// `processsData` function
func rdnsResolve(connCache connCache, msg dns.Msg, fd fieldData) rrResults[dns.PTR] {
	//msg.Question[0].Name = check1(dns.ReverseAddr(fd.name))
	if addr, err := dns.ReverseAddr(fd.name); err == nil {
		msg.Question[0].Name = addr
	} else {
		fmt.Printf("fd.name = %q\n", fd.name)
		panic(err)
	}
	var res *dns.Msg
	var results []dns.PTR

	for i := 0; i < RETRIES; i++ {
		var err error
		nameserver := randomNS()
		res, err = plainResolve(msg, connCache, nameserver)
		if err == nil {
			break
		}
	}

	if res != nil {
		for _, rr := range res.Answer {
			switch rrT := rr.(type) {
			case *dns.PTR:
				normalizeRR(rrT)
				results = append(results, *rrT)
			}
		}
	}

	return rrResults[dns.PTR]{fieldData: fd, results: results}
}

// `processsData` function
func txtResolve(connCache connCache, msg dns.Msg, fd fieldData) fdResults {
	msg.Question[0].Name = dns.Fqdn(fd.name)
	var results []string
	var res *dns.Msg

	for i := 0; i < RETRIES; i++ {
		var err error
		nameserver := randomNS()
		res, err = plainResolve(msg, connCache, nameserver)
		if err == nil {
			break
		}
	}

	if res != nil {
		for _, rr := range res.Answer {
			switch rrT := rr.(type) {
			case *dns.TXT:
				results = append(results, strings.Join(rrT.Txt, ""))
			}
		}
	}
	return fdResults{fieldData: fd, results: results}
}

func chaosTXTResolve(connCache connCache, msg dns.Msg, fd fieldData) chaosResults {
	nameserver := net.JoinHostPort(fd.name, "53")
	var results []chaosResult

	for _, name := range chaosTXTNames {
		msg.Question[0].Name = name
		var res *dns.Msg

		for i := 0; i < RETRIES; i++ {
			var err error
			res, err = plainResolve(msg, connCache, nameserver)
			if err == nil {
				break
			}
		}

		if res != nil {
			for _, rr := range res.Answer {
				switch rrT := rr.(type) {
				case *dns.TXT:
					results = append(results, chaosResult{
						queried:    name,
						resultName: strings.ToLower(rrT.Hdr.Name),
						value:      strings.Join(rrT.Txt, ""),
					})
				}
			}
		}
	}

	return chaosResults{fieldData: fd, results: results}
}

// `processsData` function
func parentNsResolve(connCache connCache, msg dns.Msg, fdr fdResults) parentNSResults {
	msg.Question[0].Name = dns.Fqdn(fdr.name)
	var nsResults []dns.NS
	var aResults []dns.A
	var aaaaResults []dns.AAAA

	if nsLen := len(fdr.results); nsLen > 0 {
		var response *dns.Msg
		var err error
	parentNsResolveOuterLoop:
		for _, nameserver := range fdr.results {
			for i := 0; i < RETRIES; i++ {
				response, err = plainResolve(msg, connCache, nameserver)
				if err == nil {
					break parentNsResolveOuterLoop
				}
			}
		}

		if response != nil {
			for _, rr := range response.Ns {
				switch rrT := rr.(type) {
				case *dns.NS:
					normalizeRR(rrT)
					nsResults = append(nsResults, *rrT)
				}
			}

			for _, rr := range response.Extra {
				switch rrT := rr.(type) {
				case *dns.A:
					normalizeRR(rrT)
					aResults = append(aResults, *rrT)
				case *dns.AAAA:
					normalizeRR(rrT)
					aaaaResults = append(aaaaResults, *rrT)
				}
			}
		}
	}

	return parentNSResults{fieldData: fdr.fieldData, ns: nsResults, a: aResults, aaaa: aaaaResults}
}

// `resolverWorker` wrapper to perform NS queries
func nsResolverWorker(inChan <-chan fieldData, outChan chan<- rrResults[dns.NS], wg *sync.WaitGroup) {
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

	resolverWorker(inChan, outChan, msg, nsResolve, wg)
}

// `resolverWorker` wrapper to perform MX queries
func mxResolverWorker(inChan <-chan fieldData, outChan chan<- mxData, wg *sync.WaitGroup) {
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

	resolverWorker(inChan, outChan, msg, mxResolve, wg)
}

// `resolverWorker` wrapper to perform A/AAAA queries
func addrResolverWorker(inChan <-chan fieldData, outChan chan<- addrData, wg *sync.WaitGroup) {
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

	resolverWorker(inChan, outChan, msg, addrResolve, wg)
}

// `resolverWorker` wrapper to query for zone parents
func parentCheckWorker(inChan <-chan childParent, outChan chan<- childParent, wg *sync.WaitGroup, tableMap TableMap, _ StmtMap) {
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

	workerInChan := make(chan childParent, MIDBUFLEN)
	go parentCheckFilter(inChan, workerInChan, tableMap)

	resolverWorker(workerInChan, outChan, msg, parentCheckResolve, wg)
}
