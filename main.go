package main

import (
	"database/sql"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const (
	RETRIES   = 5
	TIMEOUT   = 5 * time.Second
	BUFLEN    = 10_000
	CHUNKSIZE = 100_000
)

var NUMPROCS = runtime.GOMAXPROCS(0)

var (
	args         []string
	networksFile string
	netCC        string
	tcpOnly      bool
	v6           bool
	tldZone      bool
)

func check(err error) {
	if err != nil {
		fmt.Printf("%T %#v\n", err, err)
		panic(err)
	}
}

type flagData struct {
	doAction    bool
	description string
	function    func(*sql.DB)
}

var flags = map[string]*flagData{
	"parse_lists":       {description: "parse domain lists under lists/", function: parseDomainLists},
	"parse":             {description: "parse zone files under zones/", function: parseZoneFiles},
	"in_addr":           {description: "enumerate in-addr.arpa nameservers", function: getInAddrArpa},
	"rr_ns":             {description: "extract zone-ns relations from parsed RRs", function: extractNSRR},
	"rr_ip":             {description: "extract name-ip relations from parsed RRs", function: extractIPRR},
	"rr_mx":             {description: "extract name-mx relations from parsed RRs", function: extractMXRR},
	"net_ns":            {description: "fetch zone-ns relations from the internet", function: netNS},
	"net_mx":            {description: "map MX records from the internet", function: resolveMX},
	"net_ip":            {description: "fetch name-IP relations from the internet", function: netIP},
	"check_up":          {description: "perform test queries on NSes to mark responsivity of IPs", function: checkUp},
	"nsec_map":          {description: "map nsec statuses of DNS zones on the internet", function: checkNsec},
	"zone_walk":         {description: "perform zone walk on vulnerable zones", function: nsecWalk},
	"zone_walk_results": {description: "query record values from walked zones", function: nsecWalkResults},
	"axfr":              {description: "attempt axfr queries on all nameservers for each zone", function: publicAxfr},
	"parent_map":        {description: "map names to their own parent domains", function: mapZoneParents},
	"parent_ns":         {description: "fetch nameservers and glue A/AAAA records directly from a zone's parent zone", function: getParentNS},
	"unregistered":      {description: "check if domain appears in DNS", function: getUnregisteredDomains},
	"psl":               {description: "insert TLDs from PSL", function: insertPSL},
	"rdns":              {description: "perform rDNS queries on all saved IP addresses", function: rdns},
	"validate":          {description: "check if zones are valid", function: validateZones},
}

var (
	flagOrder      = []string{"parse", "parse_lists", "in_addr", "rr_ns", "rr_mx", "rr_ip", "net_ns", "net_mx", "net_ip", "rdns", "check_up", "nsec_map", "zone_walk", "zone_walk_results", "axfr", "psl", "validate", "parent_map", "parent_ns", "unregistered"}
	publicDnsFlags = []string{"in_addr", "net_ns", "net_mx", "net_ip", "nsec_map", "zone_walk", "unregistered", "rdns", "zone_walk_results"}
	directConns    = []string{"axfr", "check_up", "parent_ns"}
)

func main() {
	for flagName, flagD := range flags {
		flag.BoolVar(&flagD.doAction, flagName, false, flagD.description)
	}

	var allowDirectConns bool

	var dbName string
	flag.StringVar(&dbName, "db", "test.sqlite3", "path to sqlite3 database file")
	flag.StringVar(&networksFile, "net_file", "", "path to TSV file with country codes and subnets to scan")
	flag.StringVar(&netCC, "cc", "", "country code to filter for from net_file in in_addr")
	flag.BoolVar(&tcpOnly, "tcp", false, "only use TCP connections")
	flag.BoolVar(&v6, "v6", false, "allow implicit v6 connections (e.g AXFR)")
	flag.BoolVar(&allowDirectConns, "direct_conns", false, "allow direct connections to servers besides the configured nameservers")
	flag.BoolVar(&tldZone, "tld_zone", false, "treat parsed zone files as up-to-date zone file from TLD")
	flag.Parse()
	args = flag.Args()

	if (networksFile == "" && netCC != "") || (networksFile != "" && netCC == "") {
		fmt.Fprint(os.Stderr, "enter none or both of net_file and cc\n")
		flag.Usage()
		os.Exit(1)
	}

	if !(anyFlagSet()) {
		fmt.Fprint(os.Stderr, "enter at least one action to perform\n")
		flag.Usage()
		os.Exit(1)
	}

	if !allowDirectConns {
		triggeringFlags := make([]string, 0, len(directConns))
		for _, key := range directConns {
			if flags[key].doAction {
				triggeringFlags = append(triggeringFlags, "-"+key)
			}
		}

		if len(triggeringFlags) > 0 {
			s := strings.Join(triggeringFlags, ", ")
			fmt.Fprintf(os.Stderr, "safety check: use -direct_conns to permit direct connections to nameservers (required by the flag(s): %s)\n", s)
			os.Exit(1)
		}
	}

	readConfig()
	netCC = strings.ToUpper(netCC)

	connstring := fmt.Sprintf("file:%s?_journal_mode=WAL&mode=rwc", dbName)
	db, err := sql.Open("sqlite3", connstring)
	check(err)

	initDb(db)

	for _, key := range publicDnsFlags {
		if flags[key].doAction {
			// randomize ns (no security needed)
			rand.Seed(time.Now().UnixNano())
			break
		}
	}

	for _, flagKey := range flagOrder {
		if flagD := flags[flagKey]; flagD.doAction {
			flagD.function(db)
		}
	}

	check(db.Close())
}

func anyFlagSet() bool {
	for _, flagD := range flags {
		if flagD.doAction {
			return true
		}
	}
	return false
}
