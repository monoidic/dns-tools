#!/bin/bash

bin='./dns-tools'

functions="
axfr
zone_walk
rdns_map
"

# TODO
# something for each cmdline flag
# unreg NS domains

main() {
	for f_name in $(echo $functions); do
		if [[ "$f_name" = "$1" ]]; then
			$f_name $2
			return
		fi
	done

	# no match found
	echo -en "usage: $2 <f_name>\n\n[f_name options]$functions"
	return 1
}

_ee_init() {
	# parse .ee zone file and extract zone + NS info
	$bin -db ee.sqlite3 -tld_zone -parse -rr_{ns,ip} zones/ee.zone
}

axfr() {
	# perform AXFR on all .ee zones on each nameserver
	_ee_init
	$bin -db ee.sqlite3 -net_{ns,ip}
	$bin -db ee.sqlite3 -axfr

	echo "for results, use 'sqlite3 ee.sqlite3 <query>'"
	echo 'for a list of all domains with vulnerable nameservers and the associated nameservers:'
	echo 'SELECT zone.name, ns.name, ip.address '\
'FROM axfrable_ns '\
'INNER JOIN name AS zone ON axfrable_ns.zone_id=zone.id '\
'INNER JOIN ip ON axfrable_ns.ip_id=ip.id '\
'INNER JOIN name_ip ON name_ip.ip_id=ip.id '\
'INNER JOIN zone_ns ON zone_ns.zone_id=zone.id '\
'INNER JOIN name AS ns ON zone_ns.ns_id=ns.id '\
'WHERE name_ip.name_id=ns.id'

	echo -e "\nfor the AXFR results themselves:"
	echo 'SELECT rr_name.name, rr_value.value '\
'FROM zone2rr '\
'INNER JOIN rr_name ON zone2rr.rr_name_id=rr_name.id '\
'INNER JOIN rr_value ON zone2rr.rr_value_id=rr_value.id'
}

zone_walk() {
	_ee_init
	$bin -db ee.sqlite3 -nsec_map -zone_walk

	echo "for results, use 'sqlite3 ee.sqlite3 <query>'"
	echo 'for a list of all record names and types (not the values, fetch separately):'
	echo 'SELECT rr_name.name, rr_type.name '\
'FROM zone_walk_res '\
'INNER JOIN rr_name ON zone_walk_res.rr_name_id=rr_name.id '\
'INNER JOIN rr_type ON zone_walk_res.rr_type_id=rr_type.id '
}

rdns_map() {
	if ! [[ -e nets.txt ]]; then
		echo 'generate nets.txt in the current working directory with github.com/monoidic/rir@latest, via:'
		echo 'rir -a > nets.txt'
		exit 1
	fi

	$bin -db ee.sqlite3 -cc EE -net_file nets.txt -in_addr

	# query
}



main "$1" "$0"
