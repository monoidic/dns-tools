#!/bin/bash

bin='./dns-tools'

functions="
ee_axfr
ee_zone_walk
ee_rdns_map
x_zone_walk
"

# TODO
# something for each cmdline flag
# unreg NS domains

main() {
	self_name="$1"
	main_f_name="$2"
	main_f_arg="$3"

	for f_name in $(echo $functions); do
		if [[ "$f_name" = "$main_f_name" ]]; then
			$f_name "$main_f_arg"
			return
		fi
	done

	# no match found
	echo -en "usage: $self_name <f_name>\n\n[f_name options]$functions"
	return 1
}

_ee_init() {
	if ! [[ -e zones/ee.zone ]]; then
		echo "populate zones/ee.zone with e.g"
		echo 'dig @zone.internet.ee +noall +answer +noidnout +onesoa -t AXFR ee > zones/ee.zone'
		exit 1
	fi
	# parse .ee zone file and extract zone + NS info
	$bin -db ee.sqlite3 -tld_zone -parse -rr_{ns,ip} zones/ee.zone
}

ee_axfr() {
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

ee_zone_walk() {
	_ee_init
	$bin -db ee.sqlite3 -nsec_map -zone_walk

	echo "for results, use 'sqlite3 ee.sqlite3 <query>'"
	echo 'for a list of all record names and types (not the values, fetch separately):'
	echo 'SELECT rr_name.name, rr_type.name '\
'FROM zone_walk_res '\
'INNER JOIN rr_name ON zone_walk_res.rr_name_id=rr_name.id '\
'INNER JOIN rr_type ON zone_walk_res.rr_type_id=rr_type.id '
}

x_zone_walk() {
	zone="$1"

	# append period if missing
	if ! $(printf '%s' "$zone" | grep -q '\.$'); then
		zone="${zone}."
	fi

	# create db
	$bin -db zone_walk.sqlite3 -rr_ip

	# insert zone
	sqlite3 zone_walk.sqlite3 "INSERT INTO name (name, is_zone) VALUES ('$zone', TRUE)"

	# zone walk
	$bin -db zone_walk.sqlite3 -nsec_map -zone_walk

		echo "for results, use 'sqlite3 zone_walk.sqlite3 <query>'"
	echo 'for a list of all record names and types (not the values, fetch separately):'
	echo 'SELECT rr_name.name, rr_type.name '\
'FROM zone_walk_res '\
'INNER JOIN rr_name ON zone_walk_res.rr_name_id=rr_name.id '\
'INNER JOIN rr_type ON zone_walk_res.rr_type_id=rr_type.id '
}

ee_rdns_map() {
	if ! [[ -e nets.txt ]]; then
		echo 'generate nets.txt in the current working directory with github.com/monoidic/rir@latest, via:'
		echo 'rir -a > nets.txt'
		exit 1
	fi

	$bin -db ee.sqlite3 -cc EE -net_file nets.txt -in_addr

	# query
}



main "$0" "$1" "$2"
