#!/usr/bin/env bash

db=$(mktemp --tmpdir nsec_walk.XXXXXX.sqlite3)

source lib.sh

get_tlds() {
	init_db
	get_ns_ips
	# axfr root nameservers
	scan -direct_conns -v6 -axfr
	# get TLD nameserver info
        get_ns_ips

        # download PSL
        wget https://raw.githubusercontent.com/publicsuffix/list/refs/heads/main/public_suffix_list.dat || exit 1
        # convert to idna lol
        sed '/^\/\//d;/^$/d;s/^\*\.//;s/^!//' public_suffix_list.dat | python3 -c 'print("\n".join(x.encode("idna").decode() for x in __import__("sys").stdin.read().splitlines()))' > psl.txt
        # add entries
        scan -parse_lists psl.txt
        # idk, check for zones
        for i in {1..5}; do
        	scan -validate
        	scan -parent_map
        	scan -maybe_zone
        done
        for i in {1..3}; do
        	get_ns_ips
        done
}

main() {
    get_tlds

    scan -nsec_map

    sqlite3 $db "SELECT zone.name FROM zone_nsec_state INNER JOIN name AS zone ON zone_nsec_state.zone_id=zone.id INNER JOIN nsec_state ON zone_nsec_state.nsec_state_id=nsec_state.id WHERE nsec_state.name='nsec3' AND zone_nsec_state.opt_out=FALSE ORDER BY zone.name" > nsec3_no_optout.txt
    sqlite3 $db "SELECT zone.name FROM zone_nsec_state INNER JOIN name AS zone ON zone_nsec_state.zone_id=zone.id INNER JOIN nsec_state ON zone_nsec_state.nsec_state_id=nsec_state.id WHERE nsec_state.name='nsec3' AND zone_nsec_state.opt_out=TRUE  ORDER BY zone.name" > nsec3_optout.txt
    rm "$db"
}

main $*
