#!/usr/bin/env bash

# expects bin and db to be set

scan() {
    if [[ $verbose == 1 ]]; then
	    ~/go/bin/dns-tools -db "$db" $*
    else
        ~/go/bin/dns-tools -db "$db" $* > /dev/null
    fi
}

init_db() {
    scan -rr_ip
}

insert_zone() {
	zone="$1"
	sqlite3 "$db" "INSERT INTO name (name, is_zone) VALUES ('${zone}', TRUE)"
}

get_ns_ips() {
    for i in {1..5}; do
        scan -{net,rr}_ns -{net,rr}_ip
    done
    scan -zone_ns_ip{,_glue}
}
