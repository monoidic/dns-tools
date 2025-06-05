#!/usr/bin/env bash

bin="~/go/bin/dns-tools"
db="arpa_walk.sqlite3"

scan() {
	eval "$bin" -db "$db" $*
}

insert_zone() {
	zone="$1"
	echo "zone=$zone"
	sqlite3 "$db" "INSERT INTO name (name, is_zone) VALUES ('${zone}', TRUE)"
}


main() {
    # dummy db
    scan -rr_ip
    # add zones
    insert_zone ip6.arpa.
    insert_zone in-addr.arpa.

    for i in {1..5}; do
        scan -rr_{ns,ip}
        scan -net_{ns,ip}
        scan -rr_{ns,ip}
    done

    for i in {1..34}; do
        scan -v6 -direct_conns -axfr

        for i in {1..5}; do
            scan -rr_{ns,ip}
            scan -net_{ns,ip}
            scan -rr_{ns,ip}
        done

    done
}

main
