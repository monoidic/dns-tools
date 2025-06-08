#!/usr/bin/env bash

bin="~/go/bin/dns-tools"
db="arpa_walk.sqlite3"

source lib.sh

main() {
    init_db
    # add zones
    insert_zone ip6.arpa.
    insert_zone in-addr.arpa.

    get_ns_ips

    for i in {1..34}; do
        scan -v6 -direct_conns -axfr
        get_ns_ips
    done
}

main
