#!/usr/bin/env bash

bin="~/src/dns-tools/dns-tools"
db=$(mktemp --tmpdir open_axfr.XXXXXX.sqlite3)

zone="$1"

source lib.sh

main() {
    init_db

    insert_zone "$zone"

    get_ns_ips

    scan -direct_conns -v6 -axfr

    sqlite3 "$db" "SELECT DISTINCT rr_value.value FROM zone2rr INNER JOIN zone_ns_ip ON zone2rr.zone_id=zone_ns_ip.zone_id INNER JOIN rr_value ON zone2rr.rr_value_id=rr_value.id INNER JOIN name AS zone ON zone2rr.zone_id=zone.id WHERE zone.name='${zone}'"

    rm "$db"*
}

main
