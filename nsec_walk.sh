#!/usr/bin/env bash

db=$(mktemp --tmpdir nsec_walk.XXXXXX.sqlite3)

source lib.sh

main() {
    init_db
    for zone in $*; do
        insert_zone "$zone"
    done

    for i in {1..5}; do
        get_ns_ips
    done

    scan -nsec_map
    scan -zone_walk

    sqlite3 "$db" 'SELECT DISTINCT rr_name.name FROM zone_walk_res INNER JOIN rr_name ON zone_walk_res.rr_name_id=rr_name.id ORDER BY rr_name.name' | while read name; do
        printf '%s: ' "$name"
        sqlite3 "$db" "SELECT rr_type.name FROM zone_walk_res INNER JOIN rr_name ON zone_walk_res.rr_name_id=rr_name.id INNER JOIN rr_type ON zone_walk_res.rr_type_id=rr_type.id WHERE rr_name.name='${name}' ORDER BY rr_type.name" | tr '\n' ' '
        echo
    done

    rm "$db"
}

main $*
