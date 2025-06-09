#!/usr/bin/env bash


db=$(mktemp --tmpdir unreg_list.XXXXXX.sqlite3)

source lib.sh

main() {
    # parse list to maybe_zones
    scan -parse_lists $*
    # validate maybe_zones
    scan -maybe_zone

    # validate
    scan -validate
    # get parent NSes
    get_ns_ips
    scan -parent_map
    get_ns_ips
    scan -zone_ns_ip_glue

    # map from parents
    for i in {1..5}; do
        scan -direct_conns -v6 -parent_ns
        get_ns_ips
    done


    # get parents and ns stuff
    scan -parent_map
    get_ns_ips

    # validate zones + map each name's eTLD+1
    scan -validate
    # check if the eTLD+1s marked with (maybe_zone) are valid zones and whether they're registered
    scan -maybe_zone

    # check for unregistered zones
    scan -unregistered
    # validate again
    scan -validate

    # results
    sqlite3 "$db" 'SELECT zone.name, ns.name, parent.name FROM name AS zone INNER JOIN zone_ns ON zone_ns.zone_id=zone.id INNER JOIN name AS ns ON zone_ns.ns_id=ns.id INNER JOIN name AS parent ON ns.etldp1_id=parent.id WHERE parent.registered=FALSE AND parent.valid=TRUE'
}

main $*
