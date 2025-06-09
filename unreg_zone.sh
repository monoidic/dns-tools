#!/usr/bin/env bash

zone="$1"

db=$(mktemp --tmpdir unreg_zone.XXXXXX.sqlite3)

source lib.sh

main() {
    # parse zone file to zone2rr
    scan -tld_zone -parse $*
    # parse zone2rr from zone file
    get_ns_ips

    # fetch zone NS and NS IP records from the net, based on zones and NSes from zone2rr
    get_ns_ips

    # get parents
    scan -parent_map
    # get parent ns stuff
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
    sqlite3 "$db" 'SELECT zone.name AS zone_name, ns.name AS ns_name, parent.name AS parent_name FROM name AS zone INNER JOIN zone_ns ON zone_ns.zone_id=zone.id INNER JOIN name AS ns ON zone_ns.ns_id=ns.id INNER JOIN name AS parent ON ns.etldp1_id=parent.id WHERE parent.registered=FALSE AND parent.valid=TRUE'
}

main $*
