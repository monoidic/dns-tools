#!/usr/bin/env bash

zone="$1"

# fetch zone NS and NS IP records from the net, based on zones and NSes from zone2rr
./dns-tools -db ${zone}.sqlite3 -net_{ns,ip}
# parse the above
./dns-tools -db ${zone}.sqlite3 -rr_{ns,ip} -zone_ns_ip

# since the above likely resulted in new NSes that weren't shared between the parent and child zone, fetch their info too
# (TODO can skip ns here then?)
./dns-tools -db ${zone}.sqlite3 -net_{ns,ip}
# and parse it
./dns-tools -db ${zone}.sqlite3 -rr_{ns,ip} -zone_ns_ip

# validate zones + map each name's eTLD+1
./dns-tools -db ${zone}.sqlite3 -validate
# check if the eTLD+1s marked with (maybe_zone) are valid zones and whether they're registered
./dns-tools -db ${zone}.sqlite3 -maybe_zone
