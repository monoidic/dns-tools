#!/bin/bash

zone="$1"

# parse list to maybe_zones
./dns-tools -db ${zone}.sqlite3 -parse_lists lists/${zone}.txt
# validate maybe_zones
./dns-tools -db ${zone}.sqlite3 -maybe_zone

./unreg_common.sh "$zone"
