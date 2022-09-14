#!/bin/bash

zone="$1"

# parse zone file to zone2rr
./dns-tools -db ${zone}.sqlite3 -tld_zone -parse zones/${zone}.zone
# parse zone2rr from zone file
./dns-tools -db ${zone}.sqlite3 -rr_{ns,ip}

./unreg_common.sh "$zone"
