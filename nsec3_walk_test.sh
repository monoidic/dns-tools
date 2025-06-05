#!/usr/bin/env bash

bin="~/go/bin/dns-tools"
#db="/tmp/testx.sqlite3"
db=$(mktemp /tmp/testx.XXXXXX.sqlite3)

scan() {
	eval "$bin" -db "$db" $*
}

insert_zone() {
	zone="$1"
	echo "zone=$zone"
	sqlite3 "$db" "INSERT INTO name (name, is_zone) VALUES ('${zone}', TRUE)"
	sqlite3 "$db" "INSERT INTO zone_nsec_state (zone_id, nsec_state_id, rname_id, mname_id, nsec) VALUES ((SELECT id FROM name WHERE name.name='${zone}'), 4, 0, 0, '')"
}

main() {
	# create dummy db
	scan -rr_ip

	# add zones
	for zone in $*; do
		insert_zone $zone
	done
	# walk
	scan -nsec3_walk
}

hashcat_format() {
	sqlite3 "$db" 'SELECT nsec3_hashes.nsec3_hash, zone.name, nsec3_zone_params.salt, nsec3_zone_params.iterations FROM nsec3_zone_params INNER JOIN nsec3_hashes ON nsec3_hashes.nsec3_zone_id=nsec3_zone_params.id INNER JOIN name AS zone ON nsec3_zone_params.zone_id=zone.id' | while read s; do
		# hash has to be lowercase...?
		hash=$(echo "$s" | cut -d'|' -f1 | tr A-Z a-z)
		domain=$(echo "$s" | cut -d'|' -f2 | sed 's/^/./;s/.$//')
		salt=$(echo "$s" | cut -d'|' -f3)
		iterations=$(echo "$s" | cut -d'|' -f4)

		printf '%s:%s:%s:%d\n' "$hash" "$domain" "$salt" "$iterations"
	done
}

rm ${db}* 2>/dev/null
main $*
hashcat_format
