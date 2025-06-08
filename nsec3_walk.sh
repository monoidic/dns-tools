#!/usr/bin/env bash

bin="~/src/dns-tools/dns-tools"
db=$(mktemp --tmpdir nsec3_walk.XXXXXX.sqlite3)

source lib.sh

main() {
	# get rid of leftovers
	rm "${db}"* 2>/dev/null
	init_db

	# add zones
	for zone in $*; do
		insert_zone $zone
	done
	# detect nsec3
	scan -nsec_map
	# walk
	scan -nsec3_walk

	hashcat_format

	rr_info

	rm "${db}"*
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

rr_info() {
	sqlite3 "$db" 'SELECT nsec3_hashes.nsec3_hash, rr_type.name FROM nsec3_hash_rr_map INNER JOIN nsec3_hashes ON nsec3_hash_rr_map.nsec3_hash_id=nsec3_hashes.id INNER JOIN rr_type ON nsec3_hash_rr_map.rr_type_id=rr_type.id ORDER BY nsec3_hashes.nsec3_hash' | tr '|' '\t'
}

main $*
