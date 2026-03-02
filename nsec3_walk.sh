#!/usr/bin/env bash

db=$(mktemp ./nsec3_walk.XXXXXX.sqlite3)

source lib.sh

main() {
	init_db

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
    chunk_hash=''
    chunk_rrs=''
	while read s; do
		this_hash=$(echo "$s" | cut -d'|' -f1)
		this_rrs=$(echo "$s" | cut -d'|' -f2)

		if [[ $chunk_hash != $this_hash ]]; then
            if [[ $chunk_hash != '' ]]; then
                printf '%s:%s\n' "$chunk_hash" "$chunk_rrs"
            fi
            chunk_hash="$this_hash"
            chunk_rrs=''
        fi
		chunk_rrs="${chunk_rrs} ${this_rrs}"
	done <<< $(sqlite3 "$db" 'SELECT nsec3_hashes.nsec3_hash, rr_type.name FROM nsec3_hash_rr_map INNER JOIN nsec3_hashes ON nsec3_hash_rr_map.nsec3_hash_id=nsec3_hashes.id INNER JOIN rr_type ON nsec3_hash_rr_map.rr_type_id=rr_type.id ORDER BY nsec3_hashes.nsec3_hash, rr_type.name')
	#    ^ https://stackoverflow.com/questions/16854280/a-variable-modified-inside-a-while-loop-is-not-remembered

	# final chunk
	printf '%s:%s\n' "$chunk_hash" "$chunk_rrs"
}

main $*
