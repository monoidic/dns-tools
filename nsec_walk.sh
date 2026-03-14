#!/usr/bin/env bash

db=$(mktemp ./nsec_walk.XXXXXX.sqlite3)

source lib.sh

print_out() {
    chunk_name=''
    chunk_rrs=''

    while read s; do
        this_name=$(echo $s | cut -d'|' -f1)
        this_rrn=$(echo $s | cut -d'|' -f2)
        if [[ $chunk_name != $this_name ]]; then
            if [[ $chunk_name != '' ]]; then
                printf '%s:%s\n' "$chunk_name" "$chunk_rrs"
            fi
            chunk_name=$this_name
            chunk_rrs=''
        fi
        chunk_rrs="${chunk_rrs} ${this_rrn}"
    done <<< $(sqlite3 "$db" 'SELECT rr_name.name, rr_type.name FROM zone_walk_res INNER JOIN rr_name ON zone_walk_res.rr_name_id=rr_name.id INNER JOIN rr_type ON zone_walk_res.rr_type_id=rr_type.id ORDER BY rr_name.name, rr_type.name')
    #    ^ https://stackoverflow.com/questions/16854280/a-variable-modified-inside-a-while-loop-is-not-remembered

    # final chunk
    printf '%s:%s\n' "$chunk_name" "$chunk_rrs"
}

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

    print_out

    rm "${db}"*
}

main $*
