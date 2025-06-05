CREATE TABLE IF NOT EXISTS name
(
    id              INTEGER PRIMARY KEY,
    name            TEXT UNIQUE NOT NULL,
    is_ns           INTEGER NOT NULL DEFAULT FALSE,
    is_mx           INTEGER NOT NULL DEFAULT FALSE,
    is_zone         INTEGER NOT NULL DEFAULT FALSE,
    is_rdns         INTEGER NOT NULL DEFAULT FALSE,
    cname_tgt_id    INTEGER REFERENCES name(id),
    parent_id       INTEGER REFERENCES name(id),
    etldp1_id       INTEGER REFERENCES name(id),
    registered      INTEGER NOT NULL DEFAULT TRUE,
    reg_checked     INTEGER NOT NULL DEFAULT FALSE,
    nsec_mapped     INTEGER NOT NULL DEFAULT FALSE,
    nsec_walked     INTEGER NOT NULL DEFAULT FALSE,
    mx_resolved     INTEGER NOT NULL DEFAULT FALSE,
    ns_resolved     INTEGER NOT NULL DEFAULT FALSE,
    glue_ns         INTEGER NOT NULL DEFAULT FALSE, -- for zones. glue NS has been fetched from parent zone
    addr_resolved   INTEGER NOT NULL DEFAULT FALSE,
    spf_tried       INTEGER NOT NULL DEFAULT FALSE,
    dmarc_tried     INTEGER NOT NULL DEFAULT FALSE, -- so that '_dmarc.${name}' does not need to be stored
    valid           INTEGER NOT NULL DEFAULT TRUE,  -- has valid parent zone chain/TLD
    valid_tried     INTEGER NOT NULL DEFAULT FALSE, -- validation has been verified
    parent_mapped   INTEGER NOT NULL DEFAULT FALSE,
    maybe_zone      INTEGER NOT NULL DEFAULT FALSE,
    maybe_checked   INTEGER NOT NULL DEFAULT FALSE,
    inserted        INTEGER NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS ip
(
    id              INTEGER PRIMARY KEY,
    address         TEXT UNIQUE NOT NULL,
    rdns_mapped     INTEGER NOT NULL DEFAULT FALSE,
    responsive      INTEGER NOT NULL DEFAULT TRUE,
    ch_resolved     INTEGER NOT NULL DEFAULT FALSE, -- Chaosnet class records, e.g version.bind
    resp_checked    INTEGER NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS rdns
(
    id      INTEGER PRIMARY KEY,
    ip_id   INTEGER NOT NULL REFERENCES ip(id),
    name_id INTEGER NOT NULL REFERENCES name(id),
    UNIQUE(ip_id, name_id)
);

CREATE TABLE IF NOT EXISTS zone_ns
(
    id              INTEGER PRIMARY KEY,
    zone_id         INTEGER NOT NULL REFERENCES name(id),
    ns_id           INTEGER NOT NULL REFERENCES name(id),
    in_parent_zone  INTEGER NOT NULL DEFAULT FALSE,
    in_self_zone    INTEGER NOT NULL DEFAULT FALSE,
    UNIQUE(zone_id, ns_id)
);

CREATE TABLE IF NOT EXISTS name_mx
(
    id          INTEGER PRIMARY KEY,
    name_id     INTEGER NOT NULL REFERENCES name(id),
    mx_id       INTEGER NOT NULL REFERENCES name(id),
    preference  INTEGER NOT NULL,
    UNIQUE(name_id, mx_id)
);

CREATE TABLE IF NOT EXISTS name_ip
(
    id                  INTEGER PRIMARY KEY,
    name_id             INTEGER NOT NULL REFERENCES name(id),
    ip_id               INTEGER NOT NULL REFERENCES ip(id),
    in_parent_zone_glue INTEGER NOT NULL DEFAULT FALSE,
    in_self_zone        INTEGER NOT NULL DEFAULT FALSE,
    UNIQUE(name_id, ip_id)
);

CREATE TABLE IF NOT EXISTS zone_ns_ip (
    id          INTEGER PRIMARY KEY,
    zone_id     INTEGER NOT NULL REFERENCES name(id), -- zone, e.g example.com.
    ip_id       INTEGER NOT NULL REFERENCES ip(id),   -- ns ip, e.g 1.2.3.4 for ns1.example.com
    axfr_tried  INTEGER NOT NULL DEFAULT FALSE,
    axfrable    INTEGER NOT NULL DEFAULT FALSE,
    scan_time   INTEGER NOT NULL DEFAULT 0,
    UNIQUE(zone_id, ip_id)
);

CREATE TABLE IF NOT EXISTS spf
(
    id              INTEGER PRIMARY KEY,
    name_id         INTEGER NOT NULL REFERENCES name(id),
    spf_record_id   INTEGER NOT NULL REFERENCES spf_record(id),
    duplicate       INTEGER NOT NULL DEFAULT FALSE,
    UNIQUE(name_id, spf_record_id)
);

CREATE TABLE IF NOT EXISTS spf_record
(
    id          INTEGER PRIMARY KEY,
    value       TEXT UNIQUE NOT NULL,
    valid       INTEGER NOT NULL DEFAULT TRUE,
    error       TEXT, -- if valid == false, explain why
    any_unknown INTEGER NOT NULL DEFAULT FALSE -- any unknown modifiers
);

CREATE TABLE IF NOT EXISTS spf_name -- for DNS names scraped from the SPF record
(
    id              INTEGER PRIMARY KEY,
    spf_record_id   INTEGER NOT NULL REFERENCES spf_record(id),
    name_id         INTEGER NOT NULL REFERENCES name(id),
    spfname         INTEGER NOT NULL, -- bool, indicates names with additional spf records to fetch
    UNIQUE(spf_record_id, name_id)
);

CREATE TABLE IF NOT EXISTS dmarc_record
(
    id      INTEGER PRIMARY KEY,
    value   TEXT UNIQUE NOT NULL,
    valid   INTEGER NOT NULL DEFAULT TRUE,
    error   TEXT -- if valid == false, explain why
);

CREATE TABLE IF NOT EXISTS dmarc
(
    id              INTEGER PRIMARY KEY,
    name_id         INTEGER NOT NULL REFERENCES name(id),
    dmarc_record_id INTEGER NOT NULL REFERENCES dmarc_record(id),
    duplicate       INTEGER NOT NULL DEFAULT FALSE,
    UNIQUE(name_id, dmarc_record_id)
);

CREATE TABLE IF NOT EXISTS rr_type
(
    id      INTEGER PRIMARY KEY,
    name    TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS rr_name
(
    id      INTEGER PRIMARY KEY,
    name    TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS rr_value
(
    id      INTEGER PRIMARY KEY,
    value   TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS zone2rr
(
    id          INTEGER PRIMARY KEY,
    parsed      INTEGER NOT NULL DEFAULT FALSE,
    zone_id     INTEGER NOT NULL REFERENCES name(id),
    rr_type_id  INTEGER NOT NULL REFERENCES rr_type(id),
    rr_name_id  INTEGER NOT NULL REFERENCES rr_name(id),
    rr_value_id INTEGER NOT NULL REFERENCES rr_value(id),
    inserted    INTEGER NOT NULL DEFAULT FALSE,
    from_parent INTEGER NOT NULL DEFAULT FALSE,
    from_self   INTEGER NOT NULL DEFAULT FALSE,
    poison      INTEGER NOT NULL DEFAULT FALSE,
    UNIQUE(zone_id, rr_type_id, rr_name_id, rr_value_id)
);

CREATE TABLE IF NOT EXISTS rname
(
    id      INTEGER PRIMARY KEY,
    name    TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS mname
(
    id      INTEGER PRIMARY KEY,
    name    TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS nsec_state
(
    id      INTEGER PRIMARY KEY,
    name    TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS zone_nsec_state
(
    id              INTEGER PRIMARY KEY,
    zone_id         INTEGER NOT NULL REFERENCES name(id),
    nsec_state_id   INTEGER NOT NULL REFERENCES nsec_state(id),
    rname_id        INTEGER NOT NULL REFERENCES rname(id),
    mname_id        INTEGER NOT NULL REFERENCES mname(id),
    nsec            TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS zone_walk_res
(
    id          INTEGER PRIMARY KEY,
    zone_id     INTEGER NOT NULL REFERENCES name(id),
    rr_name_id  INTEGER NOT NULL REFERENCES rr_name(id),
    rr_type_id  INTEGER NOT NULL REFERENCES rr_type(id),
    queried     INTEGER NOT NULL DEFAULT FALSE,
    UNIQUE(zone_id, rr_name_id, rr_type_id)
);

INSERT OR IGNORE INTO nsec_state (id, name) VALUES
(1, 'unknown'       ),
(2, 'secure_nsec'   ),
(3, 'plain_nsec'    ),
(4, 'nsec3'         ),
(5, 'nsec_confusion'),
(6, 'secure_nsec3'  );

CREATE TABLE IF NOT EXISTS unwalked_root
(
    id      INTEGER PRIMARY KEY,
    name    TEXT UNIQUE NOT NULL,
    ent     INTEGER NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS chaos_query
(
    id      INTEGER PRIMARY KEY,
    name_id INTEGER NOT NULL REFERENCES name(id), -- e.g version.bind.
    ip_id   INTEGER NOT NULL REFERENCES ip(id),
    UNIQUE(name_id, ip_id)
);

CREATE TABLE IF NOT EXISTS chaos_response_value
(
    id      INTEGER PRIMARY KEY,
    value   TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS chaos_response
(
    id                      INTEGER PRIMARY KEY,
    chaos_query_id          INTEGER NOT NULL REFERENCES chaos_query(id),
    name_id                 INTEGER NOT NULL REFERENCES name(id), -- name in response may not match name in query
    chaos_response_value_id INTEGER NOT NULL REFERENCES chaos_response_value(id),
    UNIQUE(chaos_query_id, chaos_response_value_id)
);

CREATE TABLE IF NOT EXISTS nsec3_zone_params (
    id INTEGER PRIMARY KEY,
    zone_id     INTEGER NOT NULL REFERENCES name(id),
    salt        TEXT NOT NULL,
    iterations  INTEGER NOT NULL,
    UNIQUE(zone_id)
);

CREATE TABLE IF NOT EXISTS nsec3_hashes
(
    id              INTEGER PRIMARY KEY,
    nsec3_zone_id   INTEGER NOT NULL REFERENCES nsec3_zone_params(id),
    nsec3_hash      CHARACTER(32) NOT NULL,
    UNIQUE(nsec3_zone_id, nsec3_hash)
);

CREATE TABLE IF NOT EXISTS nsec3_hash_rr_map
(
    id              INTEGER PRIMARY KEY,
    nsec3_hash_id   INTEGER NOT NULL REFERENCES nsec3_hashes(id),
    rr_type_id      INTEGER NOT NULL REFERENCES rr_type(id),
    UNIQUE(nsec3_hash_id, rr_type_id)
);
