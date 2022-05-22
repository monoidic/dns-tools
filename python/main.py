#!/usr/bin/env python3

import glob
import sqlite3
import json

import dns.zone
import dns.name
import dns.rdatatype

from typing import Iterable, Any, Collection
from functools import partial
from itertools import repeat


def get_db(path: str) -> sqlite3.Connection:
    db = sqlite3.connect(path)
    c = db.cursor()

    for query in [
        '''
        CREATE TABLE IF NOT EXISTS zone
        (
            id INTEGER PRIMARY KEY,
            name STRING UNIQUE
        )
        ''',
        '''
        CREATE TABLE IF NOT EXISTS domain2rr
        (
            id INTEGER PRIMARY KEY,
            zone_id INTEGER NOT NULL,
            rr_type STRING NOT NULL,
            rr_name STRING NOT NULL,
            rr_val STRING NOT NULL,
            FOREIGN KEY(zone_id) REFERENCES zone(id)
        )
        ''',
    ]:
        try:
            c.execute(query)
        except sqlite3.OperationalError:
            print(query)
            raise

    c.close()
    db.commit()
    return db


def _insert(c: sqlite3.Cursor, *values: Iterable[Any], table_name: str, value_names: Collection[str]) -> int:
    check_s = f'SELECT id FROM {table_name} WHERE ' + ' AND '.join(f'{name}=?' for name in value_names)
    for res_id, in c.execute(check_s, values):
        break
    else:
        field_names = ','.join(value_names)
        field_values = ','.join(repeat('?', len(value_names)))
        insert_s = f'INSERT INTO {table_name} ({field_names}) VALUES ({field_values})'
        c.execute(insert_s, values)
        res_id = c.lastrowid

    assert isinstance(res_id, int)
    return res_id


insert_zone_name = partial(_insert, table_name='zone', value_names=('name',))


def insert_zone_from_file(db: sqlite3.Connection, zone: str, filename: str) -> None:  # name has to have a trailing dot
    print(f'inserting zone {zone}')
    zone_o = dns.zone.from_file(filename, zone, relativize=False)
    insert_zone(db, zone, zone_o)


def insert_zone(db: sqlite3.Connection, zone: str, zone_o: dns.zone.Zone) -> None:
    name_rrset = (
        (name, rrset)
        for name, rrset in zone_o.iterate_rdatasets()
        if rrset.rdtype not in {dns.rdatatype.RRSIG, dns.rdatatype.NSEC, dns.rdatatype.NSEC3}
    )

    c = db.cursor()
    for zone_id, in c.execute('SELECT id FROM zone WHERE name = ?', (zone,)).fetchall():
        return  # already inserted into this file?

    zone_id = insert_zone_name(c, zone)

    for name, rrset in name_rrset:
        rr_name = name.to_text()
#        print(f'inserting {rr_name}')
        rr_type = dns.rdatatype.to_text(rrset.rdtype)
        it = ((zone_id, rr_type, rr_name, str(item)) for item in rrset.items)
        c.executemany(
            'INSERT INTO domain2rr (zone_id, rr_type, rr_name, rr_val) '
            'VALUES (?, ?, ?, ?)', it
        )

    db.commit()
    c.close()



def main() -> None:
#    with open('conf.json') as fd:
#        conf = json.load(fd)

    db = get_db('test.sqlite3')
    for filename in glob.glob('zones/*.zone'):
        zone_name = filename.rsplit('/', 1)[-1].rsplit('.', 1)[0] + '.'
        insert_zone_from_file(db, zone_name, filename)


if __name__ == '__main__':
    main()
