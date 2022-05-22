#!/usr/bin/env python3

import dns.query
import dns.message
import dns.rdatatype
import dns.exception
import dns.rrset
import dns.rdtypes.nsbase
import random
import multiprocessing
import sqlite3
import enum
import base64
import sys

from typing import Callable, Any, Iterable, Optional, Dict
from functools import partial

#print = partial(print, flush=True)

used_ns = (
        '9.9.9.9',        '9.9.9.10',       '149.112.112.112', # quad9
        '1.1.1.1',        '1.0.0.1',                           # cloudflare
        '8.8.8.8',        '8.8.4.4',                           # google
        '208.67.222.222', '208.67.220.220',                    # cisco opendns
        '77.88.8.8',      '77.88.8.1',                         # yandex
        '64.6.64.6',      '64.6.65.6',                         # verisign
)

nsec3_table = str.maketrans(
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
    '0123456789ABCDEFGHIJKLMNOPQRSTUV'
)


def init_db(path: str) -> sqlite3.Connection:
    db = sqlite3.connect(path)
    c = db.cursor()

    for query in (
        '''
        CREATE TABLE IF NOT EXISTS domain
        (
            id INTEGER PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            bl_result_id INTEGER NOT NULL REFERENCES bl_result(id),
            rname_id INTEGER NOT NULL REFERENCES uniq_text(id),
            mname_id INTEGER NOT NULL REFERENCES uniq_text(id),
            nsec TEXT NOT NULL
        )
        ''',
        '''
        CREATE TABLE IF NOT EXISTS bl_result
        (
            id INTEGER PRIMARY KEY,
            name TEXT UNIQUE NOT NULL
        )
        ''',
        '''
        CREATE TABLE IF NOT EXISTS uniq_text
        (
            id INTEGER PRIMARY KEY,
            text TEXT UNIQUE NOT NULL
        )
        ''',
        '''
        INSERT OR IGNORE INTO bl_result (id, name) VALUES
        (1, 'secure_nsec'),
        (2, 'plain_nsec' ),
        (3, 'nsec3'      ),
        (4, 'unknown'    )
        '''
    ):
        c.execute(query)

    c.close()
    return db


def pool_apply(multi_f: Callable[..., Any], it: Iterable[Any], data_f: Callable[..., Any], pool_size: int = 100) -> None:
    with multiprocessing.Pool(pool_size) as pool:
        for res in pool.imap_unordered(multi_f, it):
            if res:
                data_f(res)

        pool.close()
        pool.join()


class BLResult(enum.IntEnum):
    is_bl   = 1
    not_bl  = 2
    nsec3   = 3
    unknown = 4

blacklisted_mail = {
    'dns.cloudflare.com.',
    'awsdns-hostmaster.amazon.com.',
    'hostmaster.nsone.net.',
    'admin.dnsimple.com.',
    'administrator.dynu.com.',
    'hostmaster.hichina.com.',
    'hostmaster.eurodns.com.',

    'tech.brandshelter.com.',
    'hostmaster.vismasoftware.no.',
    'domainadm.visma.com.',
}

blacklisted_ns = (
    'ultradns.com.',
#    'nsone.net.',
#    'dnspod.net.',
)


def perform_query(query: dns.message.QueryMessage) -> Optional[dns.message.QueryMessage]:
    for i in range(10):
        try:
            res, _ = dns.query.udp_with_fallback(query, random.choice(used_ns), timeout=5)
            return res
        except Exception as e:
            pass

    return None


def check_blacklisted(domain: str, res_soa: dns.message.QueryMessage) -> Dict[str, Any]:
    nsec_str = '|'.join(f'{rrset.name.to_text()}^{rr.next.to_text()}' for rrset in res_soa.authority if rrset.rdtype == dns.rdatatype.NSEC for rr in rrset)
    ret = {'domain': domain, 'nsec_str': nsec_str, 'bl_result': BLResult.unknown, 'rname': '(unknown)', 'mname': '(unknown)'}

    if any(rrset.rdtype == dns.rdatatype.SOA for rrset in res_soa.authority):
        soa_list = res_soa.authority
    else:
        query_soa = dns.message.make_query(domain, dns.rdatatype.SOA)
        res_soa = perform_query(query_soa)
        if not res_soa:
            print(f'unable to get SOA for {domain=}')
            return ret

        soa_list = res_soa.answer

    soa_rrs = [rr for rrset in soa_list if rrset.rdtype == dns.rdatatype.SOA for rr in rrset]

    if len(soa_rrs) != 1:
        print(f'not exactly 1 SOA RR for {domain=}')
        return ret

    soa_rr = soa_rrs[0]
    mail = soa_rr.rname.to_text()
    master = soa_rr.mname.to_text()
    ret.update({
        'rname': mail,
        'mname': master,
        'bl_result': (BLResult.is_bl if mail in blacklisted_mail or any(master.endswith(ns) for ns in blacklisted_ns) else BLResult.not_bl),
    })

    return ret


def data_nsec3(domain: str, res_soa: dns.message.QueryMessage) -> Dict[str, Any]:
    nsec3_str = '|'.join(rr.to_text() for rrset in res_soa.answer if rrset.rdtype == dns.rdatatype.NSEC3PARAM for rr in rrset)
    ret = {'domain': domain, 'nsec_str': nsec3_str, 'bl_result': BLResult.nsec3, 'rname': '(unknown)', 'mname': '(unknown)'}

    if any(rrset.rdtype == dns.rdatatype.SOA for rrset in res_soa.authority):
        soa_list = res_soa.authority
    else:
        query_soa = dns.message.make_query(domain, dns.rdatatype.SOA)
        res_soa = perform_query(query_soa)
        if not res_soa:
            print(f'unable to get SOA for {domain=} (nsec3)')
            return ret

        soa_list = res_soa.answer

    soa_rrs = [rr for rrset in soa_list if rrset.rdtype == dns.rdatatype.SOA for rr in rrset]

    if len(soa_rrs) != 1:
        print(f'not exactly 1 SOA RR for {domain=} (nsec3)')
        return ret

    soa_rr = soa_rrs[0]
    ret.update({
        'rname': soa_rr.rname.to_text(),
        'mname': soa_rr.mname.to_text(),
    })

    return ret


def check_nsec(domain: str) -> Optional[Dict[str, Any]]:
    query = dns.message.make_query(domain, dns.rdatatype.NSEC3PARAM, want_dnssec=True)
    res = perform_query(query)
    if res:
        if any(rrset.rdtype == dns.rdatatype.NSEC for rrset in res.authority):
            return check_blacklisted(domain, res)
        elif any(rrset.rdtype == dns.rdatatype.NSEC3PARAM for rrset in res.answer):
            return data_nsec3(domain, res)

    return None


res_string_map = {
    BLResult.is_bl  : 'blacklisted',
    BLResult.not_bl : 'vulnerable',
    BLResult.nsec3  : 'nsec3',
    BLResult.unknown: 'unknown',
}

def insert_text(c: sqlite3.Cursor, text: str) -> int:
    c.execute('SELECT id FROM uniq_text WHERE text = ?', (text,))
    for result, in c.execute('SELECT id FROM uniq_text WHERE text = ?', (text,)):
        return result

    c.execute('INSERT INTO uniq_text (text) VALUES (?)', (text,))
    return c.lastrowid

def _insert_domain(db: sqlite3.Connection, data: Dict[str, Any]) -> None:
    print(f'found {res_string_map[data["bl_result"]]} domain: {data["domain"]}')
    c = db.cursor()

    data['rname_id'] = insert_text(c, data['rname'])
    data['mname_id'] = insert_text(c, data['mname'])

    for entry_id, in c.execute('SELECT id FROM domain WHERE name=:domain', data): # exists
        data['entry_id'] = entry_id
        c.execute('UPDATE domain SET name=:domain, bl_result_id=:bl_result, rname_id=:rname_id, mname_id=:mname_id, nsec=:nsec_str WHERE id=:entry_id', data)
        break
    else:
        c.execute('INSERT INTO domain (name, bl_result_id, rname_id, mname_id, nsec) VALUES (:domain, :bl_result, :rname_id, :mname_id, :nsec_str)', data)

    c.close()
    while True:
        try:
            db.commit()
            break
        except sqlite3.OperationalError:
            pass


def main() -> None:
    db = init_db('nsec.sqlite3')
    insert_domain = partial(_insert_domain, db)

    for filename in sys.argv[1:]:
        with open(filename) as fd:
            domains = (line.strip().rstrip('.') + '.' for line in fd)
            pool_apply(check_nsec, domains, insert_domain)

    return


if __name__ == '__main__':
    main()
