#!/usr/bin/env python3

import dns.query
import dns.message
import dns.name
import dns.rdtypes.util
import dns.rdatatype
import dns.rrset
import random
import sys
import json
import bisect

from typing import Optional, Union, Iterable, List, Dict, Tuple, Any, Set

separator = "\n----------\n"

used_ns = [
        '9.9.9.9',        '9.9.9.10',       '149.112.112.112', # quad9
        '1.1.1.1',        '1.0.0.1',                           # cloudflare
        '8.8.8.8',        '8.8.4.4',                           # google
        '208.67.222.222', '208.67.220.220',                    # cisco opendns
        '77.88.8.8',      '77.88.8.1',                         # yandex
        '64.6.64.6',      '64.6.65.6',                         # verisign
]

class Zone(object):
    def __init__(self, name: dns.name.Name) -> None:
#        self.wildcards = set()
        self.unhandled_ranges: Set[Tuple[dns.name.Name, Optional[dns.name.Name]]] = set()
        self.known_ranges: List[Tuple[dns.name.Name, dns.name.Name]] = []
        self.records: Dict[str, List[str]] = {}
        self.name = name
        self.subdomains: Set[str] = set()
        self.has_soa: Dict[dns.name.Name, dns.name.Name] = {}

    def __contains__(self, name: dns.name.Name) -> bool:
        # TODO tells you if it's already discovered in the zone
        # also handle wildcards somehow here?

#        index = bisect.bisect_left(self.known_ranges, name, key=lambda e: e[0])
        starts = [start_i for start_i, end_i in self.known_ranges]
        index = bisect.bisect_left(starts, name)
        if index == len(self.known_ranges):
            if not self.known_ranges:
                return False
            index_start, index_end = self.known_ranges[index]
            return name < index_end or index_end == self.name

        index_start, index_end = self.known_ranges[index]
        if index == 0:
            return name == index_start  # only valid location for index 0
        elif name == index_start:
            return True

        prev_start, prev_end = self.known_ranges[index-1]
        return prev_start <= name < prev_end

    def add(self, rrset: dns.rrset.RRset) -> bool:
        assert len(rrset) == 1, f'big NSEC rrset:\n{str(rrset)}'

        start = rrset.name
        end = rrset[0].next
        assert start < end or end == self.name

        rec_key = start.to_text()
        if rec_key in self.records:
            return False

        print(f'adding {start} {end} to zone {self.name}')
        records = sorted(set(dns.rdtypes.util.Bitmap(rrset[0].windows).to_text()[1:].split(' ')) - {'NSEC', 'RRSIG'})

        if 'NS' in records and start != self.name:
            self.subdomains.add(rec_key)

        self.records[rec_key] = records

        ## only works with py3.10
        # index = bisect.bisect_left(self.known_ranges, start, key=lambda e: e[0])
        starts = [start_i for start_i, end_i in self.known_ranges]
        index = bisect.bisect_left(starts, start)

        if index == len(self.known_ranges):  # past end or first
            self._add_to_end(start, end)
        elif index == 0:
            if end < self.known_ranges[0][0]:  # entirely before first range
                self.known_ranges.insert(0, (start, end))
            elif end == self.known_ranges[0][0]:
                self.known_ranges[0] = (start, self.known_ranges[0][1])
            else:
                assert False
        else:
            self._add_to_middle(start, end, index)

        return True

    def _add_to_end(self, start: dns.name.Name, end: dns.name.Name) -> None:
        if not self.known_ranges:
            self.known_ranges.append((start, end))
            return

        last_name = self.known_ranges[-1][1]
        if last_name == self.name:  # the final range technically covers the new range due to wraparound
            pass
        elif start > last_name:  # new range comes after last known range, without overlap
            self.known_ranges.append((start, end))
        else: # merge (old_start < new_start <= (old_end, new_end)) into (old_start < max(old_end, new_end))
            old_start, old_end = self.known_ranges.pop()
            assert old_start < start
            new_end = self.name if self.name in (end, old_end) else max(end, old_end)
            self.known_ranges.append((old_start, new_end))

    def _add_to_middle(self, start: dns.name.Name, end: dns.name.Name, index: int) -> None:
        # somewhere in the middle
        # cases for either start or end:
        # * at the start of a range
        # * in the middle of a range
        # * at the end of a range
        # * outside of current ranges

        # "impossible" additions are impossible under the assumption
        #  that only directly successive pairs of domains are added, e.g
        #  only this sequence can be followed valid:
        # ... end outside* start middle* end outside* start ...

        # start at start,  end in start/outside: impossible
        # start at start,  end in middle/end:    nop

        # start in middle, end in start/outside: impossible
        # start in middle, end in middle/end:    nop

        # start at end,    end at start:         merge
        # start at end,    end at middle/end:    impossible
        # start at end,    end outside:          extend

        # start outside,   end at start:         extend
        # start outside,   end at middle/end:    impossible
        # start outside,   end outside:          new

        index_start, index_end = self.known_ranges[index]
        prev_start,  prev_end  = self.known_ranges[index-1]

        if start == index_start:  # start
            if not end <= index_end:  # impossible (nop otherwise)
                raise ValueError(f'unexpected value at start == index_start, {start=} {end=} {index_start=} {index_end=}')

        elif index_start < start < index_end:  # middle
            if not end <= index_end:  # impossible (nop otherwise)
                raise ValueError(f'unexpected value at index_start < start < index_end, {start=} {end=} {index_start=} {index_end=}')

        elif start == prev_end:  # end
            if end == index_start:  # merge
                self.known_ranges[index-1:index+1] = [(prev_start, index_end)]
            elif end < index_start:  # extend
                self.known_ranges[index-1] = (prev_start, end)
            else:
                raise ValueError(f'unexpected value at start == prev_end, {start=} {end=} {index_start=} {index_end=} {prev_start=} {prev_end=}')

        elif start < index_start:  # outside
            if end == index_start:  # extend
                self.known_ranges[index] = (start, index_end)
            elif end < index_start:  # new
                self.known_ranges.insert(index, (start, end))
            else:
                raise ValueError(f'unexpected value at start < index_start, {start=} {end=} {index_start=} {index_end=}')

        else:
            raise ValueError(f'unreachable {start=} {end=} {index_start=} {index_end=}')

    def _get_unknown_ranges(self) -> Iterable[Tuple[dns.name.Name, Optional[dns.name.Name]]]:
        if len(self.known_ranges) == 0:
            yield (self.name, None)
            return

        first_name = self.known_ranges[0][0]
        if first_name != self.name:
            yield (self.name, first_name)

        if len(self.known_ranges) == 1:
            last_name = self.known_ranges[0][1]
            if last_name != self.name:
                yield (last_name, None)
        else:
            first = iter(self.known_ranges)
            second = iter(self.known_ranges)
            next(second)

            for (_, start), (end, last) in zip(first, second):
                yield (start, end)

            if last != self.name:  # no wraparound
                yield (last, None)

    def get_unknown_ranges(self) -> Iterable[Tuple[dns.name.Name, Optional[dns.name.Name]]]:
        yield from (r for r in self._get_unknown_ranges() if r not in self.unhandled_ranges)

    def get_everything(self) -> Dict[str, Any]:
        ret = {
            'records': self.records,
            'subdomains': sorted(self.subdomains),
            'unhandled_ranges': sorted([start.to_text(), (None if end is None else end.to_text())] for start, end in self.unhandled_ranges),
            'has_soa': {k.to_text(): sorted(name.to_text() for name in v) for k, v in self.has_soa.items()},
        }

        return ret


def perform_query(query: dns.message.QueryMessage, tries: int = 10, nameservers: List[str] = used_ns) -> Optional[dns.message.QueryMessage]:
    for _ in range(tries):
        try:
            res, _ = dns.query.udp_with_fallback(query, random.choice(nameservers), timeout=5)
            return res
        except Exception as e:
            print(f'perform_query: {e}')

    return None


def minus_subdomains(name: List[bytes]) -> dns.name.Name:  # x.example.com -> -.x.example.com
    return dns.name.Name([b'--', b'--'] + name)


def minus_subdomain(name: List[bytes]) -> dns.name.Name:  # x.example.com -> -.x.example.com
    return dns.name.Name([b'--'] + name)


def increment_label(name: List[bytes]) -> dns.name.Name:  # aaa.example.com -> aab.example.com
    first_label = name[0]
    new_label = first_label[:-1] + bytes([first_label[-1] + 1])
    new_name = [new_label] + name[1:]
    return dns.name.Name(new_name)


def decrement_label(name: List[bytes]) -> dns.name.Name:  # bbb.example.com -> bba.example.com
    first_label = name[0]
    new_label = first_label[:-1] + bytes([first_label[-1] - 1])
    new_name = [new_label] + name[1:]
    return dns.name.Name(new_name)


def minus_appended(name: List[bytes]) -> dns.name.Name:
    return dns.name.Name([name[0] + b'--'] + name[1:])  # x.example.com -> x-.example.com


def nop(name: List[bytes]) -> dns.name.Name:
    return dns.name.Name(name)


def get_middle_domain(current: dns.name.Name, domain: dns.name.Name, end: Optional[dns.name.Name]) -> Iterable[dns.name.Name]:
    split = list(current.labels)
    if end == domain:
        end = None

    for i in range(10):
        if end is not None:
            split_end = list(end.labels)
            for f in (decrement_label, nop):
                y = f(split_end[i:])
                if y.is_subdomain(domain) and current <= y < end:
                    yield y

        for f in (minus_appended, minus_subdomains, minus_subdomain, increment_label, nop):
            y = f(split[i:])
            if y.is_subdomain(domain) and (current <= y and (end is None or y < end)):
                yield y


def walk(domain: Union[str, dns.name.Name]) -> Dict[str, Any]:
    if isinstance(domain, str):
        if not domain.endswith('.'):
            domain += '.'

        domain = dns.name.Name(domain.split('.'))

    zone = Zone(domain)

    while True:
        more_unknown_ranges = False
#        for name in (name for start, end in zone.get_unknown_ranges() for name in get_middle_domain(start, domain, end)):
        for start, end in zone.get_unknown_ranges():
            for name in get_middle_domain(start, domain, end):
                more_unknown_ranges = True
                print(f'trying {name=}')
                query = dns.message.make_query(name, dns.rdatatype.APL, want_dnssec=True)
                res = perform_query(query)
                assert res is not None

                soa_rrset = [rrset for rrset in res.authority if rrset.rdtype == dns.rdatatype.SOA]
                if soa_rrset and soa_rrset[0].name != domain:
                    zone.has_soa.setdefault(soa_rrset[0].name, set()).add(name)
                    continue

                nsec_rrsets = (rrset for rrset in res.authority if rrset.rdtype == dns.rdatatype.NSEC)

                num_added = sum(zone.add(rrset) for rrset in nsec_rrsets)
                if num_added:
#                    print(f'added {num_added} ranges')
                    break

            else:  # no matches at all
                print(f'adding unhandled range {start} {end}')
                zone.unhandled_ranges.add((start, end))
                continue
            # match
            break


        if not more_unknown_ranges:
            break


    return zone.get_everything()

    # TODO
    # attempt querying for NSEC labels directly on unknown names?
    # attempt querying for uncommon labels on uncommon names (SSHFP/PTR/OPENPGPKEY)? https://en.wikipedia.org/wiki/List_of_DNS_record_types
    # attempt AXFR first?


    # TODO
    # handle wildcard subdomains
    # dump all RRs?

    # CANONICAL ORDERING
    # set uppercase to lowercase;
    # treat as lowercase lowercase unsigned char array;
    # compare first min(len(a), len(b)) chars of a and b;
    # in case that's equal, the shorter one comes first;
    # subname comes after name

    # go along with -.<current_name>.<domain> unless it's a delegation;
    # if it's a delegation, do <current_name>-.<domain> ?;
    # alternatively, ~.<next_name>.<domain> or zzzzzzzzz.<next_name>.<domain> ?;
    # be wary of wildcard subdomains (can still be worked around since they're just plain * to DNS);
    # be wary of DNS record length limits;


def get_nameservers(domain: dns.name.Name) -> List[str]:
    ns_name_query = dns.message.make_query(domain, dns.rdatatype.NS)
    ns_name_res = perform_query(ns_name_query)
    assert ns_name_res is not None
    ns_names = [rr.target for rrset in ns_name_res.answer if rrset.rdtype == dns.rdatatype.NS and rrset.name == domain for rr in rrset]

    out: Set[str] = set()
    for ns_name in ns_names:
        ns_ip_query = dns.message.make_query(ns_name, dns.rdatatype.A)  # TODO ipv6?
        ns_ip_res = perform_query(ns_ip_query)
        assert ns_ip_res is not None
        out.update(rr.address for rrset in ns_ip_res.answer if rrset.rdtype == dns.rdatatype.A and rrset.name == ns_name for rr in rrset)

    return sorted(out)


# walk NSEC chain; might not give the full chain, but "reliable" if it works at all
# TODO even this fucking gets stuck on e.g africa.gentoo.org (subdomain of gentoo.org) because it shares nameservers
def lazy_walk(domain: Union[str, dns.name.Name]) -> Dict[str, Any]:
    # TODO verify it works at all?
    if isinstance(domain, str):
        if not domain.endswith('.'):
            domain += '.'

        domain = dns.name.Name(domain.split('.'))

    nameservers = get_nameservers(domain)

    out = {}
    remaining = {domain}
    while remaining:
        print(remaining)
        current = remaining.pop()
        query = dns.message.make_query(current, dns.rdatatype.NSEC, want_dnssec=True)
        res = perform_query(query, nameservers=nameservers)
        assert res is not None
        new_nsec = [
            rrset for rrset in res.answer
            if rrset.rdtype == dns.rdatatype.NSEC and rrset.name not in out
        ]
        out.update({
            rrset.name: dns.rdtypes.util.Bitmap(rrset[0].windows).to_text()[1:].split(' ')
            for rrset in new_nsec
        })
        remaining.update(rr.next for rrset in new_nsec for rr in rrset)

    return {k.to_text()[:-1]: v for k, v in out.items()}


def main() -> None:
    domain = sys.argv[1]
#    ret = lazy_walk(domain)
    ret = walk(domain)
    print(ret)
    with open(f'{domain.rstrip(".")}.json', 'w') as fd:
        json.dump(ret, fd, sort_keys=True)


if __name__ == '__main__':
    main()
