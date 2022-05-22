#!/usr/bin/env python3

from random import choices
from string import ascii_lowercase, digits
from typing import TextIO, List, Tuple, Iterable, Dict
from functools import lru_cache

import requests
from bs4 import BeautifulSoup

s = f'-{digits}{ascii_lowercase}'

_s_index = {c: i for i, c in enumerate(s)}
_min, _a, _z, _0, _9 = (_s_index[c] for c in '-az09')


@lru_cache
def get_match(start: int, end: int) -> str:
    if end - start == 1:
        return s[start]

    ret = '.'

    for r_start, r_end in [
        (_0, _9),
        (_a, _z),
        (_min, _min),
    ]:
        r = s[max(start, r_start):min(end, r_end+1)]
        len_r = len(r)
        if len_r == 1:
            ret += r
        elif len_r > 1:
            ret += f'{r[0]}-{r[-1]}'

    return f'[{ret}]'


def rand_string(n:int=8) -> str:
    return ''.join(choices(ascii_lowercase, k=n))


def parse_page(page: bytes) -> Tuple[List[str], bool]:
    parsed = BeautifulSoup(page, features='lxml')
    table = parsed.find('table', {'class': 'results'})
    tds = table.find_all('td')
    limit_reached = tds[-1].text == 'Query limit reached.' if tds else False

    return [e.text.lower() for e in table.find_all('a')], limit_reached


def tor_rand() -> Dict[str, str]:
    return {'https': f'http://user_{rand_string()}:pass_{rand_string()}@127.0.0.1:9080'}


def recurse_fetch(base:str='', start:int=0, end:int=len(s)) -> Iterable[str]:
    query = f'^{base}{get_match(start, end)}{rand_string(1)}?{rand_string(1)}?'
    for i in range(5):
        try:
            res = requests.post('https://whois.telecoms.gov.bb/search/', data={'Domain': query}, headers={'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:100.0) Gecko/20100101 Firefox/100.0'}, proxies=tor_rand())
            break
        except requests.exceptions.ProxyError:
            continue
    else:
        raise Exception('too many proxy errors')

    page_domains, limit_reached = parse_page(res.content)
    # print(f'{query=} {limit_reached=}')

    yield from page_domains

    if not limit_reached:
        return

    edge_char = page_domains[-1][len(base)]

    if edge_char == '.':
        raise Exception('idk lol')

    if edge_char == s[start]:
        yield from recurse_fetch(base + edge_char)
        yield from recurse_fetch(base, _s_index[edge_char]+1)
    else:
        yield from recurse_fetch(base, _s_index[edge_char], end)


def fetch(outfile: TextIO) -> None:
    for domain in sorted(set(recurse_fetch())):
        outfile.write(f'{domain}\n')


if __name__ == '__main__':
    import sys
    fetch(sys.stdout)
