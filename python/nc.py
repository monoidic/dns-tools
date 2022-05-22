#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup

from typing import TextIO

def fetch(outfile: TextIO) -> None:
    res = requests.get('https://www.domaine.nc/whos?who=A*')

    parsed = BeautifulSoup(res.content, features='lxml')

    for domain in (a.text for a in parsed.find_all('a', {'target': '_top'}) if a.attrs['href'].startswith('/whos?domain=')):
        outfile.write(f'{domain.lower()}\n')


if __name__ == '__main__':
    import sys
    fetch(sys.stdout)
