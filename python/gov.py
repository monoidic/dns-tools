#!/usr/bin/env python3

import requests

import csv
import io

from typing import TextIO

def fetch(outfile: TextIO) -> None:
    res = requests.get('https://raw.githubusercontent.com/cisagov/dotgov-data/main/current-full.csv')
    with io.StringIO(res.text) as fd:
        reader = csv.DictReader(fd)
        for domain in (e['Domain Name'].lower() for e in reader):
            outfile.write(f'{domain}\n')

if __name__ == '__main__':
    import sys
    fetch(sys.stdout)
