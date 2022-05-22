#!/usr/bin/env python3

import requests
import csv
from io import StringIO

from typing import TextIO

def fetch(outfile: TextIO) -> None:
    res = requests.get('https://sk-nic.sk/subory/domains.txt')
    with StringIO(res.text) as s:
        reader = csv.DictReader((line for line in s if not line.startswith('--')), delimiter=';')
        for domain in (e['domena'] for e in reader):
            outfile.write(f'{domain}\n')


if __name__ == '__main__':
    import sys
    fetch(sys.stdout)
