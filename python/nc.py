#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup

from typing import TextIO


def fetch(outfile: TextIO) -> None:
    res = requests.get("https://www.domaine.nc/whos?who=A*")

    parsed = BeautifulSoup(res.content, features="lxml")
    domains = (e.text for e in parsed.select('td[width="50%"] a[target=_top]'))
    for domain in domains:
        outfile.write(f"{domain.lower()}\n")


if __name__ == "__main__":
    import sys

    fetch(sys.stdout)
