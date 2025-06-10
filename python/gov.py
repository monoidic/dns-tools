#!/usr/bin/env python3

import requests

import csv
import io

from typing import TextIO


def fetch(outfile: TextIO) -> None:
    url = "https://raw.githubusercontent.com/cisagov/dotgov-data/main/current-full.csv"
    res = requests.get(url)
    with io.StringIO(res.text) as fd:
        for line in csv.DictReader(fd):
            domain = line["Domain name"]
            outfile.write(f"{domain}\n")


if __name__ == "__main__":
    import sys

    fetch(sys.stdout)
