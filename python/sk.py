#!/usr/bin/env python3

import requests
import csv
from io import StringIO

from typing import TextIO


def fetch(outfile: TextIO) -> None:
    url = "https://sk-nic.sk/subory/domains.txt"
    res = requests.get(url, headers={"user-agent": "foobar"})
    fixed = "\n".join(
        line for line in res.text.splitlines() if line and not line.startswith("--")
    )
    with StringIO(fixed) as s:
        for e in csv.DictReader(s, delimiter=";"):
            domain = e["domena"]
            outfile.write(f"{domain}\n")


if __name__ == "__main__":
    import sys

    fetch(sys.stdout)
