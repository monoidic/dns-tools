#!/usr/bin/env python3

import requests
import time
from typing import Iterable, Any, TextIO


def get_domains() -> Iterable[dict[str, Any]]:
    url = "https://odata.domain.fi/OpenDomainData.svc/"
    link = "Domains?$inlinecount=allpages"
    nextlink = "odata.nextLink"
    headers = {"Accept": "application/json"}
    with requests.Session() as s:
        while True:
            res = s.get(f"{url}/{link}", headers=headers)
            data = res.json()

            yield from data["value"]

            if not nextlink in data:
                break

            link = data[nextlink]
            time.sleep(1)


def fetch(outfile: TextIO) -> None:
    for entry in get_domains():
        domain = entry["Name"].encode("idna").decode()
        outfile.write(f"{domain.lower()}.fi\n")


if __name__ == "__main__":
    import sys

    fetch(sys.stdout)
