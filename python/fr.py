#!/usr/bin/env python3

import zipfile
import csv
from io import BytesIO, StringIO

import requests
from bs4 import BeautifulSoup

from typing import TextIO


def fetch(outfile: TextIO) -> None:
    url = "https://www.afnic.fr/en/products-and-services/fr-and-associated-services/shared-data-reuse-fr-data/"
    res = requests.get(url)
    parsed = BeautifulSoup(res.text, features="lxml")
    zip_url = parsed.select(".DocumentsOpenData a[href]")[0].attrs["href"]
    res = requests.get(zip_url)
    zip_data = res.content

    with BytesIO(zip_data) as zip_file:
        zip_reader = zipfile.ZipFile(zip_file)
        filename = zip_reader.namelist()[0]
        data = zip_reader.read(filename).decode()
        with StringIO(data) as s:
            for line in csv.DictReader(s, delimiter=";"):
                domain = line["Nom de domaine"].encode("idna").decode()
                outfile.write(f"{domain}\n")


if __name__ == "__main__":
    import sys

    fetch(sys.stdout)
