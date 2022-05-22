#!/usr/bin/env python3

import zipfile
import csv
from io import BytesIO, StringIO

import requests
from bs4 import BeautifulSoup

from typing import TextIO

def fetch(outfile: TextIO) -> None:
    res = requests.get('https://www.afnic.fr/en/products-and-services/fr-and-associated-services/shared-data-reuse-fr-data/')
    page = res.text

    parsed = BeautifulSoup(page, features='lxml')

    zip_url = parsed.find_all('h3')[0].find_parent().find_parent().attrs['href']

    res = requests.get(zip_url)
    zip_data = res.content

    with BytesIO(zip_data) as zip_file:
        zip_reader = zipfile.ZipFile(zip_file)
        with StringIO(zip_reader.read(zip_reader.namelist()[0]).decode('iso8859_2')) as s:
            csv_reader = csv.DictReader(s, delimiter=';')
            for domain in (e['Nom de domaine'] for e in csv_reader):
                outfile.write(f'{domain}\n')

if __name__ == '__main__':
    import sys
    fetch(sys.stdout)
