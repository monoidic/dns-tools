#!/usr/bin/env python3

from typing import TextIO

import publicsuffix2

def fetch(outfile: TextIO) -> None:
    data = publicsuffix2.fetch().read()
    with open(publicsuffix2.PSL_FILE, 'w') as fd:
        fd.write(data)

    publicsuffix2.get_tld('abc.co.uk')
    for tld in sorted(tld.encode('idna').decode() for tld in publicsuffix2._PSL.tlds):
        outfile.write(f'{tld}\n')

if __name__ == '__main__':
    import sys
    fetch(sys.stdout)
