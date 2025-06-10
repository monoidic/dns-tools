#!/usr/bin/env python3

import requests
import traceback
import json
import os
import datetime
import subprocess

import fr, nc, sk, cw, fi, gov, tld

from functools import partial
from typing import Dict, Any, Callable


def is_outdated(filename: str, fresh_limit: float) -> bool:
    try:
        last_updated = os.stat(filename).st_mtime
    except FileNotFoundError:  # doesn't exist yet
        return True

    now = datetime.datetime.now().timestamp()
    return (now - last_updated) >= (fresh_limit * 86400)


def fetch_axfr(conf: Dict[str, Any], full_conf: Dict[str, Any], **kwargs) -> None:
    for zone_data in conf:
        zone = zone_data["zone"]
        filename = f"zones/{zone}zone"
        if not is_outdated(filename, full_conf["outdated"]):
            print(f"skipping {zone}")
            continue

        ns = zone_data["nameserver"]
        tsig_args = []
        if zone_data["tsig"]:
            tsig_args = ["-k", f"tsig/{zone}tsig"]

        zone_args = [
            "dig",
            *tsig_args,
            f"@{ns}",
            "+noall",
            "+answer",
            "+noidnout",
            "+onesoa",
            "-t",
            "AXFR",
            zone,
        ]

        print(f"fetching {zone}")

        for i in range(3):
            with subprocess.Popen(zone_args, stdout=subprocess.PIPE) as proc:
                zone_data, _ = proc.communicate()
                if not proc.returncode:
                    break
                print(f"retry {i+1}")
        else:
            print(f"failed to fetch {zone}")
            continue

        with open(filename, "wb") as fd:
            fd.write(zone_data)


def get_fetch(conf: Dict[str, Any]) -> Callable[[str], Any]:
    account_baseurl = conf["account_baseurl"]
    auth_res = requests.post(
        f"{account_baseurl}/api/authenticate", json=conf["credentials"]
    )
    auth_token = auth_res.json()["accessToken"]

    headers = {
        "Authorization": f"Bearer {auth_token}",
    }

    return partial(requests.get, headers=headers)


def fetch_czds(conf: Dict[str, Any], full_conf: Dict[str, Any], **kwargs) -> None:
    fetch = get_fetch(conf)
    api_baseurl = conf["api_baseurl"]

    links_res = fetch(f"{api_baseurl}/czds/downloads/links")
    links = links_res.json()
    assert isinstance(links, list)

    for link in links:
        basename = link.rsplit("/", 1)[1]
        filename = f"zones/{basename}"
        if not is_outdated(filename, full_conf["outdated"]):
            print(f"skipping {basename}")
            continue
        print(f"fetching {basename}")
        try:
            with fetch(link, stream=True) as res, open(f"{filename}.gz", "wb") as fd:
                res.raise_for_status()
                for chunk in res.iter_content(chunk_size=8192):
                    fd.write(chunk)

            with subprocess.Popen(["gunzip", "-f", f"{filename}.gz"]) as proc:
                status = proc.wait()
                if status:
                    raise ValueError(f"failed to decompress {filename}.gz")
        except Exception as e:
            traceback.print_exc()


expiry_map = {
    "monthly": 30,
    "daily": 1,
}


def fetch_lists(conf: Dict[str, Any], full_conf: Dict[str, Any], **kwargs) -> None:
    print("fetching lists")
    for module, expiry in [
        (fr, "monthly"),
        (nc, "daily"),
        (sk, "daily"),
        (gov, "daily"),
        (tld, "daily"),
        (fi, "daily"),
        (cw, "daily"),
    ]:
        name = module.__name__
        filename = f"lists/{name}.txt"
        placeholder = f"{filename}.tmp"
        if not is_outdated(filename, expiry_map[expiry]):
            print(f"skipping {name}")
            continue

        print(f"fetching {name}")
        with open(placeholder, "w") as fd:
            try:
                module.fetch(fd)
            except Exception:
                traceback.print_exc()
            else:
                os.rename(placeholder, filename)


def main() -> None:
    with open("conf.json") as fd:
        conf = json.load(fd)

    # seed the search
    for f, conf_key in [
        (fetch_axfr, "axfr"),
        (fetch_czds, "czds"),
        (fetch_lists, None),
    ]:
        try:
            conf_section = conf if conf_key is None else conf[conf_key]
            f(conf_section, full_conf=conf)
        except Exception as e:
            print(f"failed to run {f}")
            traceback.print_exc()


if __name__ == "__main__":
    main()
