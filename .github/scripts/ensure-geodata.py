#!/usr/bin/env python3
"""Install immutable, checksum-verified test fixtures, independent of CI caches."""

import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import urllib.request


def ensure_asset(directory, asset, revision):
    target = directory / asset["name"]
    expected = asset["sha256"]
    if target.is_file() and hashlib.sha256(target.read_bytes()).hexdigest() == expected:
        return

    url = f"https://raw.githubusercontent.com/XTLS/Xray-rules-dat/{revision}/{asset['path']}"
    digest = hashlib.sha256()
    started = time.monotonic()
    size = 0
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=directory, delete=False) as output:
            temporary = Path(output.name)
            with urllib.request.urlopen(url, timeout=30) as response:
                while chunk := response.read(1024 * 1024):
                    size += len(chunk)
                    if size > 128 * 1024 * 1024 or time.monotonic() - started > 180:
                        raise ValueError("test fixture exceeded download bounds")
                    digest.update(chunk)
                    output.write(chunk)
        if digest.hexdigest() != expected:
            raise ValueError(f"checksum mismatch for {asset['name']}")
        os.replace(temporary, target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main():
    manifest = json.loads(Path(__file__).with_name("test-geodata.json").read_text())
    directory = Path("resources")
    directory.mkdir(exist_ok=True)
    for asset in manifest["assets"]:
        ensure_asset(directory, asset, manifest["revision"])
        print(f"Verified test fixture {asset['name']} ({asset['sha256']})")


if __name__ == "__main__":
    main()
