#!/usr/bin/env python3

from curses import beep
import sys
import hashlib
from pathlib import Path
import subprocess


# get the version
cargofile = Path("kanidm_tools/Cargo.toml")

version = None
if not cargofile.exists():
    print(f"Can't find {cargofile}, bailing.")
    sys.exit(1)
for line in cargofile.read_text().splitlines():
    if line.startswith("version"):
        version = line.replace("\"", "").split("=")[-1].strip()
        break
if version is None:
    print("Failed to find version in Cargo file, bailing.")
    sys.exit(1)

print(f"Found version: {version}")

print("Getting git head")
try:
    githead = subprocess.check_output(["git", "rev-parse", "HEAD"]).decode("utf-8")[:7]
except subprocess.CalledProcessError as spc_error:
    print(f"Failed to run 'git rev-parse HEAD': {spc_error}")
    sys.exit(1)

print(githead)
from datetime import datetime

secs = int(datetime.now().timestamp())
kanidm_version = f"kanidm-{version}-{githead}-{secs}"
print(f"{kanidm_version=}")

# first find the source files

# make a list of hashes

def hash_files():
    source_files = [
        # f"{kanidm_version}.tar.gz"
        "kanidm-1.1.0-alpha.8-202207110454-8683d45.tar.gz",
    ]

    checksums_sha1 = {}
    checksums_sha256 = {}
    files = {}

    for filename in source_files:
        source_file = Path(f"/build/{filename}")
        if not source_file.exists():
            print(f"Failed to find {source_file}, bailing")
            sys.exit(1)

        file_contents = source_file.read_bytes()
        file_size = source_file.stat().st_size
        md5 = hashlib.md5()
        md5.update(file_contents)
        sha1 = hashlib.sha1()
        sha1.update(file_contents)
        sha256 = hashlib.sha256()
        sha256.update(file_contents)
        checksums_sha1[filename] = {
            "size": file_size,
            "hash" : sha1.hexdigest()
        }
        checksums_sha256[filename] = {
            "size": file_size,
            "hash" : sha256.hexdigest()
        }
        files[filename] = {
            "size" : file_size,
            "hash" : md5.hexdigest()
        }

    sha1_list = "\n".join([ f"{data['hash']} {data['size']} {filename}"
        for filename, data in checksums_sha1.items()
        ])

    sha256_list = "\n".join([ f"{data['hash']} {data['size']} {filename}"
        for filename, data in checksums_sha256.items()
        ])

    files_list = "\n".join([ f"{data['hash']} {data['size']} {filename}"
        for filename, data in files.items()
        ])
    return (files_list, sha1_list, sha256_list)

package_name = "kanidm"
maintainer = "James Hodgkinson <james@terminaloutcomes.com>"
build_depends = ",".join(["libpam0g-dev", "libudev-dev", "libssl-dev", "libsqlite3-dev", "pkg-config", "cargo", "make"])

files_list, sha1_list, sha256_list = hash_files()


print("Showing DSC File:")
print("#"*50)
dsc_template = f"""Format: 3.0 (quilt)
Source: {package_name}
Binary {package_name}
Architecture: any
Version: {version}
Maintainer: {maintainer}
Homepage: https://github.com/kanidm/kanidm
Standards-Version: 3.8.4
Build-Depends: {build_depends}
Checksums-Sha1:
{sha1_list}
Checksums-Sha256:
{sha256_list}
Files:
{files_list}
"""
print(dsc_template)