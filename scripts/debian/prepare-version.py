#!/usr/bin/python3
"""Derive the Debian upstream version, preserving revision and release history."""
from datetime import datetime, timezone
from email.utils import format_datetime
from pathlib import Path
import os
import re
import subprocess
import sys

if sys.argv[1:] not in ([], ["--check"]):
    sys.exit("Usage: python3 debian/prepare-version.py [--check]")

root = Path(__file__).resolve().parents[1]
version = subprocess.check_output(
    ["sh", str(root / "scripts/kae-version.sh")], text=True
).strip()
changelog = root / "debian/changelog"
text = changelog.read_text()
entry = re.match(r"kae \((?P<version>[^)]+)\) (?P<distribution>\S+); urgency=(?P<urgency>\S+)", text)
if entry is None:
    sys.exit("Cannot parse the first KAE Debian changelog entry")
old_version = entry["version"]
epoch, sep, remainder = old_version.partition(":")
epoch, upstream = (epoch + sep, remainder) if sep else ("", old_version)
upstream, sep, revision = upstream.rpartition("-")
if not sep:
    sys.exit("KAE Debian packages require a Debian revision")
new_version = f"{epoch}{version}-{revision}"
if old_version == new_version:
    sys.exit(0)
if sys.argv[1:] == ["--check"]:
    sys.exit("Debian changelog differs from VERSION; run bash build.sh debpack first")
maintainer = re.search(r"^ -- (.+?)  .+$", text, re.MULTILINE)
if maintainer is None:
    sys.exit("Cannot find the Debian changelog maintainer")
timestamp = os.environ.get("SOURCE_DATE_EPOCH")
date = datetime.fromtimestamp(int(timestamp), timezone.utc) if timestamp else datetime.now(timezone.utc)
changelog.write_text(
    f"kae ({new_version}) {entry['distribution']}; urgency={entry['urgency']}\n\n"
    f"  * Build KAE {version} from the root VERSION file.\n\n"
    f" -- {maintainer[1]}  {format_datetime(date)}\n\n" + text
)
