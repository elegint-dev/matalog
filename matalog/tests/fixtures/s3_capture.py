#!/usr/bin/env python3
"""Capture the S3 fixtures from a test Splunk instance with read-only searches as the service account.

Run from the repository root: python3 matalog/tests/fixtures/s3_capture.py --url https://<host>:8089
Every search is the discovery SPL the step issues, over the discovery window
of the test slot (tests/support.SLOT), unsampled, so the fixtures carry the
figures a test run would see. Writes s3_*.json next to this script.
"""
import argparse
import getpass
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "bin"))

from matalog import client as client_mod  # noqa: E402
from matalog import keys  # noqa: E402
from matalog import settings as settings_mod  # noqa: E402
from matalog.steps import s3_discover  # noqa: E402

SLOT = 1791900000

# name -> (src_index, search_sourcetype, stratum_field, stratum_value, match regexes)
STRATA = {
    "s3_fieldsummary_crowdstrike_ProcessHandleOpDetectInfo": (
        "matalog_json", "crowdstrike:events:sensor", "event_simpleName", "ProcessHandleOpDetectInfo",
        [r"crowdstrike:events:sensor", r'event_simpleName="ProcessHandleOpDetectInfo"', r"head 2000", r"fieldsummary"]),
    "s3_fieldsummary_crowdstrike_DmpFileWritten": (
        "matalog_json", "crowdstrike:events:sensor", "event_simpleName", "DmpFileWritten",
        [r"crowdstrike:events:sensor", r'event_simpleName="DmpFileWritten"', r"head 2000", r"fieldsummary"]),
    "s3_fieldsummary_crowdstrike_missing": (
        "matalog_json", "crowdstrike:events:sensor", "event_simpleName", keys.MISSING,
        [r"crowdstrike:events:sensor", r"NOT event_simpleName=\*", r"head 2000", r"fieldsummary"]),
    "s3_fieldsummary_cloudtrail_ConsoleLogin": (
        "matalog_json", "aws:cloudtrail", "eventName", "ConsoleLogin",
        [r"aws:cloudtrail", r'eventName="ConsoleLogin"', r"head 2000", r"fieldsummary"]),
    "s3_fieldsummary_splunkd_all": (
        "_internal", "splunkd", keys.ALL, keys.ALL,
        [r'index="?_internal"? sourcetype="?splunkd"? \| head 2000', r"fieldsummary"]),
}


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", default="https://localhost:8089", help="splunkd management URL (default: %(default)s)")
    parser.add_argument("--user", default="svc_matalog", help="service account (default: %(default)s)")
    parser.add_argument("--password-file", help="file holding the service account password; default: $MATALOG_SVC_PASSWORD, else a prompt")
    return parser.parse_args(argv)


def svc_password(args):
    if args.password_file:
        with open(args.password_file, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    return os.environ.get("MATALOG_SVC_PASSWORD") or getpass.getpass("%s password: " % args.user)


def dump(name, payload):
    path = os.path.join(HERE, name + ".json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=1, ensure_ascii=False, sort_keys=True)
        handle.write("\n")
    print("%s: %d bytes, %d rows" % (name, os.path.getsize(path), len(payload["results"])))


def main(argv=None):
    args = parse_args(argv)
    settings = settings_mod.Settings.defaults()
    earliest, latest = keys.windows(settings, SLOT)["discovery"]
    client = client_mod.SplunkClient(args.url, username=args.user, password=svc_password(args), app="matalog")
    for name, (index, sourcetype, field, value, match) in STRATA.items():
        spl = s3_discover.discovery_spl(settings, index, sourcetype, field, value)
        result = client.search(spl, earliest=earliest, latest=latest, sample_ratio=1, timeout=300, tag=False)
        if not result.ok:
            sys.exit("%s failed: %s %s" % (name, result.status, result.messages))
        dump(name, {
            "spl": spl, "match": match, "earliest": earliest, "latest": latest, "sample_ratio": 1,
            "job": {"sid": result.sid, "scanCount": result.scan_count, "eventCount": result.event_count,
                    "resultCount": result.result_count, "runDuration": result.run_duration},
            "results": result.results,
        })


if __name__ == "__main__":
    main()
