#!/usr/bin/env python3
"""Capture the S4 fixtures from a test Splunk instance with read-only searches as the service account.

Run from the repository root: python3 matalog/tests/fixtures/s4_capture.py --url https://<host>:8089
Every search is the SPL the profile step issues for the test slot
(tests/support.SLOT) at the default settings: the profile jobs over the
profile window, unsampled, and the week baseline read. Writes s4_*.json next
to this script.
"""
import argparse
import getpass
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "bin"))
sys.path.insert(0, os.path.join(HERE, ".."))

import support  # noqa: E402
from matalog import client as client_mod  # noqa: E402
from matalog import keys  # noqa: E402
from matalog.steps import s4_profile  # noqa: E402

CS = ("matalog_json", "crowdstrike:events:sensor")
SPLUNKD = ("_internal", "splunkd")
TAIL = [r"matalog_t=_time", r"fieldsummary"]

# name -> (index, sourcetype, stratum_field, stratum_value, profile_head_events, match regexes)
PROFILES = {
    "s4_crowdstrike_ProcessRollup2_profile": (CS + ("event_simpleName", "ProcessRollup2", 100000,
        [r'index="matalog_json" sourcetype="crowdstrike:events:sensor" event_simpleName="ProcessRollup2"', r"head 100000 "] + TAIL)),
    "s4_crowdstrike_FileDeleteInfo_profile": (CS + ("event_simpleName", "FileDeleteInfo", 100000,
        [r'index="matalog_json" sourcetype="crowdstrike:events:sensor" event_simpleName="FileDeleteInfo"', r"head 100000 "] + TAIL)),
    "s4_crowdstrike_ProcessRollup2_profile_head": (CS + ("event_simpleName", "ProcessRollup2", 5000,
        [r'index="matalog_json" sourcetype="crowdstrike:events:sensor" event_simpleName="ProcessRollup2"', r"head 5000 "] + TAIL)),
    "s4_crowdstrike_all_profile": (CS + (keys.ALL, keys.ALL, 100000,
        [r'index="matalog_json" sourcetype="crowdstrike:events:sensor" \| head 100000 '] + TAIL)),
    "s4_splunkd_profile": (SPLUNKD + (keys.ALL, keys.ALL, 100000,
        [r'index="_internal" sourcetype="splunkd" \| head 100000 '] + TAIL)),
}
WEEK_MATCH = [r"index=matalog_profiles kind=field mode=profile", r"matalog_d=abs"]


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


def dump(name, spl, match, earliest, latest, result):
    if not result.ok:
        sys.exit("%s failed: %s %s" % (name, result.status, result.messages))
    path = os.path.join(HERE, name + ".json")
    payload = {"spl": spl, "match": match, "earliest": earliest, "latest": latest, "sample_ratio": 1,
               "job": {"sid": result.sid, "scanCount": result.scan_count, "eventCount": result.event_count,
                       "resultCount": result.result_count, "runDuration": result.run_duration},
               "results": result.results}
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=1, ensure_ascii=False, sort_keys=True)
        handle.write("\n")
    print("%s: %d bytes" % (name, os.path.getsize(path)))


def main(argv=None):
    args = parse_args(argv)
    client = client_mod.SplunkClient(args.url, username=args.user, password=svc_password(args), app="matalog", owner=args.user)
    for name, (index, sourcetype, stratum_field, stratum_value, head, match) in PROFILES.items():
        ctx = support.context(**{"profile.profile_head_events": head})
        earliest, latest = ctx.windows["profile"]
        spl = s4_profile.profile_spl(ctx.settings, index, sourcetype, stratum_field, stratum_value)
        dump(name, spl, match, earliest, latest, client.search(spl, earliest=earliest, latest=latest, timeout=300, tag=False))
    ctx = support.context()
    spl = s4_profile.week_spl(ctx, [keys.source_key(*CS), keys.source_key(*SPLUNKD)])
    earliest, latest = s4_profile.week_window(ctx)
    max_rows = ctx.settings.rebuild.rebuild_max_rows
    dump("s4_week_baseline", spl, WEEK_MATCH, earliest, latest, client.search(spl, earliest=earliest, latest=latest, timeout=300, tag=False, max_rows=max_rows))


if __name__ == "__main__":
    main()
