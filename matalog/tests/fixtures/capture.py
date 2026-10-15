#!/usr/bin/env python3
"""Capture the test fixtures from a test Splunk instance with read-only searches and config reads.

Run from the repository root: python3 matalog/tests/fixtures/capture.py --url https://<host>:8089
Searches and config reads run as an admin ($SPLUNK_PASSWORD, else a prompt); the knowledge
objects are read as the service account ($MATALOG_SVC_PASSWORD or --password-file, else a
prompt). Writes JSON files next to this script.
"""
import argparse
import getpass
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "bin"))

from matalog import client as client_mod  # noqa: E402

CS = 'search index=matalog_json sourcetype="crowdstrike:events:sensor"'
SPLUNKD = "search index=_internal sourcetype=splunkd"
STRATUM_EVAL = ('eval matalog_sv=case(isnull(event_simpleName), "__missing__", mvcount(event_simpleName)>1, "__multi__", '
                'event_simpleName=="", "__empty__", true(), event_simpleName)')

# name -> (spl, match regexes, earliest, latest, sample_ratio)
SEARCHES = {
    "metadata_matalog_json": ("| metadata type=sourcetypes index=matalog_json", [r"^\| metadata type=sourcetypes index=\"?matalog_json\"?"], None, None, 1),
    "metadata_internal": ("| metadata type=sourcetypes index=_internal", [r"^\| metadata type=sourcetypes index=\"?_internal\"?"], None, None, 1),
    "tstats_counts": ("| tstats count max(_time) as last_time where index=* by index sourcetype", [r"^\| tstats count max\(_time\)"], "0", "now", 1),
    "stratum_list_crowdstrike": ("%s | %s | stats count by matalog_sv | sort -count" % (CS, STRATUM_EVAL), [r"crowdstrike:events:sensor", r"stats count by"], "0", "now", 100),
    "fieldsummary_crowdstrike_ProcessRollup2_discovery": ('%s event_simpleName="ProcessRollup2" | head 2000 | eval matalog_n=1 | fieldsummary maxvals=100' % CS,
                                                          [r"crowdstrike:events:sensor", r'event_simpleName="ProcessRollup2"', r"head 2000", r"fieldsummary"], "0", "now", 1),
    "fieldsummary_crowdstrike_FileDeleteInfo_discovery": ('%s event_simpleName="FileDeleteInfo" | head 2000 | eval matalog_n=1 | fieldsummary maxvals=100' % CS,
                                                          [r"crowdstrike:events:sensor", r'event_simpleName="FileDeleteInfo"', r"head 2000", r"fieldsummary"], "0", "now", 1),
    "fieldsummary_crowdstrike_profile_sampled": ("%s | head 100000 | eval matalog_n=1 | fieldsummary maxvals=100" % CS,
                                                 [r"crowdstrike:events:sensor", r"head 100000", r"fieldsummary"], "0", "now", 100),
    "fieldsummary_splunkd_discovery": ("%s | head 2000 | eval matalog_n=1 | fieldsummary maxvals=100" % SPLUNKD,
                                       [r"sourcetype=\"?splunkd\"?", r"head 2000", r"fieldsummary"], "0", "now", 1),
    "fieldsummary_splunkd_profile_sampled": ("%s | head 100000 | eval matalog_n=1 | fieldsummary maxvals=100" % SPLUNKD,
                                             [r"sourcetype=\"?splunkd\"?", r"head 100000", r"fieldsummary"], "0", "now", 100),
    "licence_usage": ("search index=_internal source=*license_usage.log* type=Usage | stats sum(b) as b by idx st", [r"license_usage\.log", r"stats sum\(b\) as b by idx st"], "0", "now", 1),
    "audit_searches": ("search index=_audit action=search info=completed | head 50 | table _time user app search_id search apiStartTime apiEndTime total_run_time event_count scan_count savedsearch_name provenance",
                       [r"index=_audit", r"action=search"], "0", "now", 1),
}


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", default="https://localhost:8089", help="splunkd management URL (default: %(default)s)")
    parser.add_argument("--admin-user", default="admin", help="admin account for searches and config reads (default: %(default)s)")
    parser.add_argument("--user", default="svc_matalog", help="service account for the knowledge objects (default: %(default)s)")
    parser.add_argument("--password-file", help="file holding the service account password; default: $MATALOG_SVC_PASSWORD, else a prompt")
    return parser.parse_args(argv)


def admin_password(args):
    return os.environ.get("SPLUNK_PASSWORD") or getpass.getpass("%s password: " % args.admin_user)


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
    print("%s: %d bytes" % (name, os.path.getsize(path)))


def main(argv=None):
    args = parse_args(argv)
    client = client_mod.SplunkClient(args.url, username=args.admin_user, password=admin_password(args), app="search", owner=args.admin_user)
    for name, (spl, match, earliest, latest, ratio) in SEARCHES.items():
        result = client.search(spl, earliest=earliest, latest=latest, sample_ratio=ratio, timeout=300, tag=False)
        if not result.ok:
            sys.exit("%s failed: %s %s" % (name, result.status, result.messages))
        dump(name, {
            "spl": spl, "match": match, "earliest": earliest, "latest": latest, "sample_ratio": ratio,
            "job": {"sid": result.sid, "scanCount": result.scan_count, "eventCount": result.event_count,
                    "resultCount": result.result_count, "runDuration": result.run_duration},
            "results": result.results,
        })
    dump("conf_props", client.props())
    dump("conf_transforms", client.transforms())
    dump("conf_fields", client.fields_conf())
    dump("conf_eventtypes", client.eventtypes())
    dump("conf_tags", client.tags())
    dump("datamodels", client.datamodels())
    dump("apps_local", client.apps_local())
    dump("licence_pools", client.licence_pools())
    capture_knowledge_objects(args)


# Knowledge objects as the service account sees them, trimmed to the content S6 reads and to a few apps.
KO_APPS = ("search", "system", "launcher", "matalog", "splunk-rolling-upgrade")
KO_EXTRA_SAVED = ("instrumentation.deployment.node", "instrumentation.performance.indexing", "instrumentation.performance.search",
                  "instrumentation.deployment.forwarders", "instrumentation.usage.versionControl.report", "instrumentation.licenseUsage")
KO_KEEP = {
    "saved_searches": ("search", "is_scheduled", "cron_schedule", "alert_type", "alert_condition", "alert_comparator", "alert_threshold",
                       "actions", "alert.track", "disabled", "dispatch.earliest_time", "description", "realtime_schedule"),
    "views": ("eai:data", "label", "isDashboard", "disabled", "version"),
    "macros": ("definition", "args", "iseval", "disabled"),
    "lookup_definitions": ("filename", "collection", "external_type", "fields_list", "disabled"),
}
KO_FIXTURES = (("saved_searches", "ko_saved_searches"), ("views", "ko_data_ui_views"), ("macros", "ko_data_macros"),
               ("lookup_definitions", "ko_data_transforms_lookups"))
RUNS_LATEST = 1791924900


def capture_knowledge_objects(args):
    from matalog.steps import s6_parse_usage as s6
    svc = client_mod.SplunkClient(args.url, username=args.user, password=svc_password(args), app="matalog")
    for method, name in KO_FIXTURES:
        kept = []
        for entry in getattr(svc, method)():
            app = entry["acl"]["app"]
            extra = (method == "saved_searches" and entry["name"] in KO_EXTRA_SAVED) or (method == "macros" and app == "splunk_instrumentation")
            if app not in KO_APPS and not extra:
                continue
            kept.append({"name": entry["name"], "acl": entry["acl"],
                         "content": dict((k, v) for k, v in entry["content"].items() if k in KO_KEEP[method])})
        dump(name, kept)
    spl = s6.runs_spl()
    earliest = RUNS_LATEST - s6.RUN_HISTORY_DAYS * 86400
    result = svc.search(spl, earliest=earliest, latest=RUNS_LATEST, timeout=300, tag=False)
    if not result.ok:
        sys.exit("s6_object_runs failed: %s %s" % (result.status, result.messages))
    dump("s6_object_runs", {
        "spl": spl, "match": [r"index=_audit", r"matalog_kind"], "earliest": earliest, "latest": RUNS_LATEST, "sample_ratio": 1,
        "job": {"sid": result.sid, "scanCount": result.scan_count, "eventCount": result.event_count,
                "resultCount": result.result_count, "runDuration": result.run_duration},
        "results": result.results,
    })


if __name__ == "__main__":
    main()
