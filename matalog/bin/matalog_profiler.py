#!/usr/bin/env python3
"""matalog profiler: Splunk modular input and command line runner.

Modular input: --scheme prints the scheme, --validate-arguments validates the
stanza, no argument runs one cycle with the session key Splunk passes on stdin.
Command line: --url, --user and --password (or --password-file) run one cycle
against any Splunk; --now pins the slot and --run-mode selects normal or rebuild.
"""
import argparse
import logging
import os
import sys
import time
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from matalog import client as client_mod  # noqa: E402
from matalog import keys  # noqa: E402
from matalog import runner  # noqa: E402
from matalog import settings as settings_mod  # noqa: E402

SCHEME = """<scheme>
  <title>matalog profiler</title>
  <description>Profiles every field Splunk can see and writes the catalog to matalog_profiles and the matalog_* collections.</description>
  <use_external_validation>true</use_external_validation>
  <use_single_instance>true</use_single_instance>
  <streaming_mode>xml</streaming_mode>
  <endpoint>
    <args>
      <arg name="run_mode">
        <title>Run mode</title>
        <description>normal or rebuild</description>
        <required_on_create>false</required_on_create>
      </arg>
    </args>
  </endpoint>
</scheme>
"""


def read_input_xml(stream):
    """Session key, server URI and stanza parameters from the modular input XML."""
    root = ET.fromstring(stream.read())
    out = {"session_key": (root.findtext("session_key") or "").strip(), "server_uri": (root.findtext("server_uri") or "").strip(), "params": {}, "stanzas": []}
    for tag in ("stanza", "item"):
        for item in root.iter(tag):
            out["stanzas"].append(item.get("name") or "")
            for param in item.findall("param"):
                out["params"][param.get("name")] = (param.text or "").strip()
    return out


def validate_arguments(stream):
    try:
        data = read_input_xml(stream)
    except ET.ParseError as exc:
        sys.stderr.write("input configuration is not valid XML: %s\n" % exc)
        return 1
    mode = data["params"].get("run_mode", "normal") or "normal"
    if mode not in ("normal", "rebuild"):
        sys.stderr.write("run_mode must be normal or rebuild\n")
        return 1
    return 0


def slot_committed(client, settings, now):
    """True when the matalog_runs record of the slot containing now says committed=1."""
    run_id = keys.run_id_for(now, settings.budget.cycle_seconds)
    doc = client.kv_get("matalog_runs", run_id)
    if not doc:
        return False
    committed = doc.get("committed")
    if isinstance(committed, str) and committed.lower() in ("true", "false"):
        return committed.lower() == "true"
    try:
        return int(float(committed or 0)) == 1
    except (TypeError, ValueError):
        return False


def run_modular_input(stream, client=None, now=None):
    """One scheduled launch: exits without work when the slot already has a committed run."""
    data = read_input_xml(stream)
    if not data["stanzas"]:
        # Splunk launches a single-instance input at startup even when every stanza is disabled.
        return 0
    if client is None:
        base_url = data["server_uri"] or "https://127.0.0.1:8089"
        client = client_mod.SplunkClient(base_url, session_key=data["session_key"], app=settings_mod.APP)
    client.owner = client.current_user()
    client.username = client.owner
    settings = settings_mod.Settings.from_client(client)
    client.settings = settings
    now = time.time() if now is None else float(now)
    log = logging.getLogger("matalog")
    if slot_committed(client, settings, now):
        log.info("slot %s already has a committed run; nothing to do", keys.run_id_for(now, settings.budget.cycle_seconds))
        return 0
    record = runner.run_once(settings, client, now=now, run_mode=data["params"].get("run_mode") or "normal")
    log.info("run %s attempt %s status %s", record.get("run_id"), record.get("attempt"), record.get("status"))
    return 0 if record.get("status") in ("ok", "partial") else 1


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scheme", action="store_true")
    parser.add_argument("--validate-arguments", action="store_true")
    parser.add_argument("--url", default=os.environ.get("MATALOG_URL", ""))
    parser.add_argument("--user", default=os.environ.get("MATALOG_USER", ""))
    parser.add_argument("--password", default=os.environ.get("MATALOG_PASSWORD", ""))
    parser.add_argument("--password-file", default="")
    parser.add_argument("--now", type=float, default=None, help="epoch seconds that pin the slot; default is the wall clock")
    parser.add_argument("--run-mode", choices=("normal", "rebuild"), default="normal")
    parser.add_argument("--conf", default="", help="matalog.conf to read instead of the configs endpoint")
    parser.add_argument("--set", action="append", default=[], metavar="STANZA.SETTING=VALUE", help="override one setting")
    parser.add_argument("--log-level", default="INFO")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    # splunkd records a modular input's stderr in splunkd.log at the level that opens each line (DEBUG, INFO, WARN,
    # ERROR), as ERROR when the line opens with anything else, and adds its own timestamp.
    if args.url:
        fmt = "%(asctime)s %(levelname)s %(name)s %(message)s"
    else:
        fmt = "%(levelname)s %(name)s %(message)s"
        logging.addLevelName(logging.WARNING, "WARN")
    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO), format=fmt, stream=sys.stderr)
    if args.scheme:
        sys.stdout.write(SCHEME)
        return 0
    if args.validate_arguments:
        return validate_arguments(sys.stdin)
    if not args.url:
        return run_modular_input(sys.stdin)
    password = args.password
    if args.password_file:
        with open(args.password_file, "r", encoding="utf-8") as handle:
            password = handle.read().strip()
    client = client_mod.SplunkClient(args.url, username=args.user, password=password, app=settings_mod.APP)
    if args.conf:
        settings = settings_mod.Settings.from_conf_file(args.conf)
    else:
        settings = settings_mod.Settings.from_client(client)
    overrides = {}
    for item in args.set:
        name, _, value = item.partition("=")
        overrides[name] = value
    if overrides:
        settings = settings.with_overrides(overrides)
    client.settings = settings
    logging.getLogger("matalog").info("settings from %s, %d stratum seeds", settings.source, len(settings.stratum_seeds))
    record = runner.run_once(settings, client, now=args.now, run_mode=args.run_mode)
    sys.stdout.write("run_id=%s attempt=%s status=%s searches=%s errors=%s\n" % (
        record.get("run_id"), record.get("attempt"), record.get("status"), record.get("searches_issued"), len(record.get("errors") or [])))
    return 0 if record.get("status") in ("ok", "partial") else 1


if __name__ == "__main__":
    sys.exit(main())
