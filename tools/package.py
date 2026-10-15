#!/usr/bin/env python3
"""Build the matalog app package for Splunk Cloud.

Writes matalog-<version>.tar.gz with the app directory as the top level and
prints its path. The version comes from default/app.conf [launcher]. Left out:
local/, tests/, ui/ (the built bundles under appserver/static ship, the React
source does not), __pycache__, .pyc and .DS_Store.

    python3 tools/package.py
    python3 tools/package.py --out /tmp/dist
"""
import argparse
import configparser
import os
import sys
import tarfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = "matalog"
APP_DIR = os.path.join(ROOT, APP)
EXCLUDED_DIRS = ("local", "tests", "ui")
EXCLUDED_NAMES = ("__pycache__", ".DS_Store")
EXCLUDED_SUFFIXES = (".pyc", ".pyo")


def app_version(app_dir):
    conf = configparser.RawConfigParser(strict=False)
    conf.read(os.path.join(app_dir, "default", "app.conf"))
    return conf.get("launcher", "version")


def excluded(relative):
    parts = relative.split("/")
    if len(parts) > 1 and parts[1] in EXCLUDED_DIRS:
        return True
    name = parts[-1]
    return name in EXCLUDED_NAMES or name.endswith(EXCLUDED_SUFFIXES)


def member_filter(info):
    if excluded(info.name):
        return None
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mode = 0o755 if info.isdir() or info.mode & 0o100 else 0o644
    return info


def build(app_dir, out_dir):
    version = app_version(app_dir)
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "%s-%s.tar.gz" % (APP, version))
    with tarfile.open(path, "w:gz") as tar:
        tar.add(app_dir, arcname=APP, filter=member_filter)
    return path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default=os.path.join(ROOT, "dist"), help="directory for the package (default: dist/)")
    args = parser.parse_args(argv)
    if not os.path.isdir(os.path.join(APP_DIR, "default")):
        sys.exit("no app at %s" % APP_DIR)
    print(build(APP_DIR, args.out))


if __name__ == "__main__":
    main()
