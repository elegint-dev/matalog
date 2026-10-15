"""Test helpers: puts bin/ on the path and builds contexts without Splunk."""
import os
import sys

BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bin")
if BIN not in sys.path:
    sys.path.insert(0, BIN)

from matalog import budget as budget_mod  # noqa: E402
from matalog import runner  # noqa: E402
from matalog import settings as settings_mod  # noqa: E402

import fake_client  # noqa: E402

APP_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SLOT = 1791900000  # 2026-10-13T14:00:00Z, a whole hour


def settings(**overrides):
    return settings_mod.Settings.from_dict(overrides)


def context(client=None, now=SLOT + 10, run_mode="normal", **overrides):
    """A bound RunContext over a fake client and fresh budget."""
    s = settings(**overrides)
    client = client or fake_client.FakeClient(settings=s)
    client.settings = s
    return runner.new_context(s, client, now=now, run_mode=run_mode, profiled_as="svc_matalog")
