"""matalog.conf settings: typed access, defaults, budget json and config_hash.

The DEFAULTS table is docs/budget-settings.md; default/matalog.conf is tested
against it.
"""
import collections
import json
import logging


from . import keys

# stanza -> setting -> (type, default). Order is the order of the contract table.
DEFAULTS = collections.OrderedDict([
    ("budget", collections.OrderedDict([
        ("cycle_seconds", (int, 3600)),
        ("max_searches_per_cycle", (int, 1500)),
        ("max_concurrent_searches", (int, 4)),
        ("max_events_scanned_per_cycle", (int, 100000000)),
        ("max_search_seconds_per_cycle", (int, 7200)),
        ("max_wall_seconds_per_cycle", (int, 2700)),
        ("search_timeout_seconds", (int, 120)),
        ("max_staleness_cycles", (int, 24)),
        ("priority_usage_weight", (float, 1.0)),
        ("window_lag_seconds", (int, 300)),
        ("index_scan_interval_seconds", (int, 86400)),
    ])),
    ("discovery", collections.OrderedDict([
        ("discovery_window_seconds", (int, 900)),
        ("discovery_head_events", (int, 2000)),
        ("max_strata_per_source", (int, 300)),
        ("stratum_list_window_seconds", (int, 86400)),
        ("stratum_list_sample_ratio", (int, 100)),
        ("stratum_list_interval_seconds", (int, 86400)),
        ("max_fields_per_stratum", (int, 500)),
        ("min_events_for_absence", (int, 200)),
    ])),
    ("profile", collections.OrderedDict([
        ("profile_interval_seconds", (int, 86400)),
        ("profile_window_seconds", (int, 86400)),
        ("sample_volume_threshold", (int, 1000000)),
        ("sample_ratio", (int, 100)),
        ("profile_head_events", (int, 100000)),
        ("top_values", (int, 10)),
        ("sample_values", (int, 100)),
        ("sample_values_max_bytes", (int, 6144)),
        ("max_value_chars", (int, 128)),
        ("max_row_bytes", (int, 8192)),
        ("identifier_distinct", (int, 1000)),
        ("identifier_distinct_ratio", (float, 0.9)),
        ("identifier_min_count", (int, 50)),
        ("identifier_distinct_cap_min", (int, 500)),
        ("week_baseline_days", (int, 7)),
        ("store_sample_values", (bool, True)),
    ])),
    ("classify", collections.OrderedDict([
        ("edge_store_floor", (float, 0.5)),
        ("max_types_per_field", (int, 3)),
        ("default_match_threshold", (float, 0.9)),
        ("default_min_distinct", (int, 2)),
        ("max_lookup_values", (int, 10000)),
    ])),
    ("usage", collections.OrderedDict([
        ("usage_interval_seconds", (int, 86400)),
        ("audit_initial_lookback_days", (int, 30)),
        ("max_objects", (int, 20000)),
        ("usage_objects_shown", (int, 10)),
        ("service_account", (str, "svc_matalog")),
        ("exclude_users", (str, "svc_matalog,splunk-system-user")),
        ("exclude_apps", (str, "matalog")),
    ])),
    ("write", collections.OrderedDict([
        ("write_batch_rows", (int, 4000)),
        ("write_batch_bytes", (int, 1048576)),
        ("write_reserve_min", (int, 10)),
        ("kv_batch_size", (int, 500)),
    ])),
    ("rebuild", collections.OrderedDict([
        ("rebuild_max_rows", (int, 5000000)),
    ])),
    ("retention", collections.OrderedDict([
        ("profiles_frozen_days", (int, 180)),
        ("run_retention_count", (int, 2000)),
        ("unobserved_field_days", (int, 30)),
        ("stratum_retire_days", (int, 30)),
        ("meaning_revisions", (int, 20)),
        ("object_stale_runs", (int, 3)),
        ("cim_stale_runs", (int, 3)),
        ("gone_after_days", (int, 30)),
    ])),
])

STRATUM_STANZA_PREFIX = "stratum:"
STRATUM_SEED_KEYS = ("stratum_field", "version_field", "index_pattern")

APP = "matalog"
CONF_NAME = "matalog"
PROFILES_INDEX = "matalog_profiles"


class SettingError(ValueError):
    """An unknown setting name or a value that does not parse."""


def setting_names():
    """Every stanza.setting name in contract order."""
    return ["%s.%s" % (stanza, name) for stanza, table in DEFAULTS.items() for name in table]


def coerce(stanza, name, value):
    """Parse a raw conf value into the setting's type."""
    try:
        typ = DEFAULTS[stanza][name][0]
    except KeyError:
        raise SettingError("unknown setting %s.%s" % (stanza, name))
    if typ is str:
        return "" if value is None else str(value)
    if value is None or value == "":
        return DEFAULTS[stanza][name][1]
    if typ is bool:
        return parse_bool(stanza, name, value)
    try:
        if typ is int:
            return int(float(value)) if isinstance(value, str) else int(value)
        return float(value)
    except (TypeError, ValueError):
        raise SettingError("%s.%s: %r is not %s" % (stanza, name, value, typ.__name__))


BOOL_TEXT = {"true": True, "false": False, "1": True, "0": False, "yes": True, "no": False, "t": True, "f": False}


def parse_bool(stanza, name, value):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    try:
        return BOOL_TEXT[str(value).strip().lower()]
    except KeyError:
        raise SettingError("%s.%s: %r is not bool" % (stanza, name, value))


def parse_conf(text):
    """Parse conf text into stanza -> OrderedDict(key -> value). Comments and blanks are skipped."""
    stanzas = collections.OrderedDict()
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            stanzas.setdefault(current, collections.OrderedDict())
            continue
        if current is None or "=" not in line:
            continue
        key, _, value = line.partition("=")
        stanzas[current][key.strip()] = value.strip()
    return stanzas


class Stanza(object):
    """Attribute access to one stanza: settings.budget.cycle_seconds."""

    def __init__(self, name, values):
        self._name = name
        self._values = values

    def __getattr__(self, item):
        values = self.__dict__.get("_values", {})
        if item in values:
            return values[item]
        raise AttributeError("no setting %s.%s" % (self.__dict__.get("_name"), item))

    def __getitem__(self, item):
        return self._values[item]

    def items(self):
        return list(self._values.items())


class Settings(object):
    """Typed settings with stanza.setting access and the seed stratum stanzas.

    Build with Settings.defaults(), Settings.from_conf_text(), Settings.from_client()
    or Settings.from_dict({"budget.cycle_seconds": 60}).
    """

    def __init__(self, values=None, stratum_seeds=None, source="defaults"):
        self._values = collections.OrderedDict()
        for stanza, table in DEFAULTS.items():
            self._values[stanza] = collections.OrderedDict((name, spec[1]) for name, spec in table.items())
        for full_name, value in (values or {}).items():
            self._set(full_name, value)
        self.stratum_seeds = list(stratum_seeds or [])
        self.source = source

    def _set(self, full_name, value):
        stanza, _, name = full_name.partition(".")
        if stanza not in DEFAULTS or name not in DEFAULTS[stanza]:
            raise SettingError("unknown setting %s" % full_name)
        self._values[stanza][name] = coerce(stanza, name, value)

    @classmethod
    def defaults(cls):
        return cls()

    @classmethod
    def from_dict(cls, overrides, stratum_seeds=None):
        return cls(overrides, stratum_seeds=stratum_seeds, source="dict")

    @classmethod
    def from_stanzas(cls, stanzas, source="conf"):
        """Overlay parsed stanzas (stanza -> key -> raw value) on the defaults."""
        values = collections.OrderedDict()
        seeds = []
        for stanza, table in stanzas.items():
            if stanza.startswith(STRATUM_STANZA_PREFIX):
                seeds.append(stratum_seed(stanza[len(STRATUM_STANZA_PREFIX):], table))
                continue
            if stanza not in DEFAULTS:
                continue
            for name, raw in table.items():
                if name in DEFAULTS[stanza]:
                    values["%s.%s" % (stanza, name)] = raw
        return cls(values, stratum_seeds=seeds, source=source)

    @classmethod
    def from_conf_text(cls, text):
        return cls.from_stanzas(parse_conf(text), source="conf_text")

    @classmethod
    def from_conf_file(cls, path):
        with open(path, "r", encoding="utf-8") as handle:
            return cls.from_stanzas(parse_conf(handle.read()), source=path)

    @classmethod
    def from_client(cls, client, fallback=None):
        """Read configs/conf-matalog through the client; defaults where it fails or is silent."""
        try:
            entries = client.conf_entries(CONF_NAME, app=APP, owner="nobody")
        except Exception as exc:
            logging.getLogger("matalog").warning("matalog.conf unreadable, using defaults without seeds: %s", exc)
            return fallback if fallback is not None else cls.defaults()
        stanzas = collections.OrderedDict()
        for entry in entries:
            content = entry.get("content", {})
            stanzas[entry["name"]] = collections.OrderedDict(
                (key, value) for key, value in content.items() if not key.startswith("eai:") and key != "disabled")
        return cls.from_stanzas(stanzas, source="configs/conf-matalog")

    def with_overrides(self, overrides):
        merged = collections.OrderedDict(self.flat())
        merged.update(overrides or {})
        return Settings(merged, stratum_seeds=self.stratum_seeds, source=self.source)

    def __getattr__(self, item):
        values = self.__dict__.get("_values", {})
        if item in values:
            return Stanza(item, values[item])
        raise AttributeError("no stanza %s" % item)

    def get(self, full_name):
        stanza, _, name = full_name.partition(".")
        try:
            return self._values[stanza][name]
        except KeyError:
            raise SettingError("unknown setting %s" % full_name)

    def __getitem__(self, full_name):
        return self.get(full_name)

    def flat(self):
        """OrderedDict of stanza.setting -> value in contract order."""
        out = collections.OrderedDict()
        for stanza, table in self._values.items():
            for name, value in table.items():
                out["%s.%s" % (stanza, name)] = value
        return out

    def budget_json(self):
        """Every setting as used by this run, for matalog_runs.budget: {stanza: {setting: value}}.

        Nested by stanza because KV store document keys may not contain a dot.
        """
        return collections.OrderedDict((stanza, collections.OrderedDict(table)) for stanza, table in self._values.items())

    def config_hash(self, stratum_rows=(), declaration_keys=()):
        """First 32 hex of SHA-256 over budget json, the stratum config rows and the declaration keys in force."""
        payload = {
            "budget": self.flat(),
            "stratum_config": [stratum_row_for_hash(r) for r in sorted(stratum_rows, key=lambda r: str(r.get("_key", "")))],
            "declarations": sorted(str(d) for d in declaration_keys),
        }
        return keys.sha32(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False))

    def exclude_users(self):
        return [u.strip() for u in self.usage.exclude_users.split(",") if u.strip()]

    def exclude_apps(self):
        return [a.strip() for a in self.usage.exclude_apps.split(",") if a.strip()]


def stratum_row_for_hash(row):
    return dict((key, row.get(key)) for key in ("_key", "index_pattern", "src_sourcetype", "stratum_field", "version_field", "enabled", "origin"))


def stratum_seed(src_sourcetype, table):
    """One [stratum:<sourcetype>] stanza as a seed dict."""
    return collections.OrderedDict([
        ("src_sourcetype", src_sourcetype),
        ("stratum_field", str(table.get("stratum_field", "")).strip()),
        ("version_field", str(table.get("version_field", "")).strip()),
        ("index_pattern", str(table.get("index_pattern", "*")).strip() or "*"),
    ])


