#!/usr/bin/env python3
"""GET /services/matalog/summary: the catalog's per-source and per-field summary in compact JSON.

Query parameters, one of:
    source=<index>:<sourcetype>   the source row and every source-level field of that source
    field=<name>                  one card per source carrying that field name, the other name matches
                                  and the data model fields of that name
    type=<name>                   one card per source-level field whose best semantic type has that bare name and
                                  whose match rate reaches the type's match_threshold, best rate first
    q=<word>                      sources whose sourcetype, search name, source paths or config apps contain the
                                  word (srcs), then field name matches
plus limit=<n> (default 200, at most 2000) on the field, card, source and match lists and defaults=1 to list Splunk
default fields. Top values are capped at 10. Field entries carry abs and absn (the strata of a stratified source
without the field in its last profile, and their count) and dflt (1 on a Splunk default, internal or date_* field).
Default fields are left out of fields, cards of type=, other and matches unless defaults=1 (defaults_hidden counts
them); the cards of an exact field= request are always listed. Matches rank exact name first, then prefix, then
substring, then by usage and coverage.

Every count carries the window it was measured in: ws and we (epoch bounds) next to run and ev on a field entry, a
match, a stratum entry and a source (its trailing day), computed from the run record's budget as the pages compute
them; a discovery snapshot takes the searched stratum row's own window (cur_earliest, cur_latest) when the row
still carries that run, which is where an anchored first discovery (window_anchor=last_event) differs from the
slot window. no_events is 1 when ev is 0 and anchor names the anchor. Every response carries window, the day,
profile, discovery and cycle windows of the newest committed run with the events the readable catalog saw in the
day, so an empty answer still says what was looked at, and note, what the request named that was ignored or not
found. The run records and the stratum rows are read once per response.

The collections are read with the system session after the capability check and narrowed to the indexes the
caller's roles can search (matalog_access.py); the keys are documented in docs/data-model.md, "Agent surface".
The value helpers here also serve matalog_meanings.py.
"""
import datetime
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from matalog_access import IN_CHUNK, KvStore, RequestError, ScopedReader, caller_from_request, chunks, request_params, text  # noqa: E402

try:
    from splunk.persistconn.application import PersistentServerConnectionApplication
except ImportError:
    PersistentServerConnectionApplication = object

DEFAULT_LIMIT = 200
MAX_LIMIT = 2000
TOP_CAP = 10
SAMPLE_CAP = 5
OBJECTS_CAP = 5
DAY_SECONDS = 86400
RUN_ID_FORMAT = "%Y%m%dT%H%MZ"
PLAIN_NAME = re.compile(r"^[A-Za-z0-9_.:]+$")
SOURCE_PAGE = "/app/matalog/source?source_key=%s"

FIELD_COLUMNS = (
    "field_key", "source_key", "src_index", "src_sourcetype", "stratum_value", "field_name", "level", "is_rollup",
    "rollup_strata", "absent_strata", "absent_strata_count", "is_default", "presence", "first_seen_run", "last_seen_time", "origin", "origin_app", "origin_stanza",
    "origin_conflict", "cur_disc_run_id", "cur_disc_count", "cur_disc_events", "cur_disc_coverage", "cur_disc_distinct",
    "cur_prof_run_id", "cur_prof_count", "cur_prof_events", "cur_prof_coverage", "cur_prof_distinct",
    "cur_prof_distinct_exact", "cur_prof_sample_ratio", "stratum_key", "window_anchor", "type_guess", "identifier", "numeric_count", "num_min",
    "num_max", "num_mean", "top_values", "top_counts", "sample_values", "best_type_id", "best_type_rate", "cim_fields",
    "meaning_human", "meaning_human_author", "meaning_human_time", "usage_count", "usage_alert_count", "usage_objects",
    "usage_unscoped_count",
)
MATCH_COLUMNS = ("field_key", "source_key", "src_index", "src_sourcetype", "field_name", "last_seen_time", "origin",
                 "best_type_id", "cur_disc_run_id", "cur_disc_events", "cur_disc_coverage", "cur_disc_distinct",
                 "cur_prof_run_id", "cur_prof_events", "cur_prof_coverage", "cur_prof_distinct", "usage_count",
                 "usage_alert_count", "stratum_key", "window_anchor")
STRATUM_CHILD_COLUMNS = ("source_key", "field_name", "stratum_value", "stratum_key", "cur_disc_run_id", "cur_disc_events", "cur_disc_coverage",
                         "cur_prof_run_id", "cur_prof_events", "cur_prof_coverage")
STRATUM_WINDOW_COLUMNS = ("stratum_key", "source_key", "level", "cur_run_id", "cur_earliest", "cur_latest", "window_anchor")
PARAMETERS = ("source", "field", "type", "q", "limit", "defaults")
SOURCE_COLUMNS = ("source_key", "src_index", "src_sourcetype", "state", "stratum_field", "daily_events", "events_last_cycle",
                  "daily_bytes", "daily_bytes_status", "first_event_time", "last_event_time", "last_human_search_time",
                  "last_human_search_user", "strata_count", "strata_deferred", "field_count", "usage_count",
                  "usage_alert_count", "config_apps", "profile_mode", "sample_ratio", "last_profiled_run",
                  "last_discovered_run", "updated_run_id")
SOURCE_MATCH_COLUMNS = ("source_key", "src_index", "src_sourcetype", "search_sourcetype", "state", "daily_events",
                        "field_count", "usage_count", "usage_alert_count", "last_human_search_time",
                        "last_human_search_user", "config_apps", "sources_top", "updated_run_id")
STRATUM_COLUMNS = ("stratum_field", "stratum_value", "stratum_label", "value_kind", "share_of_source", "field_count",
                   "last_discovered_run")
WINDOW_LENGTHS = {
    "profile": ("profile", "profile_window_seconds"),
    "discovery": ("discovery", "discovery_window_seconds"),
    "cycle": ("budget", "cycle_seconds"),
}


# Value helpers.

def num(value, default=None):
    if value in (None, ""):
        return default
    try:
        f = float(value)
    except (TypeError, ValueError):
        return default
    return int(f) if f == int(f) and "." not in str(value) else f


def inum(value, default=0):
    v = num(value, default)
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def type_name(type_id):
    # Type ids are namespaced (mt:, user:); callers get the bare name.
    value = text(type_id)
    return value.split(":", 1)[1] if ":" in value else value


def app_name(app):
    # config_apps entries are app@version.
    return text(app).split("@", 1)[0]


def listing(value):
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return [text(v) for v in value]
    return [text(value)]


def spl_name(name):
    return name if PLAIN_NAME.match(name) else '"%s"' % name.replace('"', '\\"')


def spl_value(value):
    return '"%s"' % text(value).replace("\\", "\\\\").replace('"', '\\"')


def source_spl(idx, st):
    return "index=%s sourcetype=%s" % (idx, spl_value(st))


def stratum_filter(stratum_field, value, value_kind):
    name = spl_name(stratum_field)
    if value_kind == "missing":
        return "NOT %s=*" % name
    if value_kind == "empty":
        return '%s=""' % name
    if value_kind == "value":
        return "%s=%s" % (name, spl_value(value))
    return ""


def field_spl(idx, st, name):
    fname = spl_name(name)
    return "%s %s=* | stats count by %s" % (source_spl(idx, st), fname, fname)


def slot_start_of(run_id):
    """Slot start epoch of a run id; None when it is not one."""
    try:
        dt = datetime.datetime.strptime(text(run_id), RUN_ID_FORMAT).replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        return None
    return int(dt.timestamp())


# Windows.

class Windows(object):
    """Window bounds from the run records, the way the pages compute them (ui/src/lib/window.js): the window ends
    window_lag_seconds before the run's slot start and reaches back profile_window_seconds, discovery_window_seconds,
    cycle_seconds or a day. A discovery window is taken from the stratum row the search ran on when that row's
    current discovery is the same run (cur_earliest, cur_latest; for a source-level row, the span of the source's
    stratum rows discovered in that run), which is the real window of an anchored first discovery. The newest
    committed run is read on construction; the runs and strata the rows name are stamped as the entries are built
    and read in one query each by resolve()."""

    def __init__(self, read):
        self.read = read
        self.budgets = {}
        self.strata = {}
        self.newest = ""
        self.pending = []
        for row in read("matalog_runs", {"committed": 1}, fields=("run_id", "budget"), limit=1, sort="started_at:-1"):
            self.newest = text(row.get("run_id"))
            self.budgets[self.newest] = row.get("budget") or {}

    def values_stored(self):
        profile = (self.budgets.get(self.newest) or {}).get("profile")
        if isinstance(profile, dict) and "store_sample_values" in profile:
            return 0 if profile.get("store_sample_values") in (False, 0, "0", "false", "False") else 1
        return 1

    def stamp(self, target, start_key, end_key, run_id, kind, row=None, anchor_key=None):
        """Fill target[start_key] and target[end_key] with the bounds of the run's window once resolve() has run;
        row is the field row whose stratum_key and source_key locate the stratum window of a discovery, and
        target[anchor_key] takes that stratum row's window_anchor when the row carries none."""
        target[start_key] = None
        target[end_key] = None
        where = None
        if kind == "discovery" and row is not None:
            where = (text(row.get("source_key")), text(row.get("stratum_key")))
        self.pending.append((target, start_key, end_key, text(run_id), kind, where, anchor_key))

    def resolve(self):
        wanted = sorted(set(p[3] for p in self.pending if p[3]) - set(self.budgets))
        for chunk in chunks(wanted, IN_CHUNK):
            for row in self.read("matalog_runs", {"run_id": {"$in": chunk}}, fields=("run_id", "budget")):
                self.budgets[text(row.get("run_id"))] = row.get("budget") or {}
        sources = sorted(set(p[5][0] for p in self.pending if p[5] and p[5][0]) - set(self.strata))
        for chunk in chunks(sources, IN_CHUNK):
            for key in chunk:
                self.strata[key] = []
            for row in self.read("matalog_strata", {"source_key": {"$in": chunk}}, fields=STRATUM_WINDOW_COLUMNS):
                self.strata.setdefault(text(row.get("source_key")), []).append(row)
        for target, start_key, end_key, run_id, kind, where, anchor_key in self.pending:
            bounds, anchor = self.stratum_bounds(run_id, where) if where else (None, "")
            target[start_key], target[end_key] = bounds or self.bounds(run_id, kind)
            if anchor_key is not None and not target.get(anchor_key):
                target[anchor_key] = anchor
        self.pending = []

    def stratum_bounds(self, run_id, where):
        """([cur_earliest, cur_latest], window_anchor) of the stratum row the discovery ran on, when its current
        discovery is run_id: the row by stratum_key, else the span of the source's stratum-level rows of that run
        (anchored when any of them is); (None, "") otherwise."""
        source_key, stratum_key = where
        rows = [r for r in self.strata.get(source_key) or [] if text(r.get("cur_run_id")) == run_id
                and num(r.get("cur_earliest")) is not None and num(r.get("cur_latest")) is not None]
        own = [r for r in rows if text(r.get("stratum_key")) == stratum_key]
        if own:
            return [num(own[0].get("cur_earliest")), num(own[0].get("cur_latest"))], text(own[0].get("window_anchor"))
        strata = [r for r in rows if text(r.get("level")) == "stratum"]
        if strata:
            anchor = next((text(r.get("window_anchor")) for r in strata if text(r.get("window_anchor"))), "")
            return [min(num(r.get("cur_earliest")) for r in strata), max(num(r.get("cur_latest")) for r in strata)], anchor
        return None, ""

    def bounds(self, run_id, kind):
        """[start, end] of the profile, discovery, cycle or day window of a run; [None, None] when the run record
        is gone or the run id is not one."""
        start = slot_start_of(run_id)
        budget = self.budgets.get(text(run_id))
        if start is None or not isinstance(budget, dict):
            return [None, None]
        lag = num((budget.get("budget") or {}).get("window_lag_seconds"))
        if kind == "day":
            length = DAY_SECONDS
        else:
            group, name = WINDOW_LENGTHS[kind]
            length = num((budget.get(group) or {}).get(name))
        if lag is None or length is None:
            return [None, None]
        end = start - lag
        return [end - length, end]

    def block(self):
        """The newest committed run's windows with the day's events over the readable sources."""
        sources = self.read("matalog_sources", {"state": "active"}, fields=("daily_events",))
        day, profile, discovery, cycle = (self.bounds(self.newest, k) for k in ("day", "profile", "discovery", "cycle"))
        return {
            "run": self.newest,
            "ws": day[0], "we": day[1],
            "ev": sum(inum(s.get("daily_events")) for s in sources),
            "srcs": len(sources),
            "pws": profile[0], "pwe": profile[1],
            "dws": discovery[0], "dwe": discovery[1],
            "cws": cycle[0], "cwe": cycle[1],
        }


# Row shaping.

def snapshot(row):
    """The profile snapshot when one exists, else the discovery snapshot."""
    if row.get("cur_prof_run_id"):
        return "profile", "cur_prof_"
    return "discovery", "cur_disc_"


def compact_field(row, windows):
    win, p = snapshot(row)
    top_values = listing(row.get("top_values"))[:TOP_CAP]
    top_counts = listing(row.get("top_counts"))[:TOP_CAP]
    top = [[v, inum(c)] for v, c in zip(top_values, top_counts)]
    profile = win == "profile"
    out = {
        "n": text(row.get("field_name")),
        "idx": text(row.get("src_index")),
        "st": text(row.get("src_sourcetype")),
        "key": text(row.get("field_key")),
        "cov": num(row.get(p + "coverage")),
        "cnt": inum(row.get(p + "count")),
        "ev": inum(row.get(p + "events")),
        "dist": inum(row.get(p + "distinct")),
        "exact": inum(row.get("cur_prof_distinct_exact"), 1) if profile else None,
        "win": win,
        "ratio": inum(row.get("cur_prof_sample_ratio"), 1) if profile else 1,
        "run": text(row.get(p + "run_id")),
        "ws": None,
        "we": None,
        "no_events": 0,
        "anchor": text(row.get("window_anchor")) if win == "discovery" else "",
        "tg": text(row.get("type_guess")),
        "id": inum(row.get("identifier")),
        "ty": type_name(row.get("best_type_id")),
        "tr": num(row.get("best_type_rate")),
        "seen": num(row.get("last_seen_time")),
        "first_run": text(row.get("first_seen_run")),
        "org": text(row.get("origin")),
        "app": text(row.get("origin_app")),
        "stanza": text(row.get("origin_stanza")),
        "conflict": inum(row.get("origin_conflict")),
        "dm": listing(row.get("cim_fields")),
        "mean": text(row.get("meaning_human")),
        "mean_by": text(row.get("meaning_human_author")),
        "mean_at": num(row.get("meaning_human_time")),
        "used": inum(row.get("usage_count")),
        "alerts": inum(row.get("usage_alert_count")),
        "unscoped": inum(row.get("usage_unscoped_count")),
        "objects": listing(row.get("usage_objects"))[:OBJECTS_CAP],
        "top": top,
        "samples": [] if top else listing(row.get("sample_values"))[:SAMPLE_CAP],
        "num": [num(row.get("num_min")), num(row.get("num_max")), num(row.get("num_mean"))] if inum(row.get("numeric_count")) else [],
        "strata_n": inum(row.get("rollup_strata")),
        "abs": listing(row.get("absent_strata")),
        "absn": inum(row.get("absent_strata_count")),
        "dflt": inum(row.get("is_default")),
        "spl": field_spl(text(row.get("src_index")), text(row.get("src_sourcetype")), text(row.get("field_name"))),
    }
    out["no_events"] = 1 if out["ev"] == 0 else 0
    windows.stamp(out, "ws", "we", out["run"], win, row, "anchor")
    return out


def compact_match(row, windows):
    win, p = snapshot(row)
    out = {
        "n": text(row.get("field_name")),
        "idx": text(row.get("src_index")),
        "st": text(row.get("src_sourcetype")),
        "key": text(row.get("field_key")),
        "ty": type_name(row.get("best_type_id")),
        "cov": num(row.get(p + "coverage")),
        "dist": inum(row.get(p + "distinct")),
        "ev": inum(row.get(p + "events")),
        "win": win,
        "run": text(row.get(p + "run_id")),
        "ws": None,
        "we": None,
        "no_events": 0,
        "anchor": text(row.get("window_anchor")) if win == "discovery" else "",
        "seen": num(row.get("last_seen_time")),
        "org": text(row.get("origin")),
        "used": inum(row.get("usage_count")),
        "alerts": inum(row.get("usage_alert_count")),
    }
    out["no_events"] = 1 if out["ev"] == 0 else 0
    windows.stamp(out, "ws", "we", out["run"], win, row, "anchor")
    return out


def compact_source(row, strata, windows):
    idx, st = text(row.get("src_index")), text(row.get("src_sourcetype"))
    stratum_field = text(row.get("stratum_field")) or "__all__"
    rows = sorted(strata, key=lambda s: -(num(s.get("share_of_source"), 0) or 0))
    out = {
        "idx": idx,
        "st": st,
        "key": text(row.get("source_key")),
        "state": text(row.get("state")),
        "events_day": inum(row.get("daily_events")),
        "events_cycle": inum(row.get("events_last_cycle")),
        "ws": None,
        "we": None,
        "updated": text(row.get("updated_run_id")),
        "bytes_day": num(row.get("daily_bytes")),
        "bytes_status": text(row.get("daily_bytes_status")),
        "first_event": num(row.get("first_event_time")),
        "last_event": num(row.get("last_event_time")),
        "last_search": num(row.get("last_human_search_time")),
        "last_search_user": text(row.get("last_human_search_user")),
        "stratum_field": stratum_field,
        "strata": [[text(s.get("stratum_value")), num(s.get("share_of_source"), 0), inum(s.get("field_count")),
                    stratum_filter(stratum_field, s.get("stratum_value"), text(s.get("value_kind")))] for s in rows],
        "strata_deferred": inum(row.get("strata_deferred")),
        "fields": inum(row.get("field_count")),
        "used": inum(row.get("usage_count")),
        "alerts": inum(row.get("usage_alert_count")),
        "apps": listing(row.get("config_apps")),
        "mode": text(row.get("profile_mode")),
        "ratio": inum(row.get("sample_ratio"), 1),
        "profiled": text(row.get("last_profiled_run")),
        "discovered": text(row.get("last_discovered_run")),
        "spl": source_spl(idx, st),
    }
    windows.stamp(out, "ws", "we", out["updated"], "day")
    return out


def card_source(src, windows):
    """The source essentials a field card carries."""
    keys = ("events_day", "updated", "bytes_day", "first_event", "last_event", "last_search", "last_search_user",
            "stratum_field", "fields", "used", "alerts", "apps", "mode", "ratio")
    out = dict((k, src.get(k)) for k in keys)
    out["strata_n"] = len(src.get("strata") or [])
    windows.stamp(out, "ws", "we", out["updated"], "day")
    return out


def compact_source_match(row, via, windows):
    idx, st, key = text(row.get("src_index")), text(row.get("src_sourcetype")), text(row.get("source_key"))
    out = {
        "idx": idx,
        "st": st,
        "sst": text(row.get("search_sourcetype")) or st,
        "key": key,
        "state": text(row.get("state")),
        "events_day": inum(row.get("daily_events")),
        "ws": None,
        "we": None,
        "updated": text(row.get("updated_run_id")),
        "fields": inum(row.get("field_count")),
        "used": inum(row.get("usage_count")),
        "alerts": inum(row.get("usage_alert_count")),
        "last_search": num(row.get("last_human_search_time")),
        "last_search_user": text(row.get("last_human_search_user")),
        "apps": listing(row.get("config_apps")),
        "via": via,
        "spl": source_spl(idx, st),
        "page": SOURCE_PAGE % key,
    }
    windows.stamp(out, "ws", "we", out["updated"], "day")
    return out


# Routes.

def parse_limit(value):
    n = inum(value, DEFAULT_LIMIT)
    if n < 1:
        n = DEFAULT_LIMIT
    return min(n, MAX_LIMIT)


def parse_defaults(value):
    return 1 if text(value).strip().lower() in ("1", "true", "yes") else 0


def hide_defaults(query, defaults):
    """The query with Splunk default fields left out unless defaults=1; rows without the column count as not default."""
    if defaults:
        return query
    out = dict(query)
    out["is_default"] = {"$ne": 1}
    return out


def count_defaults(read, query, defaults):
    """How many is_default rows the query would have listed; 0 when they are listed."""
    if defaults:
        return 0
    hidden = dict(query)
    hidden["is_default"] = 1
    return len(read("matalog_fields", hidden, fields=("_key",)))


def split_source(source):
    idx, sep, st = source.partition(":")
    if not sep or not idx or not st:
        raise RequestError(400, "source must be <index>:<sourcetype>")
    return idx.lower(), st


def read_source(read, idx, st):
    rows = read("matalog_sources", {"src_index": idx, "src_sourcetype": st}, fields=SOURCE_COLUMNS, limit=1)
    if not rows:
        raise RequestError(404, "no source %s:%s in the catalog" % (idx, st))
    return rows[0]


def read_strata(read, source_keys):
    if not source_keys:
        return []
    return read("matalog_strata", {"source_key": {"$in": sorted(source_keys)}, "level": "stratum", "state": "active"},
                fields=("source_key",) + STRATUM_COLUMNS)


def source_summary(source, limit, read, defaults, windows):
    idx, st = split_source(source)
    row = read_source(read, idx, st)
    key = text(row.get("source_key"))
    strata = read_strata(read, [key])
    query = {"source_key": key, "level": "source", "presence": "present"}
    fields = read("matalog_fields", hide_defaults(query, defaults), fields=FIELD_COLUMNS, limit=limit, sort="field_name")
    hidden = count_defaults(read, query, defaults)
    total = max(inum(row.get("field_count"), len(fields)) - hidden, len(fields))
    return {
        "source": compact_source(row, strata, windows),
        "fields": [compact_field(f, windows) for f in fields],
        "n": total,
        "limit": limit,
        "truncated": 1 if total > len(fields) else 0,
        "defaults": defaults,
        "defaults_hidden": hidden,
    }


def match_rank(name, word):
    """0 for the exact name (case-insensitive), 1 for a prefix, 2 for a substring match."""
    lower, needle = name.lower(), word.lower()
    if lower == needle:
        return 0
    if lower.startswith(needle):
        return 1
    return 2


def name_matches(word, limit, read, windows, exclude=None, defaults=0):
    query = {"field_name": {"$regex": re.escape(word), "$options": "i"}, "level": "source"}
    rows = read("matalog_fields", hide_defaults(query, defaults), fields=MATCH_COLUMNS, limit=MAX_LIMIT + 1, sort="field_name")
    rows = [r for r in rows if exclude is None or r.get("field_name") != exclude]
    rows.sort(key=lambda r: (match_rank(text(r.get("field_name")), word), -inum(r.get("usage_count")),
                             -(num(r.get(snapshot(r)[1] + "coverage"), 0) or 0), text(r.get("field_name")).lower(),
                             text(r.get("src_index")), text(r.get("src_sourcetype"))))
    truncated = len(rows) > limit
    rows = rows[:limit]
    hidden = count_defaults(read, query, defaults)
    return [compact_match(r, windows) for r in rows], truncated, hidden


def source_matches(word, limit, read, windows):
    """Sources whose sourcetype, search sourcetype, source paths (sources_top) or config app names contain the word:
    exact sourcetype first, then prefix, substring, a source path, an app; then usage and daily events."""
    pattern = {"$regex": re.escape(word), "$options": "i"}
    query = {"$or": [{"src_sourcetype": pattern}, {"search_sourcetype": pattern}, {"sources_top": pattern}, {"config_apps": pattern}]}
    rows = read("matalog_sources", query, fields=SOURCE_MATCH_COLUMNS, limit=MAX_LIMIT + 1, sort="src_sourcetype")
    needle = word.lower()
    ranked = []
    for r in rows:
        st, sst = text(r.get("src_sourcetype")), text(r.get("search_sourcetype"))
        via, rank = [], 5
        if needle in st.lower():
            via.append("sourcetype")
            rank = min(rank, match_rank(st, word))
        if sst and sst != st and needle in sst.lower():
            via.append("search_sourcetype")
            rank = min(rank, match_rank(sst, word))
        if any(needle in s.lower() for s in listing(r.get("sources_top"))):
            via.append("source")
            rank = min(rank, 3)
        if any(needle in app_name(a).lower() for a in listing(r.get("config_apps"))):
            via.append("app")
            rank = min(rank, 4)
        if via:
            ranked.append((rank, -inum(r.get("usage_count")), -inum(r.get("daily_events")), text(r.get("src_index")), st, r, via))
    ranked.sort(key=lambda t: t[:5])
    truncated = len(ranked) > limit
    return [compact_source_match(r, via, windows) for _, _, _, _, _, r, via in ranked[:limit]], truncated


def build_cards(rows, read, windows):
    """Field cards for source-level rows: the field object plus presence, the source essentials and the strata."""
    source_keys = set(text(r.get("source_key")) for r in rows)
    names = set(text(r.get("field_name")) for r in rows)
    sources = {}
    if source_keys:
        for s in read("matalog_sources", {"source_key": {"$in": sorted(source_keys)}}, fields=SOURCE_COLUMNS):
            sources[text(s.get("source_key"))] = s
    strata_by_source = {}
    for s in read_strata(read, source_keys):
        strata_by_source.setdefault(text(s.get("source_key")), []).append(s)
    children = {}
    if source_keys:
        for c in read("matalog_fields", {"field_name": {"$in": sorted(names)}, "level": "stratum", "presence": "present",
                                         "source_key": {"$in": sorted(source_keys)}}, fields=STRATUM_CHILD_COLUMNS):
            win, p = snapshot(c)
            entry = [text(c.get("stratum_value")), num(c.get(p + "coverage")), inum(c.get(p + "events")), None, None]
            windows.stamp(entry, 3, 4, c.get(p + "run_id"), win, c)
            children.setdefault((text(c.get("source_key")), text(c.get("field_name"))), []).append(entry)
    cards = []
    for r in rows:
        key = text(r.get("source_key"))
        card = compact_field(r, windows)
        src = compact_source(sources.get(key, {"source_key": key, "src_index": r.get("src_index"),
                                               "src_sourcetype": r.get("src_sourcetype")}), strata_by_source.get(key, []), windows)
        card["presence"] = text(r.get("presence"))
        card["src"] = card_source(src, windows)
        card["strata"] = sorted(children.get((key, card["n"]), []), key=lambda c: (-(c[1] or 0), c[0]))
        card["absent"] = max(len(src["strata"]) - len(card["strata"]), 0) if src["strata"] else 0
        cards.append(card)
    cards.sort(key=lambda c: (-c["alerts"], -c["used"], -(c["cov"] or 0), -(c["src"]["events_day"] or 0), c["idx"], c["st"]))
    return cards


def field_summary(name, limit, read, defaults, windows):
    rows = read("matalog_fields", {"field_name": name, "level": "source"}, fields=FIELD_COLUMNS, limit=limit + 1,
                sort="src_sourcetype")
    truncated = len(rows) > limit
    cards = build_cards(rows[:limit], read, windows)
    other, other_truncated, hidden = name_matches(name, limit, read, windows, exclude=name, defaults=defaults)
    return {
        "field": name,
        "cards": cards,
        "n": len(cards),
        "truncated": 1 if truncated else 0,
        "other": other,
        "other_truncated": 1 if other_truncated else 0,
        "dm": datamodel_fields(name, read),
        "limit": limit,
        "defaults": defaults,
        "defaults_hidden": hidden,
    }


def type_rows(name, read):
    """The matalog_semantic_types rows whose bare name is the given one, case-insensitive."""
    pattern = {"$regex": "^(mt|user):%s$" % re.escape(name), "$options": "i"}
    return read("matalog_semantic_types", {"type_id": pattern}, fields=("type_id", "match_threshold"))


def type_summary(name, limit, read, defaults, windows, notes):
    """One card per source-level field whose best type is the bare name (mt: or user: namespace), case-insensitive,
    and whose best_type_rate reaches the type's match_threshold; best rate first, then the card order."""
    types = type_rows(name, read)
    if not types:
        notes.append("type %s is not a known semantic type" % name)
    thresholds = dict((text(t.get("type_id")), num(t.get("match_threshold"), 0) or 0) for t in types)
    query = {"level": "source", "best_type_id": {"$regex": "^(mt|user):%s$" % re.escape(name), "$options": "i"}}
    rows = read("matalog_fields", hide_defaults(query, defaults), fields=FIELD_COLUMNS, limit=MAX_LIMIT + 1, sort="src_sourcetype")
    kept = [r for r in rows if (num(r.get("best_type_rate"), 0) or 0) >= thresholds.get(text(r.get("best_type_id")), 0)]
    below = len(rows) - len(kept)
    truncated = len(kept) > limit
    kept = kept[:limit]
    cards = build_cards(kept, read, windows)
    cards.sort(key=lambda c: -(c["tr"] or 0))
    return {
        "type": name,
        "ids": sorted(set(text(r.get("best_type_id")) for r in kept)),
        "threshold": dict((k, v) for k, v in thresholds.items()),
        "cards": cards,
        "n": len(cards),
        "below_threshold": below,
        "truncated": 1 if truncated else 0,
        "limit": limit,
        "defaults": defaults,
        "defaults_hidden": count_defaults(read, query, defaults),
    }


def datamodel_fields(name, read):
    rows = read("matalog_cim_coverage", {"cim_field": name}, fields=("cim_dataset", "mapped", "src_index", "src_sourcetype",
                                                                     "field_name", "cim_via"), limit=MAX_LIMIT)
    by_dataset = {}
    for r in rows:
        entry = by_dataset.setdefault(text(r.get("cim_dataset")), {"ds": text(r.get("cim_dataset")), "mapped": 0,
                                                                    "unmapped": 0, "sources": []})
        if inum(r.get("mapped")):
            entry["mapped"] += 1
            entry["sources"].append("%s:%s" % (text(r.get("src_index")), text(r.get("src_sourcetype"))))
        else:
            entry["unmapped"] += 1
    return [by_dataset[k] for k in sorted(by_dataset)]


def request_notes(params):
    """What the request named that is ignored: parameters the endpoint does not take, and the routes after the
    first one given, in the order source, field, type, q."""
    notes = []
    for name in sorted(params):
        if name not in PARAMETERS and not name.startswith("output_mode"):
            notes.append("unknown parameter %s ignored" % name)
    given = [name for name in ("source", "field", "type", "q") if params.get(name)]
    for name in given[1:]:
        notes.append("%s ignored, %s given" % (name, given[0]))
    return notes


def summarize(params, read):
    limit = parse_limit(params.get("limit"))
    defaults = parse_defaults(params.get("defaults"))
    windows = Windows(read)
    notes = request_notes(params)
    if params.get("source"):
        out = source_summary(params["source"], limit, read, defaults, windows)
    elif params.get("field"):
        out = field_summary(params["field"], limit, read, defaults, windows)
        if not out["cards"]:
            notes.append("field %s is not in the readable catalog" % params["field"])
    elif params.get("type"):
        out = type_summary(params["type"], limit, read, defaults, windows, notes)
    elif params.get("q"):
        srcs, srcs_truncated = source_matches(params["q"], limit, read, windows)
        matches, truncated, hidden = name_matches(params["q"], limit, read, windows, defaults=defaults)
        out = {"q": params["q"], "srcs": srcs, "srcs_n": len(srcs), "srcs_truncated": 1 if srcs_truncated else 0,
               "matches": matches, "n": len(matches), "truncated": 1 if truncated else 0, "limit": limit,
               "defaults": defaults, "defaults_hidden": hidden}
    else:
        raise RequestError(400, "one of source=<index>:<sourcetype>, field=<name>, type=<name> or q=<word> is required")
    windows.resolve()
    out["window"] = windows.block()
    out["values_stored"] = windows.values_stored()
    out["note"] = notes
    return out


# splunkd side.

class SummaryHandler(PersistentServerConnectionApplication):
    def __init__(self, command_line=None, command_arg=None):
        if PersistentServerConnectionApplication is not object:
            PersistentServerConnectionApplication.__init__(self)

    def handle(self, in_string):
        try:
            request = json.loads(in_string)
        except ValueError:
            return {"status": 400, "payload": {"error": "request is not JSON"}}
        if text(request.get("method")).upper() != "GET":
            return {"status": 405, "payload": {"error": "GET only"}}
        try:
            caller, system_key = caller_from_request(request)
            store = KvStore(system_key)
            payload = summarize(request_params(request), ScopedReader(store, caller))
        except RequestError as exc:
            return {"status": exc.status, "payload": {"error": str(exc)}}
        except Exception as exc:
            return {"status": 500, "payload": {"error": "%s: %s" % (exc.__class__.__name__, str(exc)[:500])}}
        return {"status": 200, "payload": payload, "headers": {"Content-Type": "application/json"}}
