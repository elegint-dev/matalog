"""Row builders and the column contract for every summary row kind and KV collection.

Column lists and types are docs/data-model.md. validate() rejects unknown and
missing columns so a step cannot drift from the contract. Values use None for
empty; the writer encodes None as "" in the index and drops it in KV.
"""
import collections
import hashlib
import json
import math

from . import keys

STRING, INT, FLOAT, BOOL, EPOCH, STRING_LIST, JSON = "string", "int", "float", "bool", "epoch", "string[]", "json"
SCALAR_TYPES = (STRING, INT, FLOAT, BOOL, EPOCH)

TYPE_GUESSES = ("string", "integer", "float", "boolean", "mixed", "empty")
ORIGINS = ("indexed", "json_auto", "kv_auto", "regex_extract", "regex_report", "alias", "eval", "lookup", "datamodel", "unknown")
COST_STATUSES = ("ok", "failed", "timeout")
RUN_STATUSES = ("running", "ok", "partial", "failed", "skipped_locked")
RUN_MODES = ("normal", "rebuild")
ROW_MODES = ("discovery", "profile")
STRATUM_ROW_MODES = ROW_MODES + ("listing",)
SHAPES = ("slim", "full")
# window_anchor of a discovery or listing whose window ended at the source's last_event_time instead of the slot.
ANCHOR_LAST_EVENT = "last_event"


class RowError(ValueError):
    """A row has an unknown column, lacks a column, or holds a value of the wrong type."""


def _cols(*pairs):
    out = collections.OrderedDict()
    for names, typ in pairs:
        for name in names.split():
            out[name] = typ
    return out


def _prefixed(prefix, spec):
    return [(" ".join(prefix + n for n in names.split()), typ) for names, typ in spec]


SUMMARY_COMMON = _cols(("kind run_id", STRING), ("attempt", INT), ("profiled_as", STRING))

_DISC_SNAPSHOT = [("run_id", STRING), ("count events", INT), ("coverage", FLOAT), ("distinct", INT)]
_PROF_SNAPSHOT = _DISC_SNAPSHOT + [("distinct_exact", BOOL), ("sample_ratio", INT)]
_STRATUM_SNAPSHOT = [("run_id", STRING), ("events_seen events_scanned", INT), ("scan_ratio", FLOAT), ("fields_found", INT)]
_EDGE_SNAPSHOT = [("run_id type_version profile_id", STRING), ("tested matched", INT), ("match_rate", FLOAT)]

SUMMARY_KINDS = collections.OrderedDict([
    ("source", _cols(
        ("row_id source_key src_index src_sourcetype", STRING),
        ("events_last_cycle daily_events daily_bytes", INT),
        ("last_event_time", EPOCH),
        ("config_apps version_top version_top_counts", STRING_LIST))),
    ("stratum", _cols(
        ("row_id mode source_key stratum_key src_index src_sourcetype stratum_field stratum_value", STRING),
        ("earliest latest", EPOCH),
        ("sample_ratio events_seen events_scanned", INT),
        ("scan_ratio", FLOAT),
        ("fields_found", INT),
        ("truncated fields_truncated prunable", BOOL),
        ("version_top version_top_counts", STRING_LIST),
        ("sid", STRING),
        ("search_seconds", FLOAT),
        ("window_anchor", STRING))),
    ("field", _cols(
        ("profile_id shape mode field_key stratum_key source_key src_index src_sourcetype stratum_field stratum_value field_name", STRING),
        ("earliest latest", EPOCH),
        ("sample_ratio events_in_stratum count", INT),
        ("coverage", FLOAT),
        ("distinct", INT),
        ("distinct_exact", BOOL),
        ("numeric_count", INT),
        ("num_min num_max num_mean num_stdev", FLOAT),
        ("type_guess", STRING),
        ("identifier", BOOL),
        ("values_hash sid window_anchor", STRING))),
    ("search_cost", _cols(
        ("row_id sid step subject_key spl_hash", STRING),
        ("earliest latest", EPOCH),
        ("sample_ratio scan_count event_count result_rows", INT),
        ("run_duration", FLOAT),
        ("status error", STRING))),
    ("commit", _cols(
        ("row_id run_mode", STRING),
        ("committed_at", EPOCH),
        ("type_versions_hash config_hash", STRING),
        ("rows_kind rows_count", STRING_LIST),
        ("write_bytes searches_issued events_scanned", INT),
        ("search_seconds wall_seconds", FLOAT),
        ("budget_exhausted", STRING))),
])

# Columns present only on full kind=field rows.
FIELD_FULL_COLUMNS = _cols(("top_values top_counts sample_values", STRING_LIST), ("samples_truncated", BOOL), ("origin origin_app", STRING))

COLLECTIONS = collections.OrderedDict([
    ("matalog_sources", _cols(
        ("source_key src_index src_sourcetype search_sourcetype profiled_as stratum_field version_field state first_seen_run last_seen_run", STRING),
        ("first_event_time last_event_time", EPOCH),
        ("events_last_cycle daily_events daily_bytes", INT),
        ("daily_bytes_status", STRING),
        ("base_rate_per_hour", FLOAT),
        ("profile_mode", STRING),
        ("sample_ratio", INT),
        ("priority", FLOAT),
        ("last_discovered_run last_profiled_run", STRING),
        ("next_profile_due", EPOCH),
        ("strata_count strata_deferred strata_profile_due field_count", INT),
        ("last_human_search_time", EPOCH),
        ("last_human_search_user", STRING),
        ("usage_count usage_alert_count", INT),
        ("config_apps", STRING_LIST),
        ("config_apps_changed_run", STRING),
        ("version_top version_top_counts", STRING_LIST),
        ("version_changed_run", STRING),
        ("stratum_candidates", STRING_LIST),
        ("sources_top hosts_top", STRING_LIST),
        ("index_scan_run", STRING),
        ("updated_run_id", STRING))),
    ("matalog_stratum_config", _cols(
        ("index_pattern src_sourcetype stratum_field version_field origin", STRING),
        ("enabled", BOOL),
        ("set_by", STRING),
        ("set_at", EPOCH))),
    ("matalog_strata", _cols(
        ("stratum_key source_key src_index src_sourcetype stratum_field stratum_value stratum_label value_kind level", STRING),
        ("prunable", BOOL),
        ("state", STRING),
        ("listed_events listed_sample_ratio", INT),
        ("rate_per_hour share_of_source", FLOAT),
        ("first_seen_run last_seen_run retired_run last_discovered_run discovery_due_run cur_run_id", STRING),
        ("cur_earliest cur_latest", EPOCH),
        ("cur_events_seen cur_events_scanned", INT),
        ("cur_scan_ratio", FLOAT),
        ("cur_fields_found", INT),
        ("cur_truncated cur_fields_truncated", BOOL),
        ("window_anchor", STRING),
        *_prefixed("base_", _STRATUM_SNAPSHOT),
        ("last_profiled_run profile_due_run", STRING),
        ("field_count", INT),
        ("version_top version_top_counts", STRING_LIST),
        ("version_changed_run", STRING),
        ("updated_run_id", STRING))),
    ("matalog_fields", _cols(
        ("field_key source_key stratum_key src_index src_sourcetype stratum_field stratum_value stratum_label field_name level", STRING),
        ("is_rollup", BOOL),
        ("rollup_strata", INT),
        ("absent_strata", STRING_LIST),
        ("absent_strata_count", INT),
        ("is_stratum_field is_default", BOOL),
        ("presence", STRING),
        ("observed declared", BOOL),
        ("first_seen_run last_seen_run", STRING),
        ("last_seen_time", EPOCH),
        ("consecutive_unseen", INT),
        ("retired_run origin origin_app origin_stanza origin_decl_key", STRING),
        ("origin_candidates", STRING_LIST),
        ("origin_conflict", BOOL),
        ("origin_changed_run", STRING),
        *_prefixed("cur_disc_", _DISC_SNAPSHOT),
        ("window_anchor", STRING),
        *_prefixed("base_disc_", _DISC_SNAPSHOT),
        *_prefixed("cur_prof_", _PROF_SNAPSHOT),
        *_prefixed("base_prof_", _PROF_SNAPSHOT),
        *_prefixed("week_prof_", _PROF_SNAPSHOT),
        ("profile_id type_guess", STRING),
        ("identifier", BOOL),
        ("numeric_count", INT),
        ("num_min num_max num_mean", FLOAT),
        ("top_values top_counts sample_values", STRING_LIST),
        ("samples_truncated", BOOL),
        ("values_hash best_type_id", STRING),
        ("best_type_rate", FLOAT),
        ("types cim_fields cim_via", STRING_LIST),
        ("meaning_human meaning_human_author", STRING),
        ("meaning_human_time", EPOCH),
        ("meaning_human_revision usage_count usage_alert_count", INT),
        ("usage_objects", STRING_LIST),
        ("usage_last_run_time", EPOCH),
        ("usage_unscoped_count", INT),
        ("updated_run_id", STRING))),
    ("matalog_declarations", _cols(
        ("decl_key app app_version owner sharing conf_file stanza stanza_kind src_sourcetype attribute origin_class raw_value", STRING),
        ("fields_declared", STRING_LIST),
        ("parse_status", STRING),
        ("applies_to_source_keys", STRING_LIST),
        ("first_seen_run last_seen_run", STRING))),
    ("matalog_cim_coverage", _cols(
        ("cim_dataset cim_field src_index src_sourcetype source_key", STRING),
        ("mapped", BOOL),
        ("field_name field_key cim_via via_decl_key", STRING),
        ("coverage", FLOAT),
        ("cim_description", STRING),
        ("cim_expected_values", STRING_LIST),
        ("derived_run", STRING))),
    ("matalog_meanings", _cols(
        ("field_key src_index src_sourcetype field_name", STRING),
        ("revision", INT),
        ("is_current", BOOL),
        ("text author", STRING),
        ("created_at", EPOCH),
        ("note status", STRING))),
    ("matalog_objects", _cols(
        ("object_key ko_type app owner name sharing", STRING),
        ("is_scheduled is_alert disabled is_matalog_own", BOOL),
        ("spl_hash parse_status", STRING),
        ("parse_gaps", STRING_LIST),
        ("last_run_time", EPOCH),
        ("run_count_30d", INT),
        ("last_parsed_run last_seen_run", STRING))),
    ("matalog_usage", _cols(
        ("object_key ko_type app name", STRING),
        ("is_alert", BOOL),
        ("field_name ref_kind resolution scope scope_text", STRING),
        ("resolved_field_keys", STRING_LIST),
        ("confidence last_seen_run", STRING),
        ("expanded", BOOL),
        ("macros scope_via", STRING_LIST))),
    ("matalog_semantic_types", _cols(
        ("type_id name label description origin", STRING),
        ("enabled", BOOL),
        ("matcher_kind pattern name_pattern", STRING),
        ("enum_values", STRING_LIST),
        ("enum_source lookup_name lookup_field", STRING),
        ("case_sensitive", BOOL),
        ("match_threshold", FLOAT),
        ("min_distinct specificity", INT),
        ("parent_type_id type_version author", STRING),
        ("updated_at", EPOCH))),
    ("matalog_field_types", _cols(
        ("field_key type_id src_index src_sourcetype stratum_value field_name level", STRING),
        *_prefixed("cur_", _EDGE_SNAPSHOT),
        *_prefixed("base_", _EDGE_SNAPSHOT),
        ("is_match is_best", BOOL),
        ("source first_match_run", STRING))),
    ("matalog_runs", _cols(
        ("run_id", STRING),
        ("attempt", INT),
        ("committed", BOOL),
        ("committed_attempt", INT),
        ("run_mode status profiled_as app_context", STRING),
        ("started_at finished_at", EPOCH),
        ("budget", JSON),
        ("config_hash", STRING),
        ("type_versions", JSON),
        ("type_versions_hash", STRING),
        ("reclassified_types", STRING_LIST),
        ("searches_issued searches_failed write_searches write_reserve write_bytes events_scanned events_matched", INT),
        ("search_seconds wall_seconds", FLOAT),
        ("peak_concurrency", INT),
        ("per_step", JSON),
        ("sources_total sources_due sources_profiled sources_deferred strata_total strata_due strata_discovered "
         "strata_deferred strata_over_cap strata_profile_due strata_profiled fields_present fields_new indexes_total indexes_scanned", INT),
        ("budget_exhausted", STRING),
        ("indexes_sourceless", STRING_LIST),
        ("rows_written", JSON),
        ("objects_total objects_parsed objects_partial objects_failed", INT),
        ("cim_datasets cim_datasets_unresolved cim_mapped", INT),
        ("scan_ratio_max", FLOAT),
        ("audit_watermark", EPOCH),
        ("errors", JSON))),
])

ACCELERATED = collections.OrderedDict([
    ("matalog_sources", ["src_sourcetype", "state", "daily_bytes"]),
    ("matalog_stratum_config", ["src_sourcetype", "enabled"]),
    ("matalog_strata", ["source_key", "stratum_value", "state"]),
    ("matalog_fields", ["field_name", "source_key", "stratum_key", "level", "presence", "best_type_id"]),
    ("matalog_declarations", ["src_sourcetype", "app"]),
    ("matalog_cim_coverage", ["cim_dataset", "cim_field", "src_sourcetype", "mapped"]),
    ("matalog_meanings", ["field_key", "is_current"]),
    ("matalog_objects", ["ko_type", "parse_status"]),
    ("matalog_usage", ["field_name", "object_key", "resolution"]),
    ("matalog_semantic_types", ["enabled", "origin"]),
    ("matalog_field_types", ["type_id", "field_key", "is_match"]),
    ("matalog_runs", ["started_at", "status"]),
])

# Collections the profiler keeps for its own write path; not part of the catalog contract.
# matalog_write_buffer holds summary rows (r is the stash line) until a collect job copies them to the index.
# matalog_run_lock holds the one lock document (_key LOCK_KEY) of the attempt in progress.
INTERNAL_COLLECTIONS = collections.OrderedDict([
    ("matalog_write_buffer", _cols(("run_id", STRING), ("attempt seq", INT), ("kind r", STRING))),
    ("matalog_run_lock", _cols(("run_id", STRING), ("attempt pid", INT), ("host", STRING), ("started_at", EPOCH))),
])
INTERNAL_ACCELERATED = collections.OrderedDict([("matalog_write_buffer", ["run_id"]), ("matalog_run_lock", [])])
LOCK_KEY = "lock"

# Splunk default and internal fields: stored like any field, flagged is_default=1 so readers can hide them.
DEFAULT_FIELD_NAMES = frozenset((
    "_raw", "_time", "_indextime", "_cd", "_bkt", "_si", "_serial", "_sourcetype", "_subsecond", "_kv",
    "host", "index", "source", "sourcetype", "linecount", "punct", "splunk_server", "splunk_server_group",
    "timestamp", "timestartpos", "timeendpos", "eventtype", "tag", "tag::eventtype",
))


def is_default_field(field_name):
    """1 for a Splunk default field, an internal _ field or a date_* field."""
    name = str(field_name or "")
    return 1 if name in DEFAULT_FIELD_NAMES or name.startswith("date_") or name.startswith("tag::") else 0

# The column that equals _key per collection, where the contract names one.
KEY_COLUMN = {
    "matalog_sources": "source_key", "matalog_strata": "stratum_key", "matalog_fields": "field_key",
    "matalog_declarations": "decl_key", "matalog_objects": "object_key", "matalog_semantic_types": "type_id",
    "matalog_runs": "run_id",
}

# Snapshot groups the baseline roll rule moves: collection -> list of (cur prefix, base prefix, column suffixes).
SNAPSHOT_GROUPS = {
    "matalog_fields": [
        ("cur_disc_", "base_disc_", [n for names, _ in _DISC_SNAPSHOT for n in names.split()]),
        ("cur_prof_", "base_prof_", [n for names, _ in _PROF_SNAPSHOT for n in names.split()]),
    ],
    "matalog_strata": [("cur_", "base_", [n for names, _ in _STRATUM_SNAPSHOT for n in names.split()])],
    "matalog_field_types": [("cur_", "base_", [n for names, _ in _EDGE_SNAPSHOT for n in names.split()])],
}


# Validation.

def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _check_type(column, typ, value):
    if value is None:
        return
    if typ == STRING:
        if not isinstance(value, str):
            raise RowError("%s must be a string, got %r" % (column, value))
    elif typ == INT:
        if not _is_int(value):
            raise RowError("%s must be an int, got %r" % (column, value))
    elif typ == FLOAT or typ == EPOCH:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise RowError("%s must be a number, got %r" % (column, value))
        if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
            raise RowError("%s must be finite, got %r" % (column, value))
    elif typ == BOOL:
        if value not in (0, 1) or isinstance(value, bool) or isinstance(value, float):
            raise RowError("%s must be 0 or 1, got %r" % (column, value))
    elif typ == STRING_LIST:
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise RowError("%s must be a list of strings, got %r" % (column, value))
    elif typ == JSON:
        if not isinstance(value, (dict, list)):
            raise RowError("%s must be a dict or list, got %r" % (column, value))


def columns_for(kind=None, collection=None, shape=None):
    """The column -> type table for a summary kind or a KV collection."""
    if kind is not None:
        if kind not in SUMMARY_KINDS:
            raise RowError("unknown summary kind %r" % (kind,))
        table = collections.OrderedDict(SUMMARY_COMMON)
        table.update(SUMMARY_KINDS[kind])
        if kind == "field" and shape == "full":
            table.update(FIELD_FULL_COLUMNS)
        return table
    if collection is not None:
        if collection not in COLLECTIONS:
            raise RowError("unknown collection %r" % (collection,))
        table = collections.OrderedDict([("_key", STRING)])
        table.update(COLLECTIONS[collection])
        return table
    raise RowError("kind or collection is required")


def validate(row, kind=None, collection=None, partial=False):
    """Check a row against the contract: no unknown columns, every column present (unless partial), typed values.

    A summary row is validated by its kind column when kind is None. A KV doc
    needs its collection. partial=True allows a doc that updates a subset of
    columns, which is how steps stage KV writes; _key stays required.
    """
    if not isinstance(row, dict):
        raise RowError("row must be a dict")
    if kind is None and collection is None:
        kind = row.get("kind")
        if kind is None:
            raise RowError("row has no kind")
    if kind is not None and row.get("kind") not in (None, kind):
        raise RowError("row kind %r is not %r" % (row.get("kind"), kind))
    shape = row.get("shape") if kind == "field" else None
    if kind == "field" and shape not in ("slim", "full"):
        raise RowError("kind=field row needs shape slim or full, got %r" % (shape,))
    table = columns_for(kind=kind, collection=collection, shape=shape)
    unknown = [c for c in row if c not in table]
    if unknown:
        raise RowError("unknown column(s) for %s: %s" % (kind or collection, ", ".join(sorted(unknown))))
    if partial:
        if collection is not None and "_key" not in row:
            raise RowError("partial doc for %s has no _key" % collection)
    else:
        missing = [c for c in table if c not in row]
        if missing:
            raise RowError("missing column(s) for %s: %s" % (kind or collection, ", ".join(missing)))
    for column, value in row.items():
        _check_type(column, table[column], value)
    if kind == "search_cost" and row.get("status") not in COST_STATUSES:
        raise RowError("search_cost status must be one of %s" % (COST_STATUSES,))
    if kind == "field" and row.get("type_guess") not in TYPE_GUESSES:
        raise RowError("type_guess must be one of %s" % (TYPE_GUESSES,))
    if kind == "field" and row.get("mode") not in ROW_MODES:
        raise RowError("mode must be one of %s, got %r" % (ROW_MODES, row.get("mode")))
    if kind == "stratum" and row.get("mode") not in STRATUM_ROW_MODES:
        raise RowError("mode must be one of %s, got %r" % (STRATUM_ROW_MODES, row.get("mode")))
    if kind == "field" and row.get("mode") == "profile" and shape != "full":
        raise RowError("profile rows are full rows")
    if kind == "field" and row.get("origin") not in (None, "") and row["origin"] not in ORIGINS:
        raise RowError("origin must be one of %s" % (ORIGINS,))
    if kind == "commit" and row.get("run_mode") not in RUN_MODES:
        raise RowError("run_mode must be one of %s" % (RUN_MODES,))
    if collection == "matalog_fields" and "origin" in row and row["origin"] not in (None, "") and row["origin"] not in ORIGINS:
        raise RowError("origin must be one of %s" % (ORIGINS,))
    if collection == "matalog_runs" and "status" in row and row["status"] not in RUN_STATUSES:
        raise RowError("run status must be one of %s" % (RUN_STATUSES,))
    if collection == "matalog_runs" and row.get("run_mode") is not None and row["run_mode"] not in RUN_MODES:
        raise RowError("run_mode must be one of %s" % (RUN_MODES,))
    return row


def _fill(table, values, required):
    """Build a full row: every column present, None where not given."""
    unknown = [c for c in values if c not in table]
    if unknown:
        raise RowError("unknown column(s): %s" % ", ".join(sorted(unknown)))
    for name in required:
        if values.get(name) is None:
            raise RowError("%s is required" % name)
    row = collections.OrderedDict()
    for column in table:
        row[column] = values.get(column)
    return row


# Summary row builders. ctx_cols is {"run_id", "attempt", "profiled_as"}.

def _summary(kind, run, values, required, shape=None):
    table = columns_for(kind=kind, shape=shape)
    merged = dict(values)
    merged.update({"kind": kind, "run_id": run["run_id"], "attempt": run["attempt"], "profiled_as": run["profiled_as"]})
    row = _fill(table, merged, required)
    return validate(row, kind=kind)


def source_row(run, src_index, src_sourcetype, **values):
    """kind=source: one per source per run."""
    src_index = keys.norm_index(src_index)
    src_sourcetype = keys.norm_sourcetype(src_sourcetype)
    source_key = keys.source_key(src_index, src_sourcetype)
    values.update(src_index=src_index, src_sourcetype=src_sourcetype, source_key=source_key,
                  row_id=keys.k(run["run_id"], "source", source_key))
    for column in ("config_apps", "version_top", "version_top_counts"):
        values.setdefault(column, [])
    return _summary("source", run, values, ("events_last_cycle", "daily_events"))


def stratum_row(run, mode, src_index, src_sourcetype, stratum_field, stratum_value, **values):
    """kind=stratum: one per searched stratum per mode per run."""
    identity = stratum_identity(src_index, src_sourcetype, stratum_field, stratum_value)
    if mode not in STRATUM_ROW_MODES:
        raise RowError("mode must be one of %s" % (STRATUM_ROW_MODES,))
    values.update(identity)
    values.update(mode=mode, row_id=keys.k(run["run_id"], mode, identity["stratum_key"]))
    values.setdefault("prunable", keys.prunable(identity["stratum_value"]))
    for column in ("version_top", "version_top_counts"):
        values.setdefault(column, [])
    if values.get("events_seen") is not None and values.get("events_scanned") is not None and values.get("scan_ratio") is None:
        values["scan_ratio"] = scan_ratio(values["events_scanned"], values["events_seen"])
    if mode == "listing":
        required = ("earliest", "latest", "sample_ratio", "events_seen")
    else:
        required = ("earliest", "latest", "sample_ratio", "events_seen", "events_scanned", "fields_found", "truncated", "fields_truncated")
    return _summary("stratum", run, values, required)


def field_row(run, mode, shape, src_index, src_sourcetype, stratum_field, stratum_value, field_name, **values):
    """kind=field: slim or full."""
    identity = field_identity(src_index, src_sourcetype, stratum_field, stratum_value, field_name)
    if mode not in ("discovery", "profile"):
        raise RowError("mode must be discovery or profile")
    if shape not in ("slim", "full"):
        raise RowError("shape must be slim or full")
    values.update(identity)
    values.update(mode=mode, shape=shape, profile_id=keys.k(run["run_id"], mode, identity["field_key"]))
    if shape == "full":
        for column in ("top_values", "top_counts", "sample_values"):
            values.setdefault(column, [])
        values.setdefault("samples_truncated", 0)
    else:
        for column in FIELD_FULL_COLUMNS:
            if column in values:
                raise RowError("slim row carries full column %s" % column)
    if values.get("coverage") is None and values.get("count") is not None and values.get("events_in_stratum"):
        values["coverage"] = coverage(values["count"], values["events_in_stratum"])
    return _summary("field", run, values, ("earliest", "latest", "sample_ratio", "events_in_stratum", "count", "distinct", "distinct_exact", "numeric_count", "type_guess", "identifier", "values_hash"), shape=shape)


def search_cost_row(run, result, step, subject_key):
    """kind=search_cost from a finished JobResult."""
    # A job that never got a sid is identified by what it searched.
    sid = result.sid or keys.k(run["run_id"], step, subject_key or "", result.spl_hash, keys.num_text(result.earliest),
                               keys.num_text(result.latest), keys.num_text(result.sample_ratio))
    values = {
        "row_id": keys.k(run["run_id"], sid), "sid": sid, "step": step, "subject_key": subject_key or "",
        "spl_hash": result.spl_hash, "earliest": _epoch_or_none(result.earliest), "latest": _epoch_or_none(result.latest),
        "sample_ratio": int(result.sample_ratio or 1), "scan_count": int(result.scan_count), "event_count": int(result.event_count),
        "result_rows": int(result.result_count), "run_duration": float(result.run_duration), "status": result.status,
        "error": getattr(result, "error", "") or "",
    }
    return _summary("search_cost", run, values, ("status",))


def commit_row(run, run_mode, committed_at, config_hash, rows_written, budget_snapshot, write_bytes, type_versions_hash=""):
    """kind=commit, written last by S10. rows_written is {kind: count}."""
    kinds = list(rows_written.keys())
    values = {
        "row_id": keys.k(run["run_id"], run["attempt"]), "run_mode": run_mode, "committed_at": float(committed_at),
        "type_versions_hash": type_versions_hash or "", "config_hash": config_hash,
        "rows_kind": [str(k) for k in kinds], "rows_count": [str(int(rows_written[k])) for k in kinds],
        "write_bytes": int(write_bytes), "searches_issued": int(budget_snapshot["searches_issued"]),
        "events_scanned": int(budget_snapshot["events_scanned"]), "search_seconds": float(budget_snapshot["search_seconds"]),
        "wall_seconds": float(budget_snapshot["wall_seconds"]), "budget_exhausted": budget_snapshot.get("budget_exhausted") or "",
    }
    return _summary("commit", run, values, ("run_mode", "config_hash"))


# KV document builders. Each returns a partial doc (the columns given plus the
# identity columns) validated against the collection; the writer merges it onto
# the stored document and applies the roll rule.

def kv_doc(collection, key, **values):
    """A partial KV document with _key and the key column set."""
    table = columns_for(collection=collection)
    doc = collections.OrderedDict([("_key", key)])
    column = KEY_COLUMN.get(collection)
    if column:
        doc[column] = key
    for name, value in values.items():
        if name not in table:
            raise RowError("unknown column %s for %s" % (name, collection))
        doc[name] = value
    return validate(doc, collection=collection, partial=True)


def source_identity(src_index, src_sourcetype):
    src_index = keys.norm_index(src_index)
    src_sourcetype = keys.norm_sourcetype(src_sourcetype)
    return collections.OrderedDict([("source_key", keys.source_key(src_index, src_sourcetype)), ("src_index", src_index), ("src_sourcetype", src_sourcetype)])


def stratum_identity(src_index, src_sourcetype, stratum_field, stratum_value):
    ident = source_identity(src_index, src_sourcetype)
    stratum_field = keys.norm_stratum_field(stratum_field)
    if stratum_field == keys.ALL:
        stratum_value = keys.ALL
    keys.check_identity(stratum_value, "stratum_value")
    ident["stratum_key"] = keys.stratum_key(src_index, src_sourcetype, stratum_field, stratum_value)
    ident["stratum_field"] = stratum_field
    ident["stratum_value"] = stratum_value
    return ident


def field_identity(src_index, src_sourcetype, stratum_field, stratum_value, field_name):
    ident = stratum_identity(src_index, src_sourcetype, stratum_field, stratum_value)
    ident["field_name"] = keys.norm_field_name(field_name)
    ident["field_key"] = keys.field_key(src_index, src_sourcetype, ident["stratum_field"], ident["stratum_value"], field_name)
    return ident


def sources_doc(src_index, src_sourcetype, **values):
    ident = source_identity(src_index, src_sourcetype)
    values.update(src_index=ident["src_index"], src_sourcetype=ident["src_sourcetype"])
    return kv_doc("matalog_sources", ident["source_key"], **values)


def strata_doc(src_index, src_sourcetype, stratum_field, stratum_value, **values):
    ident = stratum_identity(src_index, src_sourcetype, stratum_field, stratum_value)
    values.update(source_key=ident["source_key"], src_index=ident["src_index"], src_sourcetype=ident["src_sourcetype"],
                  stratum_field=ident["stratum_field"], stratum_value=ident["stratum_value"])
    values.setdefault("stratum_label", keys.stratum_label(ident["stratum_field"], ident["stratum_value"]))
    values.setdefault("value_kind", keys.value_kind(ident["stratum_value"]))
    values.setdefault("level", "source" if ident["stratum_value"] == keys.ALL else "stratum")
    values.setdefault("prunable", keys.prunable(ident["stratum_value"]))
    return kv_doc("matalog_strata", ident["stratum_key"], **values)


def fields_doc(src_index, src_sourcetype, stratum_field, stratum_value, field_name, **values):
    ident = field_identity(src_index, src_sourcetype, stratum_field, stratum_value, field_name)
    values.update(source_key=ident["source_key"], stratum_key=ident["stratum_key"], src_index=ident["src_index"],
                  src_sourcetype=ident["src_sourcetype"], stratum_field=ident["stratum_field"], stratum_value=ident["stratum_value"],
                  field_name=ident["field_name"])
    values.setdefault("stratum_label", keys.stratum_label(ident["stratum_field"], ident["stratum_value"]))
    values.setdefault("level", "source" if ident["stratum_value"] == keys.ALL else "stratum")
    values.setdefault("is_stratum_field", 1 if ident["field_name"] == ident["stratum_field"] else 0)
    values.setdefault("is_default", is_default_field(ident["field_name"]))
    return kv_doc("matalog_fields", ident["field_key"], **values)


def stratum_config_doc(index_pattern, src_sourcetype, stratum_field, version_field="", origin="seed", enabled=1, set_by="matalog", set_at=None):
    index_pattern = index_pattern or "*"
    return kv_doc("matalog_stratum_config", keys.k(index_pattern, src_sourcetype), index_pattern=index_pattern,
                  src_sourcetype=src_sourcetype, stratum_field=stratum_field, version_field=version_field or "",
                  origin=origin, enabled=int(enabled), set_by=set_by, set_at=set_at)


def declarations_doc(app, conf_file, stanza, attribute, **values):
    values.update(app=app, conf_file=conf_file, stanza=stanza, attribute=attribute)
    return kv_doc("matalog_declarations", keys.k(app, conf_file, stanza, attribute), **values)


def cim_coverage_doc(cim_dataset, cim_field, src_index, src_sourcetype, **values):
    ident = source_identity(src_index, src_sourcetype)
    values.update(cim_dataset=cim_dataset, cim_field=cim_field, src_index=ident["src_index"], src_sourcetype=ident["src_sourcetype"], source_key=ident["source_key"])
    return kv_doc("matalog_cim_coverage", keys.k(cim_dataset, cim_field, ident["src_index"], ident["src_sourcetype"]), **values)


def meanings_doc(field_key, revision, **values):
    values.update(field_key=field_key, revision=int(revision))
    return kv_doc("matalog_meanings", keys.k(field_key, revision), **values)


def objects_doc(ko_type, app, owner, name, **values):
    values.update(ko_type=ko_type, app=app, owner=owner, name=name)
    return kv_doc("matalog_objects", keys.k(ko_type, app, owner, name), **values)


def usage_doc(object_key, scope, field_name, ref_kind, **values):
    values.update(object_key=object_key, scope=scope, field_name=field_name, ref_kind=ref_kind)
    return kv_doc("matalog_usage", keys.k(object_key, scope, field_name, ref_kind), **values)


def semantic_types_doc(type_id, **values):
    values.setdefault("name", type_id.split(":", 1)[1] if ":" in type_id else type_id)
    return kv_doc("matalog_semantic_types", type_id, **values)


def field_types_doc(field_key, type_id, **values):
    values.update(field_key=field_key, type_id=type_id)
    return kv_doc("matalog_field_types", keys.k(field_key, type_id), **values)


def runs_doc(run_id, **values):
    return kv_doc("matalog_runs", run_id, **values)


class RunCounts(collections.OrderedDict):
    """ctx.counts: run record counters, checked against matalog_runs when set so a bad name fails in its step."""

    def __setitem__(self, column, value):
        table = COLLECTIONS["matalog_runs"]
        if column not in table:
            raise RowError("unknown column for matalog_runs: %s (counters must be matalog_runs columns)" % column)
        _check_type(column, table[column], value)
        collections.OrderedDict.__setitem__(self, column, value)


# Value encoding and the trimming order.

def _json_bytes(obj):
    return len(json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def row_bytes(row):
    """Bytes of the row as compact JSON, the size the caps are measured in."""
    return _json_bytes(row)


# Columns holding observed field values, the only ones max_value_chars truncates.
# Identity, key and id columns are stored verbatim so keys recompute from the row.
VALUE_COLUMNS = ("top_values", "sample_values", "version_top")


def truncate_value(value, max_chars):
    """A stored field value truncated to profile.max_value_chars characters."""
    text = value if isinstance(value, str) else str(value)
    return text[:int(max_chars)]


def cap_sample_values(values, max_values, max_bytes, max_chars):
    """Fill sample_values to max_values values or max_bytes bytes, whichever first.

    Values are truncated first and then de-duplicated, so the set stays
    distinct. Returns (list, truncated) where truncated is 1 when the byte cap
    stopped the fill.
    """
    out = []
    seen = set()
    used = 2
    for value in values:
        if len(out) >= int(max_values):
            break
        text = truncate_value(value, max_chars)
        if text in seen:
            continue
        cost = _json_bytes(text) + 1
        if used + cost > int(max_bytes):
            return out, 1
        out.append(text)
        seen.add(text)
        used += cost
    return out, 0


def trim_row(row, settings):
    """Apply the value caps to a summary row in the contract's order.

    Field values (VALUE_COLUMNS) are truncated to max_value_chars; sample_values
    is capped by count and bytes; top_values/top_counts entries are dropped from
    the tail until the row fits max_row_bytes. A row still over the cap after
    that loses sample_values from the tail; samples_truncated keeps meaning the
    byte cap on the sample set was hit.
    """
    max_chars = settings.profile.max_value_chars
    out = collections.OrderedDict()
    for column, value in row.items():
        if column in VALUE_COLUMNS and isinstance(value, list):
            out[column] = [truncate_value(v, max_chars) for v in value]
        else:
            out[column] = list(value) if isinstance(value, list) else value
    if "sample_values" in out and out["sample_values"]:
        capped, truncated = cap_sample_values(out["sample_values"], settings.profile.sample_values, settings.profile.sample_values_max_bytes, max_chars)
        out["sample_values"] = capped
        if truncated:
            out["samples_truncated"] = 1
    limit = settings.profile.max_row_bytes
    while row_bytes(out) > limit and out.get("top_values"):
        out["top_values"] = out["top_values"][:-1]
        if out.get("top_counts"):
            out["top_counts"] = out["top_counts"][:len(out["top_values"])]
    while row_bytes(out) > limit and out.get("sample_values"):
        out["sample_values"] = out["sample_values"][:-1]
    return out


# fieldsummary helpers.

def parse_fieldsummary_values(values_json):
    """fieldsummary values as a list of (value, count), most frequent first."""
    if not values_json:
        return []
    parsed = json.loads(values_json) if isinstance(values_json, str) else values_json
    pairs = []
    for item in parsed:
        if isinstance(item, dict):
            pairs.append((str(item.get("value", "")), int(item.get("count", 0))))
    pairs.sort(key=lambda p: -p[1])
    return pairs


def numeric_stats(fs_row):
    """numeric_count, num_min, num_max, num_mean, num_stdev from a fieldsummary row; stats None when numeric_count is 0."""
    numeric_count = int(float(fs_row.get("numeric_count") or 0))
    if numeric_count == 0:
        return {"numeric_count": 0, "num_min": None, "num_max": None, "num_mean": None, "num_stdev": None}
    out = {"numeric_count": numeric_count}
    for column, source in (("num_min", "min"), ("num_max", "max"), ("num_mean", "mean"), ("num_stdev", "stdev")):
        raw = fs_row.get(source)
        try:
            out[column] = float(raw) if raw not in (None, "") else None
        except (TypeError, ValueError):
            out[column] = None
    return out


_BOOL_VALUES = {"true", "false", "t", "f", "yes", "no", "0", "1"}


def _classify_value(value):
    text = value.strip() if isinstance(value, str) else str(value)
    if text == "":
        return "empty"
    lower = text.lower()
    if lower in ("true", "false", "t", "f", "yes", "no"):
        return "boolean"
    try:
        int(text)
        return "integer"
    except ValueError:
        pass
    try:
        float(text)
        return "float"
    except ValueError:
        return "string"


def type_guess(values):
    """string, integer, float, boolean, mixed or empty, from a sample of values."""
    kinds = set()
    for value in values:
        kind = _classify_value(value)
        if kind != "empty":
            kinds.add(kind)
    if not kinds:
        return "empty"
    if kinds == {"integer"}:
        return "integer"
    if kinds <= {"integer", "float"}:
        return "float"
    if kinds == {"boolean"}:
        return "boolean"
    if kinds == {"string"}:
        return "string"
    if len(kinds) == 1:
        return kinds.pop()
    if "string" in kinds and kinds - {"string"} == {"integer"}:
        return "mixed"
    return "mixed"


def is_identifier(count, distinct, settings, distinct_exact=1):
    """The cardinality gate: distinct >= identifier_distinct, or count >= identifier_min_count and distinct/count >= ratio.

    An inexact distinct is fieldsummary's cap, so the true count is at least
    that: the gate holds when the cap is at least identifier_distinct_cap_min.
    """
    count = int(count or 0)
    distinct = int(distinct or 0)
    p = settings.profile
    if distinct >= p.identifier_distinct:
        return 1
    if not distinct_exact and distinct >= p.identifier_distinct_cap_min:
        return 1
    if count >= p.identifier_min_count and count > 0 and float(distinct) / count >= p.identifier_distinct_ratio:
        return 1
    return 0


def rollup_distinct(children, stratum_field, probed=None):
    """(distinct, distinct_exact) of a level=source rollup over its children, each (distinct, distinct_exact, stratum_value).

    The whole-source dc() the S4 probe measured, when given, is the figure
    and exact. Without it the union over strata is unknown from per-stratum
    counts: one child keeps its own figure and exactness; the stratum field
    sums its children, whose strata partition its values, exact when every
    child is and none is a __multi__ set; any other field takes the maximum,
    inexact.
    """
    if probed is not None:
        return int(probed), 1
    if len(children) == 1:
        return int(children[0][0]), 1 if int(children[0][1] or 0) else 0
    if stratum_field:
        exact = all(int(e or 0) for _, e, _ in children) and not any(keys.is_multi(v) for _, _, v in children)
        return sum(int(d) for d, _, _ in children), 1 if exact else 0
    return max(int(d) for d, _, _ in children), 0


def values_hash(values):
    """SHA-256 (32 hex) of the sorted top value set before any truncation."""
    payload = json.dumps(sorted(str(v) for v in values), ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


def coverage(count, events):
    events = int(events or 0)
    return (float(count or 0) / events) if events > 0 else 0.0


def scan_ratio(scanned, seen):
    return float(scanned or 0) / max(int(seen or 0), 1)


def _epoch_or_none(value):
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def field_row_from_fieldsummary(run, settings, mode, shape, fs_row, src_index, src_sourcetype, stratum_field, stratum_value,
                                events_in_stratum, earliest, latest, sample_ratio, sid, origin=None, origin_app=None, window_anchor=None,
                                probe_distinct=None):
    """A kind=field row from one fieldsummary result row, with the gates and caps applied.

    fs_row carries field, count, distinct_count, is_exact, numeric_count,
    values and the numeric min, max, mean, stdev when present. probe_distinct,
    when given, is the exact dc() of the field over the same events and
    replaces a capped distinct_count.
    """
    pairs = parse_fieldsummary_values(fs_row.get("values"))
    top = [v for v, _ in pairs]
    count = int(float(fs_row.get("count") or 0))
    distinct = int(float(fs_row.get("distinct_count") or 0))
    distinct_exact = 1 if str(fs_row.get("is_exact", "0")) in ("1", "true", "True") else 0
    if probe_distinct is not None and not distinct_exact:
        distinct, distinct_exact = min(int(probe_distinct), count), 1
    identifier = is_identifier(count, distinct, settings, distinct_exact)
    values = {
        "earliest": float(earliest), "latest": float(latest), "sample_ratio": int(sample_ratio or 1),
        "events_in_stratum": int(events_in_stratum), "count": count, "distinct": distinct,
        "distinct_exact": distinct_exact,
        "type_guess": type_guess(top), "identifier": identifier, "values_hash": values_hash(top), "sid": sid,
        "window_anchor": window_anchor,
    }
    values.update(numeric_stats(fs_row))
    if shape == "full":
        # The empty string does not survive a stash line read back, so it is left out of the stored value sets.
        kept = [(v, c) for v, c in pairs if v != ""]
        if not settings.profile.store_sample_values:
            kept = []
        n = settings.profile.top_values
        values["top_values"] = [] if identifier else [v for v, _ in kept[:n]]
        values["top_counts"] = [] if identifier else [str(c) for _, c in kept[:n]]
        values["sample_values"] = [v for v, _ in kept]
        values["origin"] = origin
        values["origin_app"] = origin_app
    row = field_row(run, mode, shape, src_index, src_sourcetype, stratum_field, stratum_value, fs_row["field"], **values)
    return trim_row(row, settings)


# Rebuild mapping: a committed summary row to the KV document it implies.

def kv_from_summary(row):
    """(collection, partial doc) for a kind=source, stratum or field summary row; None for other kinds.

    This is the mapping rebuild and crash replay use, and the one S1, S3 and S4
    produce for the same rows, so KV state is reproducible from the index.
    first_seen_run is the row's run_id: writer.apply_roll keeps the earliest
    value, so replaying rows oldest first leaves the earliest run read. Slim
    rows carry no numeric stats, values or samples.
    """
    kind = row.get("kind")
    run_id = row["run_id"]
    if kind == "source":
        events = max(_int_or_none(row.get("events_last_cycle")) or 0, _int_or_none(row.get("daily_events")) or 0)
        values = dict(
            profiled_as=row.get("profiled_as"), first_seen_run=run_id,
            events_last_cycle=_int_or_none(row.get("events_last_cycle")), daily_events=_int_or_none(row.get("daily_events")),
            daily_bytes=_int_or_none(row.get("daily_bytes")), last_event_time=_epoch_or_none(row.get("last_event_time")),
            updated_run_id=run_id)
        if events > 0:
            values["last_seen_run"] = run_id
        # Empty lists must not clear stored values written by a later step.
        for column in ("config_apps", "version_top", "version_top_counts"):
            listed = _list(row.get(column))
            if listed:
                values[column] = listed
        return "matalog_sources", sources_doc(row["src_index"], row["src_sourcetype"], **values)
    if kind == "stratum":
        if row.get("mode") == "listing":
            # Listing rows become strata state through steps.s10_commit.listing_strata, never a discovery snapshot.
            return None
        common = dict(prunable=_int_or_none(row.get("prunable")), first_seen_run=run_id, updated_run_id=run_id)
        if row.get("mode") == "profile":
            common["last_profiled_run"] = run_id
        else:
            common.update(version_top=_list(row.get("version_top")), version_top_counts=_list(row.get("version_top_counts")),
                          last_discovered_run=run_id, cur_run_id=run_id, cur_earliest=_epoch_or_none(row.get("earliest")),
                          cur_latest=_epoch_or_none(row.get("latest")), cur_events_seen=_int_or_none(row.get("events_seen")),
                          cur_events_scanned=_int_or_none(row.get("events_scanned")), cur_scan_ratio=_float_or_none(row.get("scan_ratio")),
                          cur_fields_found=_int_or_none(row.get("fields_found")), cur_truncated=_int_or_none(row.get("truncated")),
                          cur_fields_truncated=_int_or_none(row.get("fields_truncated")), window_anchor=row.get("window_anchor") or None)
        return "matalog_strata", strata_doc(row["src_index"], row["src_sourcetype"], row["stratum_field"], row["stratum_value"], **common)
    if kind == "field":
        prefix = "cur_prof_" if row.get("mode") == "profile" else "cur_disc_"
        doc = {
            prefix + "run_id": run_id, prefix + "count": _int_or_none(row.get("count")), prefix + "events": _int_or_none(row.get("events_in_stratum")),
            prefix + "coverage": _float_or_none(row.get("coverage")), prefix + "distinct": _int_or_none(row.get("distinct")),
            "observed": 1, "presence": "present", "first_seen_run": run_id, "last_seen_run": run_id,
            "last_seen_time": _epoch_or_none(row.get("latest")),
            "type_guess": row.get("type_guess"), "identifier": _int_or_none(row.get("identifier")),
            "values_hash": row.get("values_hash"), "updated_run_id": run_id,
        }
        if row.get("mode") == "profile":
            doc["cur_prof_distinct_exact"] = _int_or_none(row.get("distinct_exact"))
            doc["cur_prof_sample_ratio"] = _int_or_none(row.get("sample_ratio"))
        else:
            doc["window_anchor"] = row.get("window_anchor") or None
        if row.get("shape") == "full":
            # Numeric stats, values and samples come from the newest full row only.
            doc.update(profile_id=row.get("profile_id"), top_values=_list(row.get("top_values")), top_counts=_list(row.get("top_counts")),
                       sample_values=_list(row.get("sample_values")), samples_truncated=_int_or_none(row.get("samples_truncated")),
                       numeric_count=_int_or_none(row.get("numeric_count")), num_min=_float_or_none(row.get("num_min")),
                       num_max=_float_or_none(row.get("num_max")), num_mean=_float_or_none(row.get("num_mean")))
            if row.get("origin"):
                doc["origin"] = row.get("origin")
                doc["origin_app"] = row.get("origin_app") or ""
        return "matalog_fields", fields_doc(row["src_index"], row["src_sourcetype"], row["stratum_field"], row["stratum_value"], row["field_name"], **doc)
    return None


def _int_or_none(value):
    if value is None or value == "":
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _float_or_none(value):
    return _epoch_or_none(value)


def _list(value):
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]
