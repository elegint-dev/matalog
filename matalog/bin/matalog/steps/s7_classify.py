"""S7 classify.

Inputs: lookups/matalog_semantic_types_shipped.csv, the stored
matalog_semantic_types rows, this run's full kind=field rows in ctx.summary,
ctx.previous_run["type_versions"], and for reclassify the latest committed
full kind=field row per field read through writer.latest_full_rows_spl.

Rollup rows have no full row; they are classified from the sample_values
of the rollup doc staged this run (reclassify and rebuild read the stored
rollup docs), with cur_profile_id empty.

Outputs: matalog_semantic_types docs (the shipped rows reseeded with
origin=shipped and type_version recomputed, enabled kept from the stored row;
a user row gets its type_version written back when it differs);
matalog_field_types edges under the rules of the contract's Field-to-type
edge section; best_type_id, best_type_rate and types on matalog_fields;
ctx.counts type_versions, type_versions_hash and reclassified_types, with
type_versions_hash also on ctx.run_record for the commit row.

Regex types are matched with re.search on the pattern as written (the
contract requires anchors), DOTALL, case-insensitive unless case_sensitive;
a type with name_pattern is tested only on fields whose name re.search
matches it, case-insensitive, and counts as untested elsewhere;
enum types compare the value, lowercased unless case_sensitive, with
enum_values; lookup types read the lookup's column once per run through one
inputlookup job. A type whose matcher cannot be built is recorded in
ctx.errors and left out of the run, so its edges and version are not touched.
"""
import collections
import csv
import json
import os
import re

from .. import budget as budget_mod
from .. import keys
from .. import rows as rows_mod
from .. import writer as writer_mod
from ..runner import Step

STEP = "S7"
TYPES = "matalog_semantic_types"
EDGES = "matalog_field_types"
FIELDS = "matalog_fields"
SHIPPED_CSV = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "lookups", "matalog_semantic_types_shipped.csv")
SHIPPED_AUTHOR = "matalog"
ENUM_SEPARATOR = "|"
MATCHER_KINDS = ("regex", "enum", "lookup")
KV_CHUNK = 500
EDGE_IDENTITY = ("src_index", "src_sourcetype", "stratum_value", "field_name", "level")
# Stored rollup columns S7 reads for reclassify.
ROLLUP_COLUMNS = ("_key", "field_key", "src_index", "src_sourcetype", "stratum_value", "field_name", "level", "is_rollup", "presence",
                  "sample_values", "cur_prof_run_id")
# Columns of a type row that type_version covers, in hash order.
VERSIONED = ("matcher_kind", "pattern", "enum_values", "lookup_name", "lookup_field", "case_sensitive", "match_threshold", "min_distinct",
             "name_pattern")


def _empty(value):
    return value is None or value == "" or value == []


def _int(value, default=None):
    if _empty(value):
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return 1 if value.strip().lower() == "true" else 0
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _float(value, default=None):
    if _empty(value):
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _list(value):
    if _empty(value):
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def _chunks(items, size=KV_CHUNK):
    items = list(items)
    for start in range(0, len(items), size):
        yield items[start:start + size]


# Type rows.

def normalize_type(doc, settings):
    """A type row with every column typed and the classify defaults filled in; None when it has no usable identity."""
    type_id = doc.get("type_id") or doc.get("_key")
    if _empty(type_id):
        return None
    c = settings.classify
    out = collections.OrderedDict()
    out["_key"] = str(type_id)
    out["type_id"] = str(type_id)
    out["name"] = str(doc.get("name") or (str(type_id).split(":", 1)[1] if ":" in str(type_id) else str(type_id)))
    for column in ("label", "description", "pattern", "name_pattern", "enum_source", "lookup_name", "lookup_field", "parent_type_id", "author"):
        out[column] = "" if _empty(doc.get(column)) else str(doc.get(column))
    out["origin"] = "user" if doc.get("origin") == "user" else "shipped"
    out["enabled"] = 1 if _int(doc.get("enabled"), 1) != 0 else 0
    out["matcher_kind"] = str(doc.get("matcher_kind") or "regex")
    out["enum_values"] = _list(doc.get("enum_values"))
    out["case_sensitive"] = 1 if _int(doc.get("case_sensitive"), 0) == 1 else 0
    out["match_threshold"] = _float(doc.get("match_threshold"), float(c.default_match_threshold))
    out["min_distinct"] = _int(doc.get("min_distinct"), int(c.default_min_distinct))
    out["specificity"] = _int(doc.get("specificity"), 0)
    out["updated_at"] = _float(doc.get("updated_at"))
    out["type_version"] = type_version(out)
    return out


def type_version(doc):
    """keys.k over the VERSIONED columns: enum_values as a compact JSON array, case_sensitive as 0 or 1, numbers in keys.num_text form.

    name_pattern is appended only when set, so a type without one keeps its version.
    """
    parts = [
        doc.get("matcher_kind") or "", doc.get("pattern") or "",
        json.dumps(_list(doc.get("enum_values")), ensure_ascii=False, separators=(",", ":")),
        doc.get("lookup_name") or "", doc.get("lookup_field") or "",
        "1" if _int(doc.get("case_sensitive"), 0) == 1 else "0",
        keys.num_text(doc.get("match_threshold")), keys.num_text(doc.get("min_distinct"))]
    if doc.get("name_pattern"):
        parts.append(str(doc["name_pattern"]))
    return keys.k(*parts)


def type_versions_hash(type_versions):
    return keys.sha32(json.dumps(type_versions, sort_keys=True, separators=(",", ":"), ensure_ascii=False))


def read_shipped(path=SHIPPED_CSV):
    """The shipped type rows from the CSV, as raw dicts; enum_values are split on ENUM_SEPARATOR."""
    out = []
    with open(path, "r", encoding="utf-8", newline="") as handle:
        for raw in csv.DictReader(handle):
            doc = collections.OrderedDict((k, v) for k, v in raw.items() if k is not None)
            doc["enum_values"] = [v for v in (doc.get("enum_values") or "").split(ENUM_SEPARATOR) if v != ""]
            doc["origin"] = "shipped"
            out.append(doc)
    return out


def shipped_doc(normalized, stored, now):
    """The matalog_semantic_types document of one shipped row: stored enabled kept, updated_at kept while the version stands."""
    doc = collections.OrderedDict(normalized)
    doc.pop("_key")
    stored = stored or {}
    doc["origin"] = "shipped"
    doc["author"] = SHIPPED_AUTHOR
    doc["enabled"] = 1 if _int(stored.get("enabled"), 1) != 0 else 0
    if stored.get("type_version") == doc["type_version"] and _float(stored.get("updated_at")) is not None:
        doc["updated_at"] = _float(stored.get("updated_at"))
    else:
        doc["updated_at"] = float(now)
    return rows_mod.semantic_types_doc(doc.pop("type_id"), **doc)


def load_types(ctx, reseed=True, path=SHIPPED_CSV):
    """Every type row in force this run as normalized docs by type_id, with the shipped rows reseeded through ctx.stage_kv.

    User rows come from the store; a user row whose stored type_version is
    not the recomputed one gets the recomputed value staged.
    """
    settings = ctx.settings
    stored = collections.OrderedDict()
    for doc in ctx.client.kv_query(TYPES):
        key = doc.get("_key") or doc.get("type_id")
        if key:
            stored[str(key)] = doc
    types = collections.OrderedDict()
    if reseed:
        for raw in read_shipped(path):
            normalized = normalize_type(raw, settings)
            if normalized is None:
                continue
            doc = shipped_doc(normalized, stored.get(normalized["type_id"]), ctx.now)
            ctx.stage_kv(TYPES, doc)
            normalized["enabled"] = doc["enabled"]
            normalized["updated_at"] = doc["updated_at"]
            types[normalized["type_id"]] = normalized
    for key, doc in stored.items():
        if key in types:
            continue
        normalized = normalize_type(doc, settings)
        if normalized is None:
            continue
        if doc.get("origin") == "user" and doc.get("type_version") != normalized["type_version"]:
            ctx.stage_kv(TYPES, rows_mod.kv_doc(TYPES, key, type_version=normalized["type_version"]))
        types[key] = normalized
    return types


# Matchers.

class Matcher(object):
    """One enabled type's test over a value list, gated by the field name when the type has a name_pattern."""

    def __init__(self, doc, test, name_test=None):
        self.doc = doc
        self.type_id = doc["type_id"]
        self.version = doc["type_version"]
        self.specificity = int(doc.get("specificity") or 0)
        self.threshold = float(doc["match_threshold"])
        self.min_distinct = int(doc["min_distinct"])
        self.test = test
        self.name_test = name_test

    def run(self, values, field_name=""):
        """(tested, matched) over the values; (0, 0) when the field name fails the type's name_pattern."""
        if self.name_test is not None and self.name_test.search(str(field_name or "")) is None:
            return 0, 0
        matched = 0
        for value in values:
            if self.test(value):
                matched += 1
        return len(values), matched


def regex_matcher(doc):
    flags = re.DOTALL | (0 if doc.get("case_sensitive") else re.IGNORECASE)
    compiled = re.compile(doc.get("pattern") or "", flags)
    return lambda value: compiled.search(value) is not None


def enum_matcher(values, case_sensitive):
    if case_sensitive:
        allowed = set(str(v) for v in values)
        return lambda value: value in allowed
    allowed = set(str(v).lower() for v in values)
    return lambda value: value.lower() in allowed


def _spl_quote(text):
    return '"' + str(text).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _eval_field(name):
    return "'" + str(name).replace("'", "\\'") + "'"


def lookup_spl(lookup_name, lookup_field):
    return "| inputlookup %s | dedup %s | table %s" % (_spl_quote(lookup_name), _eval_field(lookup_field), _eval_field(lookup_field))


def lookup_values(ctx, doc):
    """The distinct values of a lookup type's column, through one inputlookup job; raises on a failed read."""
    name, column = doc.get("lookup_name") or "", doc.get("lookup_field") or ""
    if not name or not column:
        raise ValueError("lookup type without lookup_name and lookup_field")
    limit = int(ctx.settings.classify.max_lookup_values)
    result = ctx.client.search(lookup_spl(name, column), step=STEP, subject_key=doc["type_id"], max_rows=limit)
    if not result.ok:
        raise ValueError("inputlookup %s %s" % (name, result.status))
    out = []
    for row in result.results:
        value = row.get(column)
        for item in (value if isinstance(value, list) else [value]):
            if not _empty(item):
                out.append(str(item))
    return out[:limit]


def build_matchers(ctx, types):
    """Matcher per enabled type, in specificity order; a type whose matcher cannot be built is recorded and left out."""
    out = collections.OrderedDict()
    for type_id, doc in types.items():
        if _int(doc.get("enabled"), 1) != 1:
            continue
        kind = doc.get("matcher_kind")
        try:
            if kind == "regex":
                test = regex_matcher(doc)
            elif kind == "enum":
                test = enum_matcher(doc.get("enum_values") or [], doc.get("case_sensitive"))
            elif kind == "lookup":
                test = enum_matcher(lookup_values(ctx, doc), doc.get("case_sensitive"))
            else:
                raise ValueError("matcher_kind must be one of %s" % (MATCHER_KINDS,))
            name_test = re.compile(doc["name_pattern"], re.IGNORECASE) if doc.get("name_pattern") else None
        except budget_mod.BudgetExhausted as exc:
            ctx.error(STEP, type_id, "budget ceiling %s" % exc.ceiling)
            continue
        except Exception as exc:
            ctx.error(STEP, type_id, "matcher not built: %s: %s" % (exc.__class__.__name__, exc))
            continue
        out[type_id] = Matcher(doc, test, name_test)
    return collections.OrderedDict(sorted(out.items(), key=lambda item: (-item[1].specificity, item[0])))


# Classification of one field.

class Subject(object):
    """One field to classify: identity, the row whose sample_values are tested, and the source label."""

    def __init__(self, field_key, identity, profile_id, sample_values, source):
        self.field_key = field_key
        self.identity = identity
        self.profile_id = profile_id or ""
        self.values = [str(v).strip() for v in (sample_values or []) if not _empty(v)]
        self.source = source


def subject_from_rollup(doc, run_id, source=None):
    """A Subject from a level=source rollup doc, whose sample_values are the union over its children; no profile row to point at."""
    identity = collections.OrderedDict()
    for column in EDGE_IDENTITY:
        identity[column] = "source" if column == "level" else str(doc.get(column) or (keys.ALL if column == "stratum_value" else ""))
    if source is None:
        source = "profile" if str(doc.get("cur_prof_run_id") or "") == run_id else "discovery"
    return Subject(str(doc.get("field_key") or doc.get("_key") or ""), identity, "", doc.get("sample_values"), source)


def subject_from_row(row, source=None):
    """A Subject from a full kind=field row (staged this run or read back from the index)."""
    identity = collections.OrderedDict()
    for column in EDGE_IDENTITY:
        if column == "level":
            identity[column] = "source" if row.get("stratum_value") == keys.ALL else "stratum"
        else:
            identity[column] = str(row.get(column) or "")
    if source is None:
        source = "profile" if row.get("mode") == "profile" else "discovery"
    return Subject(str(row.get("field_key") or ""), identity, row.get("profile_id"), row.get("sample_values"), source)


class Outcome(object):
    """What one type found for one field."""

    def __init__(self, matcher, tested, matched):
        self.matcher = matcher
        self.type_id = matcher.type_id
        self.tested = int(tested)
        self.matched = int(matched)
        self.rate = (float(matched) / tested) if tested > 0 else 0.0
        self.is_match = 1 if tested >= matcher.min_distinct and self.rate >= matcher.threshold and tested > 0 else 0
        self.specificity = matcher.specificity


def stored_match(edge, matcher):
    """An Outcome taken from a stored edge of a type not evaluated this run, when its version is still the type's."""
    if edge.get("cur_type_version") != matcher.version:
        return None
    tested, matched = _int(edge.get("cur_tested"), 0), _int(edge.get("cur_matched"), 0)
    return Outcome(matcher, tested, matched)


def classify_subject(ctx, subject, matchers, evaluated, stored_edges):
    """Stage the edges and the field row columns of one subject.

    evaluated names the matchers run against the values; the other matchers
    contribute their stored edge's outcome when its version is current. Edges
    are written for the evaluated types that meet the contract's store rules
    and for a stored edge whose is_best flag changes. The per-field cap
    applies to types without a stored edge only: an evaluated type whose
    stored edge was a match or at the floor is always rewritten, so no stored
    is_match=1 outlives the values it was tested on.
    """
    c = ctx.settings.classify
    floor = float(c.edge_store_floor)
    outcomes = collections.OrderedDict()
    for type_id, matcher in matchers.items():
        if type_id in evaluated:
            tested, matched = matcher.run(subject.values, subject.identity.get("field_name"))
            outcomes[type_id] = Outcome(matcher, tested, matched)
        elif type_id in stored_edges:
            outcome = stored_match(stored_edges[type_id], matcher)
            if outcome is not None:
                outcomes[type_id] = outcome
    matches = [o for o in outcomes.values() if o.is_match]
    matches.sort(key=lambda o: (-o.specificity, o.type_id))
    best = matches[0] if matches else None
    chosen = []
    for type_id in evaluated:
        outcome = outcomes.get(type_id)
        if outcome is None:
            continue
        stored = stored_edges.get(type_id) or {}
        refresh = (_int(stored.get("is_match"), 0) == 1 or (_float(stored.get("cur_match_rate")) or 0.0) >= floor
                   or (_float(stored.get("base_match_rate")) or 0.0) >= floor)
        wanted = refresh or outcome.rate >= floor or (best is not None and type_id == best.type_id)
        if wanted:
            chosen.append((outcome, refresh))
    chosen.sort(key=lambda o: (0 if best is not None and o[0].type_id == best.type_id else 1, -o[0].rate, -o[0].specificity, o[0].type_id))
    cap = max(1, int(c.max_types_per_field))
    kept = [o for o, refresh in chosen if refresh]
    kept += [o for o, refresh in chosen if not refresh][:max(0, cap - len(kept))]
    if best is not None and best.type_id in [o.type_id for o, _ in chosen] and best.type_id not in [o.type_id for o in kept]:
        kept.insert(0, next(o for o, _ in chosen if o.type_id == best.type_id))
    chosen = kept
    chosen_ids = set(o.type_id for o in chosen)
    for outcome in chosen:
        stored = stored_edges.get(outcome.type_id) or {}
        values = collections.OrderedDict(subject.identity)
        values.update(cur_run_id=ctx.run_id, cur_type_version=outcome.matcher.version, cur_profile_id=subject.profile_id,
                      cur_tested=outcome.tested, cur_matched=outcome.matched, cur_match_rate=outcome.rate,
                      is_match=outcome.is_match, is_best=1 if best is not None and outcome.type_id == best.type_id else 0,
                      source=subject.source)
        if outcome.is_match and _empty(stored.get("first_match_run")):
            values["first_match_run"] = ctx.run_id
        ctx.stage_kv(EDGES, rows_mod.field_types_doc(subject.field_key, outcome.type_id, **values))
    for type_id, edge in stored_edges.items():
        if type_id in chosen_ids or type_id not in matchers:
            continue
        flag = 1 if best is not None and type_id == best.type_id else 0
        if _int(edge.get("is_best"), 0) != flag:
            ctx.stage_kv(EDGES, rows_mod.field_types_doc(subject.field_key, type_id, is_best=flag))
    listed = [o.type_id for o in matches if o.type_id in chosen_ids or (o.type_id in stored_edges and o.type_id not in evaluated)]
    ctx.stage_kv(FIELDS, rows_mod.kv_doc(FIELDS, subject.field_key, best_type_id=best.type_id if best else "",
                                          best_type_rate=best.rate if best else None, types=listed))
    return best


def stored_edges_for(ctx, field_keys):
    """field_key -> {type_id: stored edge doc} for the given fields."""
    out = collections.defaultdict(dict)
    for chunk in _chunks(field_keys):
        for doc in ctx.client.kv_query(EDGES, query={"field_key": {"$in": chunk}}):
            if doc.get("field_key") and doc.get("type_id"):
                out[doc["field_key"]][doc["type_id"]] = doc
    return out


def classify_subjects(ctx, subjects, matchers, evaluated):
    """Classify every subject against the evaluated matchers; returns the number of subjects classified."""
    subjects = [s for s in subjects if s.field_key]
    edges = stored_edges_for(ctx, [s.field_key for s in subjects])
    for subject in subjects:
        classify_subject(ctx, subject, matchers, evaluated, edges.get(subject.field_key, {}))
    return len(subjects)


# The step.

def full_rows_this_run(ctx):
    """field_key -> the full kind=field row S7 tests this run; a profile row wins over a discovery row of the same field."""
    out = collections.OrderedDict()
    for row in ctx.summary.get("field", []):
        if row.get("shape") != "full" or _empty(row.get("field_key")):
            continue
        current = out.get(row["field_key"])
        if current is None or (row.get("mode") == "profile" and current.get("mode") != "profile"):
            out[row["field_key"]] = row
    return out


def rollups_this_run(ctx):
    """field_key -> the rollup docs staged this run with a sample set, merged onto their stored doc."""
    out = collections.OrderedDict()
    staged = [(k, d) for k, d in ctx.kv[FIELDS].items() if _int(d.get("is_rollup"), 0) == 1]
    stored = ctx.existing(FIELDS, [k for k, _ in staged]) if staged else {}
    for key, doc in staged:
        merged = collections.OrderedDict(stored.get(key) or {})
        merged.update((c, v) for c, v in doc.items() if v is not None)
        if merged.get("sample_values") and merged.get("presence", "present") == "present":
            out[key] = merged
    return out


def stored_rollups(ctx):
    """Every stored present rollup doc with a sample set, by key."""
    out = collections.OrderedDict()
    for doc in ctx.client.kv_query(FIELDS, query={"is_rollup": 1, "presence": "present"}, fields=list(ROLLUP_COLUMNS)):
        if doc.get("_key") and doc.get("sample_values"):
            out[doc["_key"]] = doc
    return out


def changed_types(matchers, previous_run):
    """Type ids whose version differs from the previous committed run's type_versions, or that it did not list."""
    previous = (previous_run or {}).get("type_versions")
    if not isinstance(previous, dict):
        previous = {}
    return [type_id for type_id, m in matchers.items() if previous.get(type_id) != m.version]


def read_latest_full_rows(ctx):
    """The latest committed full kind=field row per field from the index, as summary rows; None when the read failed."""
    max_rows = int(ctx.settings.rebuild.rebuild_max_rows)
    try:
        result = ctx.client.search(writer_mod.latest_full_rows_spl(max_rows), step=STEP, subject_key="reclassify", max_rows=max_rows)
    except budget_mod.BudgetExhausted as exc:
        ctx.error(STEP, "reclassify", "budget ceiling %s" % exc.ceiling)
        return None
    except Exception as exc:
        ctx.error(STEP, "reclassify", "full row read raised %s: %s" % (exc.__class__.__name__, exc))
        return None
    if not result.ok:
        ctx.error(STEP, "reclassify", "full row read %s" % result.status)
        return None
    if len(result.results) >= max_rows:
        ctx.error(STEP, "reclassify", "rebuild.rebuild_max_rows reached; reclassify is incomplete")
    out = []
    for raw in result.results:
        row = writer_mod.summary_row_from_result(raw)
        if row and row.get("shape") == "full":
            out.append(row)
    return out


def existing_field_keys(ctx, field_keys):
    """The field_keys that have a matalog_fields row now or staged this run."""
    staged = set(ctx.kv[FIELDS])
    deleted = ctx.kv_deletes[FIELDS]
    found = set(k for k in field_keys if k in staged)
    rest = [k for k in field_keys if k not in found and k not in deleted]
    for chunk in _chunks(rest):
        for doc in ctx.client.kv_query(FIELDS, query={"_key": {"$in": chunk}}, fields=["_key"]):
            if doc.get("_key"):
                found.add(doc["_key"])
    return set(k for k in found if k not in deleted)


class Classify(Step):
    """Semantic types over the full kind=field rows of this run, and reclassify for changed types; see the module docstring.

    ctx.state["classify"]: {"types", "enabled", "classified", "reclassified_types", "reclassified"}.
    """

    name = STEP
    label = "classify"

    def run(self, ctx):
        types = load_types(ctx)
        matchers = build_matchers(ctx, types)
        versions = collections.OrderedDict((type_id, m.version) for type_id, m in matchers.items())
        state = collections.OrderedDict([("types", len(types)), ("enabled", len(matchers)), ("classified", 0),
                                         ("reclassified_types", []), ("reclassified", 0)])
        ctx.state["classify"] = state
        self.record_versions(ctx, versions)
        if not matchers:
            return
        this_run = full_rows_this_run(ctx)
        rollups = rollups_this_run(ctx)
        subjects = [subject_from_row(r) for r in this_run.values()]
        subjects += [subject_from_rollup(d, ctx.run_id) for k, d in rollups.items() if k not in this_run]
        state["classified"] = classify_subjects(ctx, subjects, matchers, list(matchers))
        changed = changed_types(matchers, ctx.previous_run)
        if not changed or ctx.run_mode != "normal":
            return
        rows = read_latest_full_rows(ctx)
        if rows is None:
            return
        done = set(this_run) | set(rollups)
        subjects = [subject_from_row(r, source="reclassify") for r in rows if r.get("field_key") not in done]
        live = existing_field_keys(ctx, [s.field_key for s in subjects])
        subjects = [s for s in subjects if s.field_key in live]
        subjects += [subject_from_rollup(d, ctx.run_id, source="reclassify") for k, d in stored_rollups(ctx).items()
                     if k not in done and k not in ctx.kv_deletes[FIELDS]]
        state["reclassified"] = classify_subjects(ctx, subjects, matchers, changed)
        state["reclassified_types"] = list(changed)
        ctx.counts["reclassified_types"] = list(changed)

    def record_versions(self, ctx, versions):
        digest = type_versions_hash(versions)
        ctx.counts["type_versions"] = dict(versions)
        ctx.counts["type_versions_hash"] = digest
        ctx.counts["reclassified_types"] = []
        if ctx.run_record is not None:
            ctx.run_record["type_versions"] = dict(versions)
            ctx.run_record["type_versions_hash"] = digest


def rebuild_edges(ctx, full_rows):
    """Rebuild mode: matalog_field_types and the field type columns from the latest full rows, against the stored types.

    The shipped rows are not reseeded here; the types in force are the stored ones.
    """
    types = load_types(ctx, reseed=False)
    matchers = build_matchers(ctx, types)
    versions = collections.OrderedDict((type_id, m.version) for type_id, m in matchers.items())
    Classify().record_versions(ctx, versions)
    if not matchers:
        return 0
    subjects = []
    seen = set()
    for raw in full_rows:
        row = writer_mod.summary_row_from_result(raw)
        if not row or row.get("shape") != "full" or row.get("field_key") in seen or _empty(row.get("field_key")):
            continue
        seen.add(row["field_key"])
        subjects.append(subject_from_row(row))
    live = existing_field_keys(ctx, [s.field_key for s in subjects])
    subjects = [s for s in subjects if s.field_key in live]
    subjects += [subject_from_rollup(d, ctx.run_id) for k, d in rollups_this_run(ctx).items() if k not in seen]
    return classify_subjects(ctx, subjects, matchers, list(matchers))
