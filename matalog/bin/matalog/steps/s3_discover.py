"""S3 discover."""
import collections

from .. import budget as budget_mod
from .. import keys
from .. import rows
from ..runner import Step

KV_CHUNK = 100
PRESENCE_UNTOUCHED = ("retired", "declared_only")
# Stratum states S3 searches.
DISCOVERABLE_STATES = ("active",)
# The stored matalog_fields columns S3 reads; base_* and profile snapshots are left out.
# The KV store returns _key only when a projection names it.
STORED_FIELD_COLUMNS = (
    "_key", "field_key", "source_key", "stratum_key", "field_name", "level", "is_rollup", "rollup_strata", "presence",
    "observed", "declared", "first_seen_run", "last_seen_run", "last_seen_time", "consecutive_unseen", "origin", "origin_app",
    "cur_disc_run_id", "cur_disc_count", "cur_disc_events", "cur_disc_coverage", "cur_disc_distinct",
    "type_guess", "identifier", "numeric_count", "num_min", "num_max", "num_mean",
    "top_values", "top_counts", "sample_values", "samples_truncated", "values_hash", "updated_run_id")


def _spl_quote(text):
    return '"' + str(text).replace("\\", "\\\\").replace('"', '\\"') + '"'


def discovery_spl(settings, src_index, search_sourcetype, stratum_field, stratum_value):
    """The one search of a discovery: source, stratum filter, head, matalog_n, fieldsummary."""
    spl = "search index=%s sourcetype=%s" % (_spl_quote(src_index), _spl_quote(search_sourcetype))
    stratum_filter = keys.stratum_filter(stratum_field, stratum_value)
    if stratum_filter:
        spl += " " + stratum_filter
    return "%s | head %d | eval matalog_n=1 | fieldsummary maxvals=%d" % (
        spl, int(settings.discovery.discovery_head_events), int(settings.profile.sample_values))


def _empty(value):
    return value is None or value == "" or value == []


def _int(value, default=0):
    if _empty(value):
        return default
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _float(value, default=0.0):
    if _empty(value):
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _overlay(*layers):
    """Later layers win, column by column; None values never overwrite."""
    out = collections.OrderedDict()
    for layer in layers:
        for column, value in (layer or {}).items():
            if value is not None:
                out[column] = value
    return out


def _chunks(items, size):
    items = list(items)
    for start in range(0, len(items), size):
        yield items[start:start + size]


def _state_strata(ctx):
    """ctx.state["strata"] as source_key -> list of docs, or None when S2 left nothing."""
    raw = ctx.state.get("strata")
    if raw is None:
        return None
    grouped = collections.OrderedDict()
    if isinstance(raw, dict):
        for source_key, docs in raw.items():
            grouped[source_key] = list(docs.values()) if isinstance(docs, dict) else list(docs or [])
        return grouped
    for doc in raw:
        grouped.setdefault(doc.get("source_key"), []).append(doc)
    return grouped


def is_stratified(source):
    field = source.get("stratum_field")
    return not _empty(field) and field != keys.ALL


def entered(before, after, max_chars):
    """A value in after that a non-empty before did not hold, both compared as stored (truncated)."""
    before = [rows.truncate_value(v, max_chars) for v in (before or [])]
    if not before:
        return False
    return any(rows.truncate_value(v, max_chars) not in before for v in (after or []))


def merge_top(entries, n):
    """Merge (values, counts) lists by summed count: the n most frequent, ties by value."""
    totals = collections.OrderedDict()
    for values, counts in entries:
        for value, count in zip(values or [], counts or []):
            totals[str(value)] = totals.get(str(value), 0) + _int(count)
    ordered = sorted(totals.items(), key=lambda kv: (-kv[1], kv[0]))[:int(n)]
    return [v for v, _ in ordered], [str(c) for _, c in ordered]


def majority_type(guesses):
    """The type_guess more than half of the children share, else mixed; empty with no children."""
    counts = collections.Counter(g for g in guesses if g)
    if not counts:
        return "empty"
    guess, count = counts.most_common(1)[0]
    return guess if count * 2 > sum(counts.values()) else "mixed"


class Candidate(object):
    """One active stratum S3 may discover this run: its source and stratum views, plan order keys, job outcome."""

    def __init__(self, source, stratum, run_id):
        self.source = source
        self.stratum = stratum
        self.key = stratum["_key"]
        self.source_key = source["_key"]
        self.src_index = source["src_index"]
        self.src_sourcetype = source["src_sourcetype"]
        self.stratum_field = stratum.get("stratum_field") or keys.ALL
        self.stratum_value = stratum.get("stratum_value") or keys.ALL
        self.priority = _float(source.get("priority"))
        self.rate = _float(stratum.get("rate_per_hour"))
        due_run = stratum.get("discovery_due_run")
        self.due = _empty(due_run) or str(due_run) <= run_id
        # An anchored first discovery: the source is plan_anchor and this stratum has never been discovered (or was, by a rerun of this run).
        discovered = stratum.get("last_discovered_run")
        self.anchor = (bool(source.get("plan_anchor")) and (_empty(discovered) or str(discovered) == run_id)
                       and not _empty(source.get("last_event_time")))
        self.planned = False
        self.result = None
        self.discovery = None

    def search_sourcetype(self):
        return self.source.get("search_sourcetype") or self.src_sourcetype

    def window(self, ctx):
        """(earliest, latest) of this discovery: the slot window, or the anchored one ending at last_event_time."""
        if self.anchor:
            return keys.anchored_window(ctx.settings, self.source.get("last_event_time"))
        return ctx.windows["discovery"]

    def window_anchor(self):
        return rows.ANCHOR_LAST_EVENT if self.anchor else None


class Discovery(object):
    """What one finished discovery job yielded, before any row is staged."""

    def __init__(self, candidate, result, settings):
        self.candidate = candidate
        self.result = result
        by_field = collections.OrderedDict()
        for fs_row in result.results:
            name = fs_row.get("field")
            if name is None or name == "":
                continue
            by_field[name] = fs_row
        n_row = by_field.pop("matalog_n", None)
        self.events_seen = _int(n_row.get("count")) if n_row else 0
        self.events_scanned = int(result.scan_count or 0)
        self.truncated = 1 if self.events_seen >= int(settings.discovery.discovery_head_events) else 0
        fields = list(by_field.values())
        self.fields_found = len(fields)
        cap = int(settings.discovery.max_fields_per_stratum)
        self.fields_over_cap = max(0, self.fields_found - cap)
        if self.fields_over_cap:
            fields.sort(key=lambda r: (-_int(r.get("count")), r["field"]))
            fields = fields[:cap]
        self.fields_truncated = 1 if self.fields_over_cap else 0
        self.fields = fields
        self.version_top, self.version_top_counts = [], []
        version_field = candidate.source.get("version_field")
        if not _empty(version_field) and version_field in by_field:
            pairs = rows.parse_fieldsummary_values(by_field[version_field].get("values"))
            max_chars = settings.profile.max_value_chars
            self.version_top, self.version_top_counts = merge_top(
                [([rows.truncate_value(v, max_chars) for v, _ in pairs], [c for _, c in pairs])], settings.profile.top_values)
        self.scan_ratio = rows.scan_ratio(self.events_scanned, self.events_seen)


class Discover(Step):
    """Unsampled discovery of every active stratum due this run, inside the budget.

    Inputs: ctx.state["sources"] and ["strata"]; ctx.windows["discovery"]
    (keys.anchored_window for a plan_anchor source's undiscovered strata, whose
    rows then carry window_anchor=last_event);
    ctx.budget.plannable() for the number of jobs S3 may plan; the stored
    matalog_strata and matalog_fields rows for discovery_due_run, first_seen_run
    and consecutive_unseen. Plan order: every active stratum whose
    discovery_due_run is this run or earlier, then the rest by source priority
    and rate_per_hour descending. Strata that are not due are planned only
    in what is left after the searches S4 will use for the strata due this run
    (profile_need, capped at what is left after the due discoveries), so
    discovery ahead of schedule never starves a profile and a profile backlog
    holds only what S4 can use. Each job: the source search plus
    keys.stratum_filter, `| head discovery.discovery_head_events | eval matalog_n=1
    | fieldsummary maxvals=profile.sample_values`, run through ctx.budget.map
    with step "S3" and the stratum_key as subject.

    Outputs: one kind=stratum mode=discovery row per searched stratum
    (rows.stratum_row); one kind=field row per field, slim, or full for a field
    new this run (rows.field_row_from_fieldsummary); matalog_strata docs with
    last_discovered_run, discovery_due_run, the cur_* discovery snapshot,
    field_count, version_top, version_top_counts, version_changed_run;
    matalog_fields docs with the cur_disc_* snapshot, presence, observed,
    first_seen_run, last_seen_run, last_seen_time, consecutive_unseen, profile_id,
    type_guess, identifier, numeric stats, values and values_hash, plus the
    level=source rollup rows of stratified sources; matalog_sources
    last_discovered_run, field_count, version_top, version_changed_run;
    ctx.counts["strata_due"], ["strata_discovered"], ["strata_deferred"],
    ["fields_present"] (field rows of either level with presence=present over
    the discovered sources, as S10 will write them), ["fields_new"],
    ["scan_ratio_max"]. Deferred strata keep
    their discovery_due_run; due strata the search budget leaves unplanned are
    reported in one ctx.error with subject "plan". ctx.state["planned"] lists the planned stratum keys
    in plan order; ctx.state["discovered"] maps each discovered stratum key to
    its figures (events_seen, events_scanned, scan_ratio, fields_found,
    truncated, fields_truncated, fields_over_cap, sid, row_id, source_key).
    """

    name = "S3"
    label = "discover"

    def run(self, ctx):
        candidates = plan(ctx)
        planned = [c for c in candidates if c.planned]
        ctx.state["planned"] = [c.key for c in planned]
        ctx.state["discovered"] = collections.OrderedDict()
        ctx.counts["strata_due"] = len(planned)
        run_jobs(ctx, planned)
        discovered = [c for c in planned if c.discovery is not None]
        ctx.counts["strata_discovered"] = len(discovered)
        ctx.counts["strata_deferred"] = len(candidates) - len(discovered)
        ctx.counts["fields_present"] = 0
        ctx.counts["fields_new"] = 0
        ctx.counts["scan_ratio_max"] = max([c.discovery.scan_ratio for c in discovered] or [0.0])
        if discovered:
            stage_results(ctx, candidates)


# Planning.

def source_views(ctx):
    """The sources S1 left, in priority order, each merged with its staged and stored matalog_sources doc."""
    docs = [d for d in (ctx.state.get("sources") or []) if d.get("_key")]
    stored = ctx.existing("matalog_sources", [d["_key"] for d in docs]) if docs else {}
    out = collections.OrderedDict()
    for doc in docs:
        key = doc["_key"]
        out[key] = _overlay(stored.get(key), ctx.staged("matalog_sources", key), doc)
        out[key]["_key"] = key
    return out


def strata_views(ctx, sources):
    """source_key -> list of stratum docs merged with their staged and stored matalog_strata docs.

    Sources S2 left out of ctx.state["strata"] get their stored active strata;
    an unstratified source always has its __all__ row.
    """
    from_state = _state_strata(ctx)
    listed = collections.OrderedDict()
    missing = []
    for key in sources:
        docs = from_state.get(key) if from_state is not None else None
        if docs is None:
            missing.append(key)
            docs = []
        listed[key] = list(docs)
    for chunk in _chunks(missing, KV_CHUNK):
        for doc in ctx.client.kv_query("matalog_strata", query={"source_key": {"$in": chunk}, "state": {"$in": list(DISCOVERABLE_STATES)}}):
            listed.setdefault(doc.get("source_key"), []).append(doc)
    for key, source in sources.items():
        if not is_stratified(source):
            ident = rows.stratum_identity(source["src_index"], source["src_sourcetype"], keys.ALL, keys.ALL)
            if not any(d.get("_key") == ident["stratum_key"] for d in listed[key]):
                listed[key].append(rows.strata_doc(source["src_index"], source["src_sourcetype"], keys.ALL, keys.ALL, state="active"))
    all_keys = [d["_key"] for docs in listed.values() for d in docs if d.get("_key")]
    stored = ctx.existing("matalog_strata", all_keys) if all_keys else {}
    out = collections.OrderedDict()
    for key, docs in listed.items():
        merged = []
        for doc in docs:
            if not doc.get("_key"):
                continue
            view = _overlay(stored.get(doc["_key"]), ctx.staged("matalog_strata", doc["_key"]), doc)
            view["_key"] = doc["_key"]
            merged.append(view)
        out[key] = merged
    return out


def candidates_for(ctx, sources, strata):
    """Every active stratum S3 may plan: level=stratum rows of a stratified source, the __all__ row otherwise."""
    out = []
    for key, source in sources.items():
        stratified = is_stratified(source)
        for stratum in strata.get(key, []):
            is_all = stratum.get("stratum_value") == keys.ALL or stratum.get("level") == "source"
            if stratified == is_all or stratum.get("state", "active") not in DISCOVERABLE_STATES:
                continue
            out.append(Candidate(source, stratum, ctx.run_id))
    return out


def plan(ctx):
    """Order the candidates by the contract and mark the first budget.plannable() of them planned."""
    sources = source_views(ctx)
    if not sources:
        return []
    candidates = candidates_for(ctx, sources, strata_views(ctx, sources))
    candidates.sort(key=lambda c: (0 if c.due else 1, -c.priority, -c.rate))
    plannable = max(0, int(ctx.budget.plannable()))
    due = [c for c in candidates if c.due][:plannable]
    for candidate in due:
        candidate.planned = True
    optional = max(0, plannable - len(due) - profile_need(ctx, len(due)))
    for candidate in [c for c in candidates if not c.due][:optional]:
        candidate.planned = True
    cut = sum(1 for c in candidates if c.due and not c.planned)
    if cut:
        ctx.error("S3", "plan", "%d due strata not planned: the search budget allows %d discoveries this run" % (cut, plannable))
    return candidates


def profile_need(ctx, due_count=0):
    """Searches S4 will use this run: the strata due, capped at what is left after the due discoveries, plus its week baseline read."""
    from .s4_profile import Profile
    try:
        plans = Profile().due_plans(ctx)
    except Exception as exc:
        ctx.error("S3", "plan", "profile need unknown: %s: %s" % (exc.__class__.__name__, exc))
        return 0
    need = sum(len(p.due_targets) for p in plans)
    need = min(need, max(0, int(ctx.budget.plannable()) - int(due_count) - 1))
    return need + 1 if need else 0


# Jobs.

def run_jobs(ctx, planned):
    """Dispatch one discovery job per planned stratum through the pool; a job that fails or is deferred leaves no discovery."""
    settings = ctx.settings

    def task_for(candidate):
        spl = discovery_spl(settings, candidate.src_index, candidate.search_sourcetype(), candidate.stratum_field, candidate.stratum_value)
        earliest, latest = candidate.window(ctx)

        def task():
            return ctx.client.search(spl, earliest=earliest, latest=latest, sample_ratio=1, step="S3", subject_key=candidate.key)
        return task

    results, _ = ctx.budget.map("S3", [(c.key, task_for(c)) for c in planned])
    for candidate, result in zip(planned, results):
        candidate.result = result
        if isinstance(result, budget_mod.BudgetExhausted):
            continue
        if isinstance(result, Exception):
            ctx.error("S3", candidate.key, "discovery raised %s: %s" % (result.__class__.__name__, result))
            continue
        if not result.ok:
            text = "; ".join(str(m.get("text", "")) for m in (result.messages or [])[:2] if m.get("text"))
            ctx.error("S3", candidate.key, "discovery %s" % result.status + (": %s" % text if text else " with no message"))
            continue
        candidate.discovery = Discovery(candidate, result, settings)


# Rows.

def stored_fields_by_source(ctx, source_keys):
    """Every stored matalog_fields doc of the given sources, as {_key: doc}."""
    out = collections.OrderedDict()
    for chunk in _chunks(source_keys, KV_CHUNK):
        for doc in ctx.client.kv_query("matalog_fields", query={"source_key": {"$in": chunk}}, fields=list(STORED_FIELD_COLUMNS)):
            if doc.get("_key"):
                out[doc["_key"]] = doc
    return out


class FieldState(object):
    """The field docs of the sources touched this run: stored, with earlier steps' and this step's staging on top.

    Keys an earlier step deleted read as absent; stratum-level keys an earlier
    step staged or deleted mark their field name changed, so its rollup is recomputed.
    """

    def __init__(self, ctx, stored, source_keys):
        self.ctx = ctx
        self.stored = stored
        self.by_stratum = collections.defaultdict(list)
        self.by_source = collections.defaultdict(list)
        self.indexed = set()
        self.observed_names = collections.defaultdict(set)
        self.touched_names = collections.defaultdict(set)
        for key, doc in stored.items():
            self.index(key, doc)
        wanted = set(source_keys)
        earlier = set(ctx.kv["matalog_fields"]) | set(ctx.kv_deletes["matalog_fields"])
        for key in sorted(earlier):
            doc = _overlay(stored.get(key), ctx.staged("matalog_fields", key))
            if doc.get("source_key") not in wanted:
                continue
            self.index(key, doc)
            if doc.get("level") == "stratum" and doc.get("field_name"):
                self.touched_names[doc["source_key"]].add(doc["field_name"])

    def index(self, key, doc):
        if key in self.indexed:
            return
        self.indexed.add(key)
        self.by_stratum[doc.get("stratum_key")].append(key)
        self.by_source[doc.get("source_key")].append(key)

    def stage(self, doc):
        key = doc["_key"]
        stored = self.stored.get(key) or {}
        self.index(key, _overlay(stored, doc))
        self.ctx.stage_kv("matalog_fields", doc)
        self.touched_names[doc.get("source_key") or stored.get("source_key")].add(doc.get("field_name") or stored.get("field_name"))

    def view(self, key):
        """The doc as S10 will write it: staged merged onto stored under the roll rule; None when deleted this run."""
        if key in self.ctx.kv_deletes["matalog_fields"]:
            return None
        if self.ctx.staged("matalog_fields", key) is None:
            return self.stored.get(key)
        return self.ctx.after_roll("matalog_fields", key, stored=self.stored.get(key) or {})

    def keys_of_stratum(self, stratum_key):
        return list(self.by_stratum.get(stratum_key, []))

    def keys_of_source(self, source_key):
        return list(self.by_source.get(source_key, []))


def stage_results(ctx, candidates):
    settings = ctx.settings
    discovered = [c for c in candidates if c.discovery is not None]
    source_keys = []
    for candidate in discovered:
        if candidate.source_key not in source_keys:
            source_keys.append(candidate.source_key)
    fields = FieldState(ctx, stored_fields_by_source(ctx, source_keys), source_keys)
    min_events = int(settings.discovery.min_events_for_absence)
    new = 0
    for candidate in discovered:
        d = candidate.discovery
        earliest, latest = candidate.window(ctx)
        stratum_row = discovery_stratum_row(ctx, candidate, earliest, latest)
        ctx.stage(stratum_row)
        ctx.state["discovered"][candidate.key] = collections.OrderedDict([
            ("source_key", candidate.source_key), ("row_id", stratum_row["row_id"]), ("events_seen", d.events_seen),
            ("events_scanned", d.events_scanned), ("scan_ratio", d.scan_ratio), ("fields_found", d.fields_found),
            ("truncated", d.truncated), ("fields_truncated", d.fields_truncated), ("fields_over_cap", d.fields_over_cap),
            ("sid", d.result.sid or "")])
        observed_keys = set()
        for fs_row in d.fields:
            try:
                ident = rows.field_identity(candidate.src_index, candidate.src_sourcetype, candidate.stratum_field, candidate.stratum_value, fs_row["field"])
            except keys.IdentityError as exc:
                ctx.error("S3", candidate.key, "field skipped: %s" % exc)
                continue
            stored = fields.view(ident["field_key"]) or {}
            # A rerun of a committed run sees its own first_seen_run stored; the field is still new in this run.
            is_new = _empty(stored.get("first_seen_run")) or str(stored.get("first_seen_run")) == ctx.run_id
            origin = stored.get("origin") if stored.get("origin") in rows.ORIGINS else None
            row = rows.field_row_from_fieldsummary(
                ctx.run, settings, "discovery", "full" if is_new else "slim", fs_row, candidate.src_index, candidate.src_sourcetype,
                candidate.stratum_field, candidate.stratum_value, events_in_stratum=d.events_seen, earliest=earliest, latest=latest,
                sample_ratio=1, sid=d.result.sid or "", origin=origin, origin_app=(stored.get("origin_app") if origin else None),
                window_anchor=candidate.window_anchor())
            ctx.stage(row)
            doc = rows.kv_from_summary(row)[1]
            doc.update(consecutive_unseen=0, is_rollup=0, rollup_strata=0)
            fields.stage(doc)
            observed_keys.add(ident["field_key"])
            fields.observed_names[candidate.source_key].add(ident["field_name"])
            if is_new:
                new += 1
        if d.fields_truncated == 0 and d.events_seen >= min_events:
            apply_absence(fields, candidate, observed_keys)
        stage_stratum_doc(ctx, fields, candidate, stratum_row)
    ctx.counts["fields_new"] = new
    for source_key in source_keys:
        source = next(c.source for c in discovered if c.source_key == source_key)
        strata_of_source = [c for c in candidates if c.source_key == source_key]
        if is_stratified(source):
            stage_rollups(ctx, fields, source, strata_of_source)
        mark_declared_unseen(fields, source, strata_of_source, min_events)
        stage_source_doc(ctx, fields, source, strata_of_source)
    ctx.counts["fields_present"] = sum(1 for source_key in source_keys for key in fields.keys_of_source(source_key)
                                       if (fields.view(key) or {}).get("presence") == "present")


def discovery_stratum_row(ctx, candidate, earliest, latest):
    """The kind=stratum discovery row; version_top pairs are dropped from the tail until the row fits profile.max_row_bytes."""
    d = candidate.discovery
    limit = int(ctx.settings.profile.max_row_bytes)
    while True:
        row = rows.stratum_row(
            ctx.run, "discovery", candidate.src_index, candidate.src_sourcetype, candidate.stratum_field, candidate.stratum_value,
            earliest=float(earliest), latest=float(latest), sample_ratio=1, events_seen=d.events_seen, events_scanned=d.events_scanned,
            fields_found=d.fields_found, truncated=d.truncated, fields_truncated=d.fields_truncated,
            version_top=list(d.version_top), version_top_counts=list(d.version_top_counts), sid=d.result.sid or "",
            search_seconds=float(d.result.run_duration or 0.0), window_anchor=candidate.window_anchor())
        if not d.version_top or rows.row_bytes(row) <= limit:
            return row
        d.version_top, d.version_top_counts = d.version_top[:-1], d.version_top_counts[:-1]


def apply_absence(fields, candidate, observed_keys):
    """A field known in the stratum and missing from a qualifying discovery: consecutive_unseen up, present becomes unobserved."""
    for key in fields.keys_of_stratum(candidate.key):
        if key in observed_keys:
            continue
        doc = fields.view(key)
        if not doc or doc.get("presence") in PRESENCE_UNTOUCHED or _int(doc.get("is_rollup")) == 1:
            continue
        values = {"consecutive_unseen": _int(doc.get("consecutive_unseen")) + 1}
        if doc.get("presence") == "present":
            values["presence"] = "unobserved"
        fields.stage(rows.kv_doc("matalog_fields", key, source_key=doc.get("source_key"), stratum_key=doc.get("stratum_key"),
                                 field_name=doc.get("field_name"), **values))


def mark_declared_unseen(fields, source, strata_of_source, min_events):
    """A declared field no qualifying discovery of the source observed this run counts another unseen discovery on its source-level row."""
    qualifying = [c for c in strata_of_source if c.discovery is not None and c.discovery.fields_truncated == 0 and c.discovery.events_seen >= min_events]
    if not qualifying:
        return
    seen_names = fields.observed_names.get(source["_key"], set())
    for key in fields.keys_of_source(source["_key"]):
        doc = fields.view(key)
        if not doc or doc.get("level") != "source" or doc.get("presence") != "declared_only" or doc.get("field_name") in seen_names:
            continue
        fields.stage(rows.kv_doc("matalog_fields", key, source_key=doc.get("source_key"), field_name=doc.get("field_name"),
                                 consecutive_unseen=_int(doc.get("consecutive_unseen")) + 1))


def stage_stratum_doc(ctx, fields, candidate, stratum_row):
    settings = ctx.settings
    doc = rows.kv_from_summary(stratum_row)[1]
    doc["discovery_due_run"] = keys.run_id_add(ctx.run_id, settings.budget.max_staleness_cycles, settings.budget.cycle_seconds)
    doc["field_count"] = sum(1 for key in fields.keys_of_stratum(candidate.key) if (fields.view(key) or {}).get("presence") == "present")
    if not candidate.discovery.version_top:
        # A discovery without a version value keeps the stored version_top, so the next build still registers as entered.
        doc.pop("version_top", None)
        doc.pop("version_top_counts", None)
    elif entered(candidate.stratum.get("version_top"), doc.get("version_top"), settings.profile.max_value_chars):
        doc["version_changed_run"] = ctx.run_id
    ctx.stage_kv("matalog_strata", doc)


# Rollups and source docs.

def stratum_discovery_events(strata_of_source):
    """stratum_key -> events of each active stratum's current discovery; None for a stratum never discovered."""
    out = collections.OrderedDict()
    for candidate in strata_of_source:
        if candidate.discovery is not None:
            out[candidate.key] = int(candidate.discovery.events_seen or 0)
        else:
            out[candidate.key] = _int(candidate.stratum.get("cur_events_seen")) if not _empty(candidate.stratum.get("cur_run_id")) else None
    return out


def ordered_strata(strata_of_source):
    """Candidates as the strata table orders them: listed_events descending, then value."""
    return sorted(strata_of_source, key=lambda c: (-(_int(c.stratum.get("listed_events")) or 0), str(c.stratum_value)))


def rollup_values(ctx, source, field_name, children, strata_of_source=None, present_values=None, has_profile=False):
    """The level=source rollup doc values for one field name over its present children.

    cur_disc_events sums the current discovery of every active stratum
    (strata_of_source), a stratum without the field counting in full; without
    the strata the children's events are summed. absent_strata is set from the
    discoveries only while the rollup has no profile snapshot: the discovered
    strata whose child is missing or counted 0.
    """
    settings = ctx.settings
    children = sorted(children, key=lambda c: (-_int(c.get("cur_disc_count")), str(c.get("stratum_key", ""))))
    count = sum(_int(c.get("cur_disc_count")) for c in children)
    child_events = dict((c.get("stratum_key"), _int(c.get("cur_disc_events"))) for c in children)
    if strata_of_source is None:
        events = sum(child_events.values())
    else:
        known = stratum_discovery_events(strata_of_source)
        events = sum(child_events.get(k, 0) if known[k] is None else known[k] for k in known)
    identifier = 1 if any(_int(c.get("identifier")) == 1 for c in children) else 0
    tops = [(c.get("top_values"), c.get("top_counts")) for c in children]
    top_values, top_counts = merge_top(tops, settings.profile.top_values)
    all_values, _ = merge_top(tops, 10 ** 9)
    samples = []
    for child in children:
        samples.extend(child.get("sample_values") or [])
    sample_values, samples_truncated = rows.cap_sample_values(
        samples, settings.profile.sample_values, settings.profile.sample_values_max_bytes, settings.profile.max_value_chars)
    numeric = [c for c in children if _int(c.get("numeric_count")) > 0]
    mins = [_float(c.get("num_min")) for c in numeric if c.get("num_min") is not None]
    maxs = [_float(c.get("num_max")) for c in numeric if c.get("num_max") is not None]
    means = [(_float(c.get("num_mean")), _int(c.get("numeric_count"))) for c in numeric if c.get("num_mean") is not None]
    weight = sum(w for _, w in means)
    first_runs = [str(c["first_seen_run"]) for c in children if not _empty(c.get("first_seen_run"))]
    last_runs = [str(c["last_seen_run"]) for c in children if not _empty(c.get("last_seen_run"))]
    last_times = [_float(c["last_seen_time"]) for c in children if c.get("last_seen_time") is not None]
    values = {
        "level": "source", "is_rollup": 1, "rollup_strata": len(children), "presence": "present", "observed": 1,
        "is_stratum_field": 1 if field_name == source.get("stratum_field") else 0, "consecutive_unseen": 0,
        "first_seen_run": min(first_runs) if first_runs else ctx.run_id,
        "last_seen_run": max(last_runs) if last_runs else ctx.run_id,
        "cur_disc_run_id": ctx.run_id, "cur_disc_count": count, "cur_disc_events": events, "cur_disc_coverage": rows.coverage(count, events),
        "cur_disc_distinct": max([_int(c.get("cur_disc_distinct")) for c in children] or [0]),
        "type_guess": majority_type([c.get("type_guess") for c in children]), "identifier": identifier,
        "top_values": [] if identifier else top_values, "top_counts": [] if identifier else top_counts,
        "sample_values": sample_values, "samples_truncated": samples_truncated, "values_hash": rows.values_hash(all_values),
        "numeric_count": sum(_int(c.get("numeric_count")) for c in numeric),
        "num_min": min(mins) if mins else None, "num_max": max(maxs) if maxs else None,
        "num_mean": (sum(m * w for m, w in means) / weight) if weight > 0 else None,
    }
    if last_times:
        values["last_seen_time"] = max(last_times)
    if strata_of_source is not None and not has_profile:
        present = set(present_values or ()) | set(c.get("stratum_key") for c in children if _int(c.get("cur_disc_count")) > 0)
        known = stratum_discovery_events(strata_of_source)
        absent = [c.stratum_value for c in ordered_strata(strata_of_source) if known.get(c.key) is not None and c.key not in present]
        values["absent_strata"] = absent
        values["absent_strata_count"] = len(absent)
    return values


def stage_rollups(ctx, fields, source, strata_of_source):
    """Recompute the level=source rollup row of every field name whose child rows changed this run."""
    active_keys = set(c.key for c in strata_of_source)
    changed = set(n for n in fields.touched_names.get(source["_key"], set()) if n is not None)
    children_by_name = collections.defaultdict(list)
    present_children = collections.Counter()
    present_values = collections.defaultdict(set)
    rollups = {}
    for key in fields.keys_of_source(source["_key"]):
        doc = fields.view(key)
        if not doc:
            continue
        if _int(doc.get("is_rollup")) == 1 and doc.get("level") == "source":
            rollups[doc.get("field_name")] = doc
            continue
        if doc.get("level") != "stratum" or doc.get("stratum_key") not in active_keys:
            continue
        if doc.get("presence") != "present":
            continue
        present_children[doc["field_name"]] += 1
        if _empty(doc.get("cur_disc_run_id")) or _int(doc.get("cur_disc_count")) > 0:
            present_values[doc["field_name"]].add(doc.get("stratum_key"))
        if not _empty(doc.get("cur_disc_run_id")):
            children_by_name[doc["field_name"]].append(doc)
    # A present rollup counting more strata than its present children lost a child outside this run's discoveries.
    for field_name, doc in rollups.items():
        if doc.get("presence") == "present" and _int(doc.get("rollup_strata")) > present_children[field_name]:
            changed.add(field_name)
    ident_all = (source["src_index"], source["src_sourcetype"], keys.ALL, keys.ALL)
    for field_name in sorted(n for n in changed if n):
        children = children_by_name.get(field_name, [])
        if children:
            has_profile = not _empty((rollups.get(field_name) or {}).get("cur_prof_run_id"))
            values = rollup_values(ctx, source, field_name, children, strata_of_source, present_values[field_name], has_profile)
            fields.stage(rows.fields_doc(*ident_all, field_name=field_name, **values))
            continue
        if present_children[field_name]:
            # Only profiled children remain; the profile step owns that rollup.
            continue
        stored = rollups.get(field_name)
        if not stored:
            continue
        values = {"rollup_strata": 0, "is_rollup": 1}
        if stored.get("presence") == "present":
            values["presence"] = "unobserved"
        fields.stage(rows.fields_doc(*ident_all, field_name=field_name, **values))


def stage_source_doc(ctx, fields, source, strata_of_source):
    settings = ctx.settings
    values = {}
    discovered_now = [c for c in strata_of_source if c.discovery is not None]
    all_discovered = all(c.discovery is not None or not _empty(c.stratum.get("last_discovered_run")) for c in strata_of_source)
    if all_discovered and discovered_now:
        values["last_discovered_run"] = ctx.run_id
    version_entries = []
    for candidate in strata_of_source:
        if candidate.discovery is not None and candidate.discovery.version_top:
            version_entries.append((candidate.discovery.version_top, candidate.discovery.version_top_counts))
        else:
            version_entries.append((candidate.stratum.get("version_top"), candidate.stratum.get("version_top_counts")))
    present = 0
    for key in fields.keys_of_source(source["_key"]):
        doc = fields.view(key) or {}
        if doc.get("level") == "source" and doc.get("presence") == "present":
            present += 1
    values["field_count"] = present
    max_chars = settings.profile.max_value_chars
    version_entries = [([rows.truncate_value(v, max_chars) for v in (values_ or [])], counts) for values_, counts in version_entries]
    version_top, version_top_counts = merge_top(version_entries, settings.profile.top_values)
    if version_top:
        values["version_top"] = version_top
        values["version_top_counts"] = version_top_counts
        if entered(source.get("version_top"), version_top, max_chars):
            values["version_changed_run"] = ctx.run_id
    ctx.stage_kv("matalog_sources", rows.sources_doc(source["src_index"], source["src_sourcetype"], **values))
