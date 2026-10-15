"""S4 profile."""
import collections
import math
import re

from .. import keys
from .. import rows as rows_mod
from .. import writer as writer_mod
from ..budget import BudgetExhausted
from ..runner import Step
from . import s2_enumerate_strata as s2_mod

STEP = "S4"
COUNTER_FIELD = "matalog_n"
TIME_FIELD = "matalog_t"
INTERNAL_FIELDS = (COUNTER_FIELD, TIME_FIELD)
WEEK_DISTANCE_FIELD = "matalog_d"
SEARCHED_STATES = ("active",)

# Stratum candidate rule (Stratum invariants): distinct between 2 and 50, at least 5 other fields partitioned,
# absence at coverage below 0.05. A partitioned field's count matches one value's count within that share,
# and the candidate itself is carried by at least 1 - 0.05 of the events.
CANDIDATE_MIN_DISTINCT = 2
CANDIDATE_MAX_DISTINCT = 50
CANDIDATE_MIN_PARTITIONED = 5
ABSENT_COVERAGE = 0.05
# Splunk default fields, never offered as a stratum key nor counted as partitioned.
DEFAULT_FIELDS = frozenset(("punct", "linecount", "timestartpos", "timeendpos", "splunk_server", "splunk_server_group", "index",
                            "sourcetype", "eventtype", "tag", "tag::eventtype", "timestamp"))

WEEK_COLUMNS = ("run_id", "count", "events_in_stratum", "coverage", "distinct", "distinct_exact", "sample_ratio")
# The distinct probe: one stats dc() job per profiled source, by stratum value plus an __all__ member
# so the same job counts the whole source; the fields fieldsummary capped first, then the fields of a
# stratified source present in more than one stratum.
PROBE_PREFIX = "matalog_dc:"
PROBE_FIELD = "matalog_sv"
PROBE_SUBJECT = "distinct_probe"
PROBE_MAX_FIELDS = 1000
SAFE_PROBE_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.{}@-]*$")
PROF_SUFFIXES = ("run_id", "count", "events", "coverage", "distinct", "distinct_exact", "sample_ratio")


def _int(value):
    if isinstance(value, list):
        value = value[0] if value else None
    if value is None or value == "":
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _float(value):
    if isinstance(value, list):
        value = value[0] if value else None
    if value is None or value == "":
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _empty(value):
    return value is None or value == "" or value == []


def profile_spl(settings, index, sourcetype, stratum_field, stratum_value):
    """The profile job for one stratum: source search, stratum filter, head, counters, fieldsummary."""
    spl = "search index=%s sourcetype=%s" % (keys._spl_quote(index), keys._spl_quote(sourcetype))
    stratum = keys.stratum_filter(stratum_field, stratum_value)
    if stratum:
        spl += " " + stratum
    return "%s | head %d | eval %s=1, %s=_time | fieldsummary maxvals=%d" % (
        spl, settings.profile.profile_head_events, COUNTER_FIELD, TIME_FIELD, settings.profile.sample_values)


def probe_spl(index, sourcetype, stratum_field, names):
    """The distinct probe of one source: dc() per field, by the S2 stratum value when the source is stratified.

    The stratum value gets an __all__ member before the stats, so each event
    counts in its stratum's group and in the __all__ group, whose dc() is the
    whole source's.
    """
    aggs = ", ".join('dc("%s") as "%s%s"' % (n, PROBE_PREFIX, n) for n in names)
    spl = "search index=%s sourcetype=%s" % (keys._spl_quote(index), keys._spl_quote(sourcetype))
    if stratum_field == keys.ALL:
        return "%s | stats %s" % (spl, aggs)
    return '%s | %s | eval %s=mvappend(%s, "%s") | stats %s by %s' % (
        spl, s2_mod.stratum_value_eval(stratum_field, PROBE_FIELD), PROBE_FIELD, PROBE_FIELD, keys.ALL, aggs, PROBE_FIELD)


def is_exact(fs_row):
    return str(fs_row.get("is_exact", "0")) in ("1", "true", "True")


def week_target(ctx):
    return ctx.slot_start - ctx.settings.profile.week_baseline_days * 86400


def week_window(ctx):
    """(earliest, latest) of the week baseline read: one profile interval either side of the target, ending before the slot."""
    target = week_target(ctx)
    interval = ctx.settings.profile.profile_interval_seconds
    return target - interval, min(target + interval, ctx.slot_start)


def week_spl(ctx, source_keys):
    """Committed profile field rows of the given sources, the one nearest the week target per field_key."""
    quoted = ", ".join('"%s"' % writer_mod.spl_quote(k) for k in source_keys)
    extra = 'mode=profile source_key IN (%s) NOT run_id="%s"' % (quoted, writer_mod.spl_quote(ctx.run_id))
    return "%s | eval %s=abs(_time-%d) | sort 0 %s run_id | dedup field_key | head %d | table field_key %s" % (
        writer_mod.committed_rows_spl(["field"], extra=extra), WEEK_DISTANCE_FIELD, week_target(ctx), WEEK_DISTANCE_FIELD,
        ctx.settings.rebuild.rebuild_max_rows, " ".join(WEEK_COLUMNS))


def week_snapshot(result_row):
    """week_prof_* columns from one week baseline result row."""
    run_id = result_row.get("run_id")
    if isinstance(run_id, list):
        run_id = run_id[0] if run_id else None
    return collections.OrderedDict([
        ("week_prof_run_id", str(run_id) if run_id else None),
        ("week_prof_count", _int(result_row.get("count"))),
        ("week_prof_events", _int(result_row.get("events_in_stratum"))),
        ("week_prof_coverage", _float(result_row.get("coverage"))),
        ("week_prof_distinct", _int(result_row.get("distinct"))),
        ("week_prof_distinct_exact", _int(result_row.get("distinct_exact"))),
        ("week_prof_sample_ratio", _int(result_row.get("sample_ratio"))),
    ])


def empty_week():
    return collections.OrderedDict(("week_prof_" + s, None) for s in PROF_SUFFIXES)


def stratum_candidates(fs_rows, events):
    """Fields of an unstratified source whose values partition presence of other fields, from fieldsummary rows only.

    A candidate has distinct between 2 and 50 with an exact value list and is
    carried by at least 1 - ABSENT_COVERAGE of the events. Another field is
    partitioned by it when its count matches the count of one of the
    candidate's values within ABSENT_COVERAGE of that count, where the value
    leaves at least ABSENT_COVERAGE of the events to other values. Candidates with at least 5 partitioned fields are returned, most
    partitioned first, then by name.
    """
    events = int(events or 0)
    if events <= 0:
        return []
    usable = collections.OrderedDict()
    for fs in fs_rows:
        name = fs.get("field")
        if not name or name in INTERNAL_FIELDS or name in DEFAULT_FIELDS or name.startswith("date_"):
            continue
        count = _int(fs.get("count")) or 0
        if count > 0:
            usable[name] = (fs, count)
    found = []
    for name, (fs, count) in usable.items():
        distinct = _int(fs.get("distinct_count")) or 0
        if not CANDIDATE_MIN_DISTINCT <= distinct <= CANDIDATE_MAX_DISTINCT:
            continue
        if str(fs.get("is_exact", "0")) not in ("1", "true", "True"):
            continue
        if count < (1.0 - ABSENT_COVERAGE) * events:
            continue
        ceiling = (1.0 - ABSENT_COVERAGE) * events
        value_counts = [c for _, c in rows_mod.parse_fieldsummary_values(fs.get("values")) if 0 < c <= ceiling]
        if not value_counts:
            continue
        partitioned = 0
        for other, (_, other_count) in usable.items():
            if other == name:
                continue
            if any(abs(other_count - c) <= ABSENT_COVERAGE * c for c in value_counts):
                partitioned += 1
        if partitioned >= CANDIDATE_MIN_PARTITIONED:
            found.append((name, partitioned))
    found.sort(key=lambda item: (-item[1], item[0]))
    return [name for name, _ in found]


class Target(object):
    """One active stratum of a source; due when its last profile is older than profile.profile_interval_seconds."""

    def __init__(self, stratum_field, stratum_value, listed_events=0, last_profiled_run=None, rate=0.0):
        self.stratum_field = stratum_field
        self.stratum_value = stratum_value
        self.stratum_key = None
        self.listed_events = int(listed_events or 0)
        self.last_profiled_run = last_profiled_run
        self.rate = float(rate or 0.0)
        self.due = False


class Plan(object):
    """One source with a stratum due: its resolved doc, every active stratum, the due ones, and after fit the searched slice and its results.

    targets is the slice searched this run; deferred_targets the due strata
    left for a later run (not fitted, or their job failed).
    """

    def __init__(self, source, targets, sample_ratio, overdue):
        self.source = source
        self.all_targets = targets
        self.due_targets = [t for t in targets if t.due]
        self.targets = []
        self.deferred_targets = []
        self.sample_ratio = sample_ratio
        self.overdue = overdue
        self.results = []
        # stratum_value -> events the profile job returned; stratum_value -> {field: exact dc()} from the probe,
        # keyed __all__ for the whole source when no stratum hit head.
        self.stratum_events = collections.OrderedDict()
        self.probe = {}
        self.head_hit = False
        # Stored field docs of the active strata outside the slice, read once for the probe and the rollups.
        self.stored_docs = None

    @property
    def source_key(self):
        return self.source["source_key"]

    @property
    def stratified(self):
        return (self.source.get("stratum_field") or keys.ALL) != keys.ALL


class Profile(Step):
    """Profile every source whose next_profile_due is at or before the slot start, in priority order.

    Inputs: ctx.state["sources"] (S1 docs: source_key, src_index, src_sourcetype,
    daily_events, profile_mode, priority) resolved through ctx.after_roll onto
    the stored matalog_sources rows for next_profile_due, stratum_field,
    version_field and search_sourcetype; ctx.state["strata"] (source_key ->
    list of matalog_strata docs with stratum_field, stratum_value, level,
    state), read from matalog_strata when a stratified source is not in it;
    ctx.windows["profile"]; ctx.budget.plannable(), less one search held for
    the week baseline, and one more per profiled source for the distinct
    probe when the budget still has it: a stats dc() job over the profile
    window, by stratum value plus an __all__ member for the whole source, for
    the fields whose distinct_count fieldsummary capped (is_exact=0) and then
    the fields present in more than one stratum, PROBE_MAX_FIELDS at most, on
    unsampled sources whose strata did not hit head, so the probe reads the
    same events. A stratum is due when its last_profiled_run is empty or its
    slot plus profile.profile_interval_seconds is at or before the slot
    start; a source with a due stratum is a plan. Sources whose due time is
    in an earlier slot, or that an earlier run enumerated and none has
    profiled, are planned first, then by priority; within a source the due
    strata go by rate_per_hour descending. The due strata are taken in that
    order until the searches left are used, so a source's profile may span
    runs. One job per due stratum (level=stratum for a stratified source,
    the __all__ stratum otherwise): the source search plus
    keys.stratum_filter, `| head
    profile.profile_head_events | eval matalog_n=1, matalog_t=_time |
    fieldsummary maxvals=profile.sample_values`, sampled at
    profile.sample_ratio when profile_mode is sampled. One search per run
    over matalog_profiles for the committed profile rows nearest
    profile.week_baseline_days before run_id, for the sources profiled.

    Outputs: per stratum one kind=stratum mode=profile row whose earliest is
    the oldest event read when head was hit, and one full kind=field row per
    field with a non-zero count (at most discovery.max_fields_per_stratum,
    the rest counted in fields_truncated); matalog_fields docs from
    rows.kv_from_summary of each row (cur_prof_* raw, profile_id, the value
    columns, observed, last_seen_run, last_seen_time) plus week_prof_*, with
    presence and first_seen_run left to the docs S3 staged; rollup docs
    (level=source, is_rollup=1) of stratified sources over the strata
    profiled this run merged with the stored cur_prof_* docs of the source's
    other active strata (one KV read), their cur_prof_distinct the probe's
    whole-source dc() when the probe carried the field (rows.rollup_distinct
    otherwise), with rollup_strata left to S3 when it set one; matalog_strata
    last_profiled_run and profile_due_run; matalog_sources sample_ratio,
    strata_profile_due and stratum_candidates (unstratified sources; empty on
    stratified ones), plus last_profiled_run and next_profile_due when no
    stratum is left due. A stratum whose job was deferred, failed or timed
    out stages nothing and stays due; the source's other strata are staged.
    ctx.counts["sources_profiled"], ["sources_deferred"] (strata still due
    after this run), ["strata_profile_due"] and ["strata_profiled"]
    (sources_due is S1's); ctx.state["profiled_sources"] and
    ["profile_deferred"]: source keys.
    """

    name = "S4"
    label = "profile"

    def run(self, ctx):
        due = self.due_plans(ctx)
        planned, deferred = self.fit(ctx, due)
        self.dispatch(ctx, planned)
        profiled = []
        staged_fields = []
        for plan in planned:
            self.settle(ctx, plan)
            if plan.targets:
                profiled.append(plan)
            else:
                deferred.append(plan)
        self.probe_distinct(ctx, profiled)
        for plan in profiled:
            staged_fields.append((plan, self.stage_source(ctx, plan)))
        weeks = self.week_baselines(ctx, [p.source_key for p in profiled])
        for plan, fields in staged_fields:
            self.stage_weeks_and_rollups(ctx, plan, fields, weeks)
            self.stage_field_counts(ctx, plan)
        for plan in deferred:
            if plan.deferred_targets:
                ctx.stage_kv("matalog_sources", rows_mod.sources_doc(plan.source["src_index"], plan.source["src_sourcetype"],
                                                                     strata_profile_due=len(plan.deferred_targets)))
        still_due = [p for p in due if p.deferred_targets or not p.all_targets]
        ctx.counts["sources_profiled"] = len(profiled)
        ctx.counts["sources_deferred"] = len(still_due)
        ctx.counts["strata_profile_due"] = sum(len(p.due_targets) for p in due)
        ctx.counts["strata_profiled"] = sum(len(p.targets) for p in profiled)
        ctx.state["profiled_sources"] = [p.source_key for p in profiled]
        ctx.state["profile_deferred"] = [p.source_key for p in still_due]

    # Planning.

    def resolved_sources(self, ctx):
        sources = [s for s in (ctx.state.get("sources") or []) if s.get("source_key")]
        stored = ctx.existing("matalog_sources", [s["source_key"] for s in sources])
        out = []
        for source in sources:
            doc = collections.OrderedDict(stored.get(source["source_key"]) or {})
            doc.update((c, v) for c, v in source.items() if not _empty(v))
            merged = ctx.after_roll("matalog_sources", source["source_key"], stored.get(source["source_key"]) or {})
            doc.update((c, v) for c, v in (merged or {}).items() if not _empty(v))
            out.append(doc)
        return out

    def due_plans(self, ctx):
        """One plan per source with a due stratum, or with no active stratum while its own due time has passed."""
        plans = []
        for source in self.resolved_sources(ctx):
            if source.get("plan_anchor"):
                # An anchored first discovery: the slot-pinned profile window holds no events of this source.
                continue
            due_at = _float(source.get("next_profile_due"))
            targets = self.targets(ctx, source)
            if targets and not any(t.due for t in targets):
                continue
            if not targets and due_at is not None and due_at > ctx.slot_start:
                continue
            plans.append(Plan(source, targets, self.sample_ratio_of(ctx, source), self.overdue(ctx, source, due_at)))
        plans.sort(key=lambda p: (0 if p.overdue else 1, -(_float(p.source.get("priority")) or 0.0)))
        return plans

    def stratum_due(self, ctx, last_profiled_run):
        if _empty(last_profiled_run):
            return True
        try:
            slot = keys.slot_start_of(str(last_profiled_run))
        except ValueError:
            return True
        return slot + int(ctx.settings.profile.profile_interval_seconds) <= ctx.slot_start

    def overdue(self, ctx, source, due_at):
        """Due in an earlier slot; a never-profiled source counts once an earlier run has enumerated it."""
        if due_at is not None:
            return due_at < ctx.slot_start
        first_seen = source.get("first_seen_run")
        return not _empty(first_seen) and str(first_seen) < ctx.run_id

    def sample_ratio_of(self, ctx, source):
        mode = source.get("profile_mode")
        if mode not in ("sampled", "unsampled"):
            daily = _int(source.get("daily_events")) or 0
            mode = "sampled" if daily >= ctx.settings.profile.sample_volume_threshold else "unsampled"
        return int(ctx.settings.profile.sample_ratio) if mode == "sampled" else 1

    def targets(self, ctx, source):
        """Every active stratum of the source, rate_per_hour descending, each marked due from its own last_profiled_run."""
        stratum_field = source.get("stratum_field") or keys.ALL
        strata = (ctx.state.get("strata") or {}).get(source["source_key"])
        if strata is None:
            strata = ctx.client.kv_query("matalog_strata", query={"source_key": source["source_key"]})
        out = []
        if stratum_field == keys.ALL:
            key = keys.stratum_key(source["src_index"], source["src_sourcetype"], keys.ALL, keys.ALL)
            doc = next((d for d in strata if d.get("stratum_value") == keys.ALL or d.get("level") == "source"), None)
            if doc is None:
                doc = ctx.existing("matalog_strata", [key]).get(key) or {}
            target = Target(keys.ALL, keys.ALL, _int(doc.get("listed_events")) or 0, doc.get("last_profiled_run"), _float(doc.get("rate_per_hour")))
            target.stratum_key = key
            out.append(target)
        else:
            seen = set()
            for doc in strata:
                if doc.get("level") != "stratum" or doc.get("stratum_field") != stratum_field:
                    continue
                if (doc.get("state") or "active") not in SEARCHED_STATES:
                    continue
                value = doc.get("stratum_value")
                if _empty(value) or value in seen:
                    continue
                seen.add(value)
                target = Target(stratum_field, value, _int(doc.get("listed_events")) or 0, doc.get("last_profiled_run"), _float(doc.get("rate_per_hour")))
                target.stratum_key = keys.stratum_key(source["src_index"], source["src_sourcetype"], stratum_field, value)
                out.append(target)
            out.sort(key=lambda t: (-t.rate, -t.listed_events, str(t.stratum_value)))
        for target in out:
            target.due = self.stratum_due(ctx, target.last_profiled_run)
        return out

    def fit(self, ctx, plans):
        """Due strata in plan order, as many as the searches left after the week baseline slot; the rest stay due."""
        available = max(0, ctx.budget.plannable() - 1)
        used = 0
        planned, deferred = [], []
        for plan in plans:
            if not plan.all_targets:
                ctx.error(self.name, plan.source_key, "no active strata to profile")
                deferred.append(plan)
                continue
            plan.targets = plan.due_targets[:max(0, available - used)]
            plan.deferred_targets = plan.due_targets[len(plan.targets):]
            used += len(plan.targets)
            (planned if plan.targets else deferred).append(plan)
        return planned, deferred

    # Dispatch.

    def dispatch(self, ctx, plans):
        earliest, latest = ctx.windows["profile"]
        tasks = []
        owners = []
        for plan in plans:
            sourcetype = plan.source.get("search_sourcetype") or plan.source["src_sourcetype"]
            for target in plan.targets:
                spl = profile_spl(ctx.settings, plan.source["src_index"], sourcetype, target.stratum_field, target.stratum_value)
                tasks.append((target.stratum_key, self.job(ctx, spl, earliest, latest, plan.sample_ratio, target.stratum_key)))
                owners.append(plan)
        results, _ = ctx.budget.map(self.name, tasks)
        for plan, result in zip(owners, results):
            plan.results.append(result)

    def job(self, ctx, spl, earliest, latest, sample_ratio, subject_key):
        def run():
            return ctx.client.search(spl, earliest=earliest, latest=latest, sample_ratio=sample_ratio, step=self.name, subject_key=subject_key)
        return run

    # The distinct probe.

    def probe_fields(self, ctx, plan):
        """Field names the probe carries, on an unsampled source: capped by fieldsummary in a stratum that did not hit head,
        then, when no stratum hit head, the fields present in more than one stratum, most strata first; PROBE_MAX_FIELDS at most.

        The strata are the slice profiled this run and the stored profiles of
        the source's other active strata, so a field shared with a stratum
        profiled in an earlier run, or capped there, is probed too.
        """
        if plan.sample_ratio != 1:
            return []
        capped = []
        strata_of = collections.Counter()
        head = ctx.settings.profile.profile_head_events
        for result in plan.results:
            fs_rows = [r for r in (result.results or []) if r.get("field")]
            if self.events_of(fs_rows) >= head:
                plan.head_hit = True
                continue
            for fs in fs_rows:
                name = fs["field"]
                if name in INTERNAL_FIELDS or (_int(fs.get("count")) or 0) <= 0 or not SAFE_PROBE_NAME.match(name):
                    continue
                strata_of[name] += 1
                if not is_exact(fs) and name not in capped:
                    capped.append(name)
        for doc in self.stored_profiles(ctx, plan):
            if (_int(doc.get("cur_prof_events")) or 0) >= head:
                plan.head_hit = True
                continue
            name = doc.get("field_name")
            if not name or name in INTERNAL_FIELDS or (_int(doc.get("cur_prof_count")) or 0) <= 0 or not SAFE_PROBE_NAME.match(name):
                continue
            strata_of[name] += 1
            if _int(doc.get("cur_prof_distinct_exact")) != 1 and name not in capped:
                capped.append(name)
        names = list(capped)
        if plan.stratified and not plan.head_hit:
            shared = [n for n, k in strata_of.items() if k > 1 and n not in capped]
            names.extend(sorted(shared, key=lambda n: (-strata_of[n], n)))
        return names[:PROBE_MAX_FIELDS]

    def probe_distinct(self, ctx, plans):
        """One probe job per profiled source with fields to probe, keeping one search for the week baseline; a source not probed keeps the cap rule."""
        earliest, latest = ctx.windows["profile"]
        tasks, owners = [], []
        for plan in plans:
            if ctx.budget.plannable() - len(tasks) <= 1:
                break
            names = self.probe_fields(ctx, plan)
            if not names:
                continue
            source = plan.source
            sourcetype = source.get("search_sourcetype") or source["src_sourcetype"]
            spl = probe_spl(source["src_index"], sourcetype, source.get("stratum_field") or keys.ALL, names)
            subject = "%s:%s" % (PROBE_SUBJECT, plan.source_key)
            tasks.append((subject, self.job(ctx, spl, earliest, latest, 1, subject)))
            owners.append(plan)
        if not tasks:
            return
        results, _ = ctx.budget.map(self.name, tasks)
        for plan, result in zip(owners, results):
            if isinstance(result, Exception) or result is None or not result.ok:
                status = result.ceiling if isinstance(result, BudgetExhausted) else getattr(result, "status", None) or result.__class__.__name__
                ctx.error(self.name, plan.source_key, "distinct probe not read (%s); capped counts kept" % status)
                continue
            plan.probe = self.parse_probe(plan, result.results or [])

    def parse_probe(self, plan, rows_):
        """stratum_value -> {field: dc()}; the __all__ row of a stratified source is the whole source, dropped when a stratum hit head."""
        out = {}
        for row in rows_:
            value = s2_mod.parse_listed_value(row.get(PROBE_FIELD)) if plan.stratified else keys.ALL
            if value is None or (plan.stratified and plan.head_hit and value == keys.ALL):
                continue
            per = out.setdefault(value, {})
            for column, raw in row.items():
                if column.startswith(PROBE_PREFIX) and _int(raw) is not None:
                    per[column[len(PROBE_PREFIX):]] = _int(raw)
        return out

    def failure(self, target, result):
        if isinstance(result, BudgetExhausted):
            return "budget ceiling %s at %s" % (result.ceiling, target.stratum_key)
        if isinstance(result, Exception):
            return "%s: %s at %s" % (result.__class__.__name__, result, target.stratum_key)
        if result is None or not result.ok:
            return "job %s at %s" % (getattr(result, "status", "missing"), target.stratum_key)
        return ""

    def settle(self, ctx, plan):
        """Keep the targets whose job returned; a stratum whose job failed stays due."""
        kept, results = [], []
        for target, result in zip(plan.targets, plan.results):
            reason = self.failure(target, result)
            if reason:
                ctx.error(self.name, plan.source_key, "profile deferred: %s" % reason)
                plan.deferred_targets.append(target)
            else:
                kept.append(target)
                results.append(result)
        plan.targets, plan.results = kept, results

    # Staging.

    def stage_source(self, ctx, plan):
        """Stage the rows and KV docs of one profiled source; returns the measured field docs by field_key."""
        source = plan.source
        index, sourcetype = source["src_index"], source["src_sourcetype"]
        parsed = []
        all_keys = []
        for target, result in zip(plan.targets, plan.results):
            fs_rows = [r for r in (result.results or []) if r.get("field")]
            parsed.append((target, result, fs_rows))
            for fs in fs_rows:
                if fs["field"] not in INTERNAL_FIELDS:
                    all_keys.append(keys.field_key(index, sourcetype, target.stratum_field, target.stratum_value, fs["field"]))
        stored = ctx.existing("matalog_fields", all_keys)
        measured = collections.OrderedDict()
        candidates = []
        for target, result, fs_rows in parsed:
            plan.stratum_events[target.stratum_value] = self.events_of(fs_rows)
            measured.update(self.stage_stratum(ctx, plan, target, result, fs_rows, stored))
            if not plan.stratified:
                candidates = stratum_candidates(fs_rows, self.events_of(fs_rows))
        values = dict(sample_ratio=plan.sample_ratio, stratum_candidates=[] if plan.stratified else candidates,
                      strata_profile_due=len(plan.deferred_targets))
        if not plan.deferred_targets:
            values.update(last_profiled_run=ctx.run_id, next_profile_due=float(ctx.slot_start + ctx.settings.profile.profile_interval_seconds))
        ctx.stage_kv("matalog_sources", rows_mod.sources_doc(index, sourcetype, **values))
        return measured

    def events_of(self, fs_rows):
        for fs in fs_rows:
            if fs.get("field") == COUNTER_FIELD:
                return _int(fs.get("count")) or 0
        return 0

    def covered_window(self, ctx, fs_rows, events):
        """(earliest, latest, truncated): the window the job read; earliest moves to the oldest event when head was hit."""
        earliest, latest = ctx.windows["profile"]
        truncated = 1 if events >= ctx.settings.profile.profile_head_events else 0
        if truncated:
            for fs in fs_rows:
                if fs.get("field") == TIME_FIELD:
                    oldest = _float(fs.get("min"))
                    if oldest is not None and earliest <= oldest <= latest:
                        earliest = int(math.floor(oldest))
        return earliest, latest, truncated

    def version_top(self, ctx, plan, fs_rows):
        version_field = plan.source.get("version_field") or ""
        if not version_field:
            return [], []
        for fs in fs_rows:
            if fs.get("field") == version_field:
                pairs = rows_mod.parse_fieldsummary_values(fs.get("values"))[:ctx.settings.profile.top_values]
                max_chars = ctx.settings.profile.max_value_chars
                return [rows_mod.truncate_value(v, max_chars) for v, _ in pairs], [str(c) for _, c in pairs]
        return [], []

    def stage_stratum(self, ctx, plan, target, result, fs_rows, stored):
        source = plan.source
        index, sourcetype = source["src_index"], source["src_sourcetype"]
        events = self.events_of(fs_rows)
        earliest, latest, truncated = self.covered_window(ctx, fs_rows, events)
        fields = [fs for fs in fs_rows if fs["field"] not in INTERNAL_FIELDS and (_int(fs.get("count")) or 0) > 0]
        fields.sort(key=lambda fs: (-(_int(fs.get("count")) or 0), fs["field"]))
        cap = ctx.settings.discovery.max_fields_per_stratum
        kept = fields[:cap]
        version_top, version_counts = self.version_top(ctx, plan, fs_rows)
        stratum_row = rows_mod.stratum_row(
            ctx.run, "profile", index, sourcetype, target.stratum_field, target.stratum_value,
            earliest=float(earliest), latest=float(latest), sample_ratio=plan.sample_ratio, events_seen=events,
            events_scanned=int(result.scan_count), fields_found=len(fields), truncated=truncated,
            fields_truncated=1 if len(fields) > cap else 0, version_top=version_top, version_top_counts=version_counts,
            sid=result.sid or "", search_seconds=float(result.run_duration))
        ctx.stage(stratum_row)
        _, strata_doc = rows_mod.kv_from_summary(stratum_row)
        for column in ("version_top", "version_top_counts", "first_seen_run"):
            strata_doc.pop(column, None)
        strata_doc["profile_due_run"] = keys.run_id_of(ctx.slot_start + int(ctx.settings.profile.profile_interval_seconds))
        ctx.stage_kv("matalog_strata", strata_doc)
        measured = collections.OrderedDict()
        probe = (plan.probe.get(target.stratum_value) or {}) if (not truncated and plan.sample_ratio == 1) else {}
        for fs in kept:
            key = keys.field_key(index, sourcetype, target.stratum_field, target.stratum_value, fs["field"])
            prior = stored.get(key) or {}
            origin = prior.get("origin") if prior.get("origin") in rows_mod.ORIGINS else None
            row = rows_mod.field_row_from_fieldsummary(
                ctx.run, ctx.settings, "profile", "full", fs, index, sourcetype, target.stratum_field, target.stratum_value,
                events, earliest, latest, plan.sample_ratio, result.sid or "", origin=origin,
                origin_app=(prior.get("origin_app") or "") if origin else None, probe_distinct=probe.get(fs["field"]))
            ctx.stage(row)
            measured[key] = (row, self.stage_field(ctx, row, prior), prior)
        return measured

    def field_doc_columns(self, ctx, doc, key, prior):
        """Leave presence and first_seen_run to the doc already staged or stored; mark measured rows."""
        staged = ctx.staged("matalog_fields", key) or {}
        if not _empty(staged.get("presence")) or not _empty(prior.get("presence")):
            doc.pop("presence", None)
        if not _empty(staged.get("first_seen_run")):
            doc.pop("first_seen_run", None)
        doc.pop("origin", None)
        doc.pop("origin_app", None)
        return doc

    def stage_field(self, ctx, row, prior):
        _, doc = rows_mod.kv_from_summary(row)
        doc = self.field_doc_columns(ctx, doc, doc["_key"], prior)
        doc["is_rollup"] = 0
        doc["rollup_strata"] = 0
        return ctx.stage_kv("matalog_fields", doc)

    # Week baseline and rollups.

    def week_baselines(self, ctx, source_keys):
        """field_key -> week_prof_* columns, or None when the read did not happen or failed."""
        if not source_keys:
            return None
        earliest, latest = week_window(ctx)
        max_rows = ctx.settings.rebuild.rebuild_max_rows
        try:
            result = ctx.client.search(week_spl(ctx, source_keys), earliest=earliest, latest=latest, step=self.name,
                                       subject_key="week_baseline", max_rows=max_rows)
        except BudgetExhausted as exc:
            ctx.error(self.name, "week_baseline", "budget ceiling %s" % exc.ceiling)
            return None
        except Exception as exc:
            ctx.error(self.name, "week_baseline", "week baseline read failed: %s: %s" % (exc.__class__.__name__, exc))
            return None
        if not result.ok:
            ctx.error(self.name, "week_baseline", "week baseline read %s" % result.status)
            return None
        out = {}
        for row in result.results:
            key = row.get("field_key")
            if isinstance(key, list):
                key = key[0] if key else None
            if key and key not in out:
                out[key] = week_snapshot(row)
        return out

    def stage_weeks_and_rollups(self, ctx, plan, measured, weeks):
        children = collections.OrderedDict()
        for key, (row, doc, prior) in measured.items():
            week = None
            if weeks is not None:
                week = weeks.get(key) or empty_week()
                ctx.stage_kv("matalog_fields", rows_mod.kv_doc("matalog_fields", key, **week))
            disc_count = _int(doc.get("cur_disc_count"))
            if disc_count is None:
                disc_count = _int(prior.get("cur_disc_count")) or 0
            children.setdefault(row["field_name"], []).append((row, week, disc_count))
        if not plan.stratified:
            return
        self.stored_children(ctx, plan, children, weeks is not None)
        source = plan.source
        rollup_keys = [keys.source_field_key(source["src_index"], source["src_sourcetype"], name) for name in children]
        stored = ctx.existing("matalog_fields", rollup_keys)
        for key, (field_name, items) in zip(rollup_keys, children.items()):
            self.stage_rollup(ctx, plan, field_name, items, weeks is not None, stored.get(key) or {})

    def stored_profiles(self, ctx, plan):
        """Stored field docs with a profile snapshot of the source's active strata outside this run's slice; one KV read per plan."""
        if plan.stored_docs is not None:
            return plan.stored_docs
        plan.stored_docs = []
        if not plan.stratified:
            return plan.stored_docs
        searched = set(t.stratum_key for t in plan.targets)
        other = [t.stratum_key for t in plan.all_targets if t.stratum_key not in searched]
        if not other:
            return plan.stored_docs
        try:
            docs = ctx.client.kv_query("matalog_fields", query={"source_key": plan.source_key, "level": "stratum", "stratum_key": {"$in": other}})
        except Exception as exc:
            ctx.error(self.name, plan.source_key, "stored strata not read: %s: %s" % (exc.__class__.__name__, exc))
            return plan.stored_docs
        wanted = set(other)
        plan.stored_docs = [d for d in docs if d.get("stratum_key") in wanted and not _empty(d.get("cur_prof_run_id")) and d.get("presence") != "retired"]
        return plan.stored_docs

    def stored_children(self, ctx, plan, children, with_week):
        """Add the stored profile snapshots of the source's other active strata as rollup children."""
        for doc in self.stored_profiles(ctx, plan):
            value = str(doc.get("stratum_value"))
            plan.stratum_events.setdefault(value, _int(doc.get("cur_prof_events")) or 0)
            if (_int(doc.get("cur_prof_count")) or 0) <= 0 or not doc.get("field_name"):
                continue
            row = dict(
                run_id=str(doc["cur_prof_run_id"]), field_name=doc["field_name"], stratum_key=doc["stratum_key"], stratum_value=value,
                count=_int(doc.get("cur_prof_count")) or 0, distinct=_int(doc.get("cur_prof_distinct")) or 0,
                distinct_exact=_int(doc.get("cur_prof_distinct_exact")) or 0, sample_ratio=_int(doc.get("cur_prof_sample_ratio")) or 1,
                identifier=_int(doc.get("identifier")) or 0, type_guess=doc.get("type_guess") or "", numeric_count=_int(doc.get("numeric_count")) or 0,
                num_min=_float(doc.get("num_min")), num_max=_float(doc.get("num_max")), num_mean=_float(doc.get("num_mean")),
                top_values=list(doc.get("top_values") or []), top_counts=list(doc.get("top_counts") or []),
                sample_values=list(doc.get("sample_values") or []), latest=_float(doc.get("last_seen_time")) or 0.0)
            week = collections.OrderedDict((c, doc.get(c)) for c in empty_week()) if with_week else None
            children.setdefault(doc["field_name"], []).append((row, week, _int(doc.get("cur_disc_count")) or 0))

    def stage_rollup(self, ctx, plan, field_name, items, with_week, prior):
        """Children are ordered as rebuild orders them: cur_disc_count descending, then stratum_key.

        Coverage is over the events of every active stratum with a profile
        (this run's slice and the stored snapshots), so a stratum without the
        field counts in the denominator; absent_strata lists those strata as
        the strata table orders them.
        """
        source = plan.source
        index, sourcetype = source["src_index"], source["src_sourcetype"]
        p = ctx.settings.profile
        items = sorted(items, key=lambda item: (-item[2], str(item[0]["stratum_key"])))
        rows_ = [row for row, _, _ in items]
        count = sum(int(r["count"]) for r in rows_)
        events = sum(int(v) for v in plan.stratum_events.values())
        carried = set(str(r["stratum_value"]) for r in rows_)
        absent = [t.stratum_value for t in sorted(plan.all_targets, key=lambda t: (-t.listed_events, str(t.stratum_value)))
                  if t.stratum_value not in carried and t.stratum_value in plan.stratum_events]
        newest = max(str(r.get("run_id") or ctx.run_id) for r in rows_)
        merged_counts = collections.OrderedDict()
        probed = (plan.probe.get(keys.ALL) or {}).get(field_name)
        distinct, distinct_exact = rows_mod.rollup_distinct(
            [(int(r["distinct"]), int(r["distinct_exact"]), str(r["stratum_value"])) for r in rows_],
            field_name == source.get("stratum_field"), probed=min(int(probed), count) if probed is not None else None)
        identifier = 1 if any(int(r["identifier"]) for r in rows_) else 0
        if not identifier and probed is not None:
            identifier = rows_mod.is_identifier(count, distinct, ctx.settings, distinct_exact)
        for r in rows_:
            for value, value_count in zip(r.get("top_values") or [], r.get("top_counts") or []):
                merged_counts[str(value)] = merged_counts.get(str(value), 0) + (_int(value_count) or 0)
        top = sorted(merged_counts.items(), key=lambda item: (-item[1], item[0]))[:p.top_values]
        samples = []
        for r in rows_:
            samples.extend(r.get("sample_values") or [])
        sample_values, samples_truncated = rows_mod.cap_sample_values(samples, p.sample_values, p.sample_values_max_bytes, p.max_value_chars)
        numeric_count = sum(int(r["numeric_count"]) for r in rows_)
        numeric = [r for r in rows_ if int(r["numeric_count"]) > 0 and r.get("num_mean") is not None]
        mins = [r["num_min"] for r in numeric if r.get("num_min") is not None]
        maxes = [r["num_max"] for r in numeric if r.get("num_max") is not None]
        values = dict(
            level="source", is_rollup=1, is_stratum_field=1 if field_name == source.get("stratum_field") else 0,
            observed=1, last_seen_run=newest,
            last_seen_time=max(float(r["latest"]) for r in rows_),
            cur_prof_run_id=newest, cur_prof_count=count, cur_prof_events=events, cur_prof_coverage=rows_mod.coverage(count, events),
            absent_strata=absent, absent_strata_count=len(absent),
            cur_prof_distinct=distinct, cur_prof_distinct_exact=distinct_exact,
            cur_prof_sample_ratio=max(int(r["sample_ratio"]) for r in rows_),
            type_guess=self.majority([r["type_guess"] for r in rows_]), identifier=identifier,
            numeric_count=numeric_count,
            num_min=min(mins) if mins else None, num_max=max(maxes) if maxes else None,
            num_mean=(sum(float(r["num_mean"]) * int(r["numeric_count"]) for r in numeric) / sum(int(r["numeric_count"]) for r in numeric)) if numeric else None,
            top_values=[] if identifier else [v for v, _ in top], top_counts=[] if identifier else [str(c) for _, c in top],
            sample_values=sample_values, samples_truncated=samples_truncated, values_hash=rows_mod.values_hash(list(merged_counts.keys())),
            updated_run_id=ctx.run_id)
        if with_week:
            values.update(self.week_rollup([w for _, w, _ in items]))
        key = keys.source_field_key(index, sourcetype, field_name)
        staged = ctx.staged("matalog_fields", key) or {}
        if not (_int(staged.get("rollup_strata")) or _int(prior.get("rollup_strata"))):
            values["rollup_strata"] = len(rows_)
        if _empty(staged.get("presence")) and _empty(prior.get("presence")):
            values["presence"] = "present"
        if _empty(staged.get("first_seen_run")):
            values["first_seen_run"] = ctx.run_id
        ctx.stage_kv("matalog_fields", rows_mod.fields_doc(index, sourcetype, keys.ALL, keys.ALL, field_name, **values))

    def stage_field_counts(self, ctx, plan):
        """field_count on the source and its profiled strata, counting the present rows this step added.

        One KV read of the source's field rows, with this run's staged docs over them.
        """
        source = plan.source
        try:
            stored = ctx.client.kv_query("matalog_fields", query={"source_key": source["source_key"]},
                                         fields=["_key", "stratum_key", "level", "presence"])
        except Exception as exc:
            ctx.error(self.name, source["source_key"], "field count read failed: %s: %s" % (exc.__class__.__name__, exc))
            return
        docs = collections.OrderedDict((d["_key"], dict(d)) for d in stored if d.get("_key"))
        for key, doc in ctx.kv["matalog_fields"].items():
            if key in docs or doc.get("source_key") == source["source_key"]:
                docs.setdefault(key, {}).update((c, v) for c, v in doc.items() if c in ("stratum_key", "level", "presence") and not _empty(v))
        for key in ctx.kv_deletes["matalog_fields"]:
            docs.pop(key, None)
        present = [d for d in docs.values() if d.get("presence") == "present"]
        by_stratum = collections.Counter(d.get("stratum_key") for d in present)
        for target in plan.targets:
            ctx.stage_kv("matalog_strata", rows_mod.kv_doc("matalog_strata", target.stratum_key, field_count=by_stratum.get(target.stratum_key, 0)))
        ctx.stage_kv("matalog_sources", rows_mod.sources_doc(source["src_index"], source["src_sourcetype"],
                                                             field_count=sum(1 for d in present if d.get("level") == "source")))

    def majority(self, guesses):
        """The guess more than half the children share, else mixed; ties broken by name."""
        tally = collections.Counter(g for g in guesses if g)
        if not tally:
            return "empty"
        guess, n = sorted(tally.items(), key=lambda item: (-item[1], item[0]))[0]
        return guess if n * 2 > sum(tally.values()) else "mixed"

    def week_rollup(self, weeks):
        present = [w for w in weeks if w and not _empty(w.get("week_prof_run_id"))]
        if not present:
            return empty_week()
        count = sum(w.get("week_prof_count") or 0 for w in present)
        events = sum(w.get("week_prof_events") or 0 for w in present)
        return collections.OrderedDict([
            ("week_prof_run_id", max(w["week_prof_run_id"] for w in present)),
            ("week_prof_count", count),
            ("week_prof_events", events),
            ("week_prof_coverage", rows_mod.coverage(count, events)),
            ("week_prof_distinct", max(w.get("week_prof_distinct") or 0 for w in present)),
            ("week_prof_distinct_exact", 1 if len(present) == 1 and present[0].get("week_prof_distinct_exact") == 1 else 0),
            ("week_prof_sample_ratio", max(w.get("week_prof_sample_ratio") or 1 for w in present)),
        ])
