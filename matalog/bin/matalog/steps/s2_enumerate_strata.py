"""S2 enumerate_strata.

For every source in ctx.state["sources"]: resolve the stratum key from
matalog_stratum_config, keep the __all__ stratum row, and for a stratified
source whose last listing is due run one sampled listing,

    search index="<index>" sourcetype="<search sourcetype>"
    | eval matalog_sv=case(<absent>, "__missing__", <mvcount > 1>, "__multi__" U+001F <sorted distinct values joined by U+001F>,
                           <empty string>, "__empty__", true(), <value>)
    | stats count by matalog_sv | sort 0 -count

over ctx.windows["stratum_list"] at discovery.stratum_list_sample_ratio. A
source S1 marked plan_anchor (an anchored first discovery) is listed
unsampled over keys.anchored_window instead: the discovery-length window
ending at its last_event_time; its listing rows and level=stratum docs carry
window_anchor=last_event, and rate_per_hour is over that window.

Due: no non-retired level=stratum row under the current stratum_field, or the
newest last_seen_run among those rows is this run (a rerun relists) or at
least discovery.stratum_list_interval_seconds before the slot start.

Listed rows: a value that is reserved or not a valid identity, or a row
without a positive integer count, is skipped and recorded in ctx.errors.

Ranking: the values listed this run together with the stored non-retired
level=stratum rows of the current field that this listing missed (a sampled
listing misses rare values), by listed_events descending then stratum_value.
A missed stratum ranks on its stored listed_events and keeps them. The first
discovery.max_strata_per_source are active, the rest
deferred; share_of_source is each rate_per_hour over the sum across the
ranked strata. A missed stratum whose last_seen_run is
retention.stratum_retire_days old is retired with its field rows instead. A
listed value whose row is retired is reactivated: its field rows return to
presence=unobserved when it ranks active, and are deleted when it ranks
deferred. A stratum that drops from active to deferred loses its
field rows (deferred strata have no field rows).

Stratum key change: when the resolved stratum_field differs from the stored
matalog_sources.stratum_field (to or from __all__ included), the change takes
effect only once a listing under the new key succeeds with at least one usable
row (an unstratified new key needs no listing). Then the old level=stratum
rows and their field rows are retired with retired_run and the source is
entered in ctx.state["rekeyed_sources"]. Until then the source stays on the
stored key, and an empty listing is recorded in ctx.errors. A change to
__all__ stages one kind=stratum mode=listing row for the __all__ stratum
(events_seen 0, sample_ratio 1) so the summary index records the change.

A source in ctx.state["sources_all"] that S1 skipped gets its __all__ row
(state active) when none is stored, so every enumerated source has one.

ctx.state written:
  strata: OrderedDict source_key -> list of the source's search targets this
    run, in rank order, for every source handled: the active
    level=stratum rows of a stratified source, the __all__ row of an
    unstratified one. Sources follow ctx.state["sources"] order. Each entry
    is the matalog_strata document S10 will write (stored doc merged with
    this run's staged columns: identity, stratum_label, value_kind, level,
    prunable, state, listed_events, listed_sample_ratio, rate_per_hour,
    share_of_source, first_seen_run, last_seen_run, discovery_due_run,
    last_discovered_run, cur_*, base_*, ...) plus, not columns:
      filter: keys.stratum_filter(stratum_field, stratum_value)
      search_sourcetype: the sourcetype the source search uses
      version_field: the source's version field, "" when none
      priority: the source's priority this run
      rank: position within the source, 0 first
  strata_by_key: OrderedDict stratum_key -> the same entry objects.
  rekeyed_sources: source_key -> {"previous_stratum_field", "stratum_field"}
    for every source whose stratum key changed this run.
  sources: each entry gets stratum_field, version_field, strata_count and
    strata_deferred set in place.

ctx.counts: strata_total (targets plus deferred strata across the sources
handled) and strata_over_cap (state=deferred). strata_deferred on the run
record belongs to S3.
"""
import collections
import fnmatch

from .. import keys
from .. import rows
from .. import writer
from ..runner import Step

LISTING_FIELD = "matalog_sv"
TARGET_STATES = ("active",)
KV_CHUNK = 200
_DISABLED = (0, "0", False, "false", "False")


# SPL.

def stratum_value_eval(stratum_field, out=LISTING_FIELD):
    """eval computing the stratum value per event with the sentinel rules of keys.stratum_value_of."""
    f = keys._eval_field(stratum_field)
    sep = 'urldecode("%1F")'
    return ('eval %s=case(isnull(%s), "%s", mvcount(%s)>1, "%s".%s.mvjoin(mvsort(mvdedup(%s)), %s), %s=="", "%s", true(), %s)'
            % (out, f, keys.MISSING, f, keys.MULTI, sep, f, sep, f, keys.EMPTY, f))


def source_search(src_index, search_sourcetype):
    return "search index=%s sourcetype=%s" % (keys._spl_quote(src_index), keys._spl_quote(search_sourcetype))


def listing_spl(src_index, search_sourcetype, stratum_field):
    """The S2 listing search of one source."""
    return "%s | %s | stats count by %s | sort 0 -count" % (
        source_search(src_index, search_sourcetype), stratum_value_eval(stratum_field), LISTING_FIELD)


def parse_listed_value(raw):
    """Stratum value of one listing result; the __multi__ set is re-encoded so its order is Python's."""
    if isinstance(raw, list):
        raw = raw[0] if raw else None
    if raw is None:
        return None
    raw = str(raw)
    if keys.is_multi(raw):
        return keys.multi_value(keys.multi_values(raw))
    return raw


# Stratum config.

def _enabled(row):
    return row.get("enabled", 1) not in _DISABLED


def _specificity(pattern):
    has_wildcard = any(ch in pattern for ch in "*?[")
    literal = len(pattern.replace("*", "").replace("?", ""))
    return (0 if has_wildcard else 1, literal)


def resolve_config(config_rows, src_index, src_sourcetype):
    """The winning matalog_stratum_config row for a source, or None.

    Enabled rows of the sourcetype whose index_pattern matches the index; an
    exact index name beats a wildcard, more literal characters beat fewer,
    origin=user beats seed, then _key.
    """
    index = src_index.lower()
    candidates = []
    for row in config_rows:
        if row.get("src_sourcetype") != src_sourcetype or not _enabled(row):
            continue
        pattern = str(row.get("index_pattern") or "*").lower()
        if not fnmatch.fnmatchcase(index, pattern):
            continue
        candidates.append(((_specificity(pattern), 1 if row.get("origin") == "user" else 0), str(row.get("_key", "")), row))
    if not candidates:
        return None
    candidates.sort(key=lambda c: (c[0][0], c[0][1]), reverse=True)
    best = candidates[0][0]
    tied = sorted((c for c in candidates if c[0] == best), key=lambda c: c[1])
    return tied[0][2]


# Helpers.

def _query_by_keys(client, collection, column, values, fields=None):
    out = []
    values = sorted(set(v for v in values if v))
    for start in range(0, len(values), KV_CHUNK):
        out.extend(client.kv_query(collection, query={column: {"$in": values[start:start + KV_CHUNK]}}, fields=fields))
    return out


def _int(value, default=None):
    if value is None or value == "":
        return default
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _float(value, default=None):
    if value is None or value == "":
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _count(value):
    """A listing row's count as a positive int, or None."""
    number = _float(value)
    if number is None or number != int(number) or number < 1:
        return None
    return int(number)


def _source_list(state_sources):
    if state_sources is None:
        return []
    if isinstance(state_sources, dict):
        return list(state_sources.values())
    return list(state_sources)


class _Plan(object):
    """Per-source working state."""

    def __init__(self, src, stored_source, stored_strata):
        self.src = src
        self.source_key = src["source_key"]
        self.src_index = keys.norm_index(src["src_index"])
        self.src_sourcetype = keys.norm_sourcetype(src["src_sourcetype"])
        self.stored_source = stored_source or {}
        self.stored = collections.OrderedDict((d["_key"], d) for d in stored_strata)
        self.search_sourcetype = self.stored_source.get("search_sourcetype") or src.get("search_sourcetype") or self.src_sourcetype
        self.priority = _float(src.get("priority"), 0.0)
        self.anchor = bool(src.get("plan_anchor")) and _float(src.get("last_event_time")) is not None
        self.window = None
        self.ratio = 1
        self.staged_keys = set()
        self.rekey = False
        self.rerun_rekey = False
        self.config_field = keys.ALL
        self.config_version = ""
        self.field = keys.ALL
        self.version_field = ""
        self.previous_field = ""
        self.due = False
        self.listing = None
        self.listed = collections.OrderedDict()


class EnumerateStrata(Step):
    """List the strata of each stratified source whose last listing is due; see the module docstring."""

    name = "S2"
    label = "enumerate_strata"

    def run(self, ctx):
        sources = _source_list(ctx.state.get("sources"))
        ctx.state["strata"] = collections.OrderedDict()
        ctx.state["strata_by_key"] = collections.OrderedDict()
        ctx.state["rekeyed_sources"] = collections.OrderedDict()
        self.retire_strata = set()
        self.reactivate_strata = set()
        self.defer_strata = set()
        self.total = 0
        self.over_cap = 0
        self.stage_skipped_all_rows(ctx, sources)
        if not sources:
            ctx.counts["strata_total"] = 0
            ctx.counts["strata_over_cap"] = 0
            return
        config_rows = ctx.client.kv_query("matalog_stratum_config")
        source_keys = [s["source_key"] for s in sources]
        stored_sources = ctx.existing("matalog_sources", source_keys)
        stored_strata = collections.defaultdict(list)
        for doc in _query_by_keys(ctx.client, "matalog_strata", "source_key", source_keys):
            stored_strata[doc.get("source_key")].append(doc)
        plans = []
        for src in sources:
            plan = _Plan(src, stored_sources.get(src["source_key"]), stored_strata.get(src["source_key"], []))
            self.configure(ctx, plan, config_rows)
            plans.append(plan)
        self.list_due(ctx, [p for p in plans if p.due])
        for plan in plans:
            self.apply(ctx, plan)
        self.update_field_rows(ctx)
        ctx.counts["strata_total"] = self.total
        ctx.counts["strata_over_cap"] = self.over_cap

    def stage_skipped_all_rows(self, ctx, sources):
        """The __all__ row of every enumerated source S1 skipped that has none stored; nothing is listed or searched for it."""
        handled = set(s["source_key"] for s in sources)
        skipped = [e for e in (ctx.state.get("sources_all") or {}).values()
                   if e.get("source_key") not in handled and e.get("src_index") and e.get("src_sourcetype")]
        if not skipped:
            return
        all_keys = dict((keys.stratum_key(e["src_index"], e["src_sourcetype"], keys.ALL, keys.ALL), e) for e in skipped)
        stored = ctx.existing("matalog_strata", list(all_keys))
        for key, entry in all_keys.items():
            if key in stored or ctx.staged("matalog_strata", key):
                continue
            ctx.stage_kv("matalog_strata", rows.strata_doc(entry["src_index"], entry["src_sourcetype"], keys.ALL, keys.ALL,
                                                           state="active", first_seen_run=ctx.run_id))

    # Planning.

    def configure(self, ctx, plan, config_rows):
        row = resolve_config(config_rows, plan.src_index, plan.src_sourcetype)
        if row is not None:
            plan.config_field = keys.norm_stratum_field(str(row.get("stratum_field") or "").strip())
            plan.config_version = str(row.get("version_field") or "").strip() if plan.config_field != keys.ALL else ""
        stored_field = plan.stored_source.get("stratum_field") or ""
        retired_here = [d for d in plan.stored.values() if d.get("level") == "stratum" and d.get("retired_run") == ctx.run_id
                        and d.get("stratum_field") != plan.config_field]
        plan.previous_field = stored_field
        if stored_field and stored_field != plan.config_field:
            plan.rekey = True
        elif retired_here and stored_field in ("", plan.config_field):
            # A rerun of the run that changed the key: the stored source already carries the new key.
            plan.rekey = plan.rerun_rekey = True
            plan.previous_field = retired_here[0].get("stratum_field")
        if plan.config_field == keys.ALL:
            plan.due = False
            return
        current = [d for d in plan.stored.values() if d.get("level") == "stratum" and d.get("stratum_field") == plan.config_field
                   and d.get("state") != "retired"]
        last = max([d.get("last_seen_run") for d in current if d.get("last_seen_run")] or [""])
        if not current or not last or last >= ctx.run_id:
            plan.due = True
        else:
            age = ctx.slot_start - keys.slot_start_of(last)
            plan.due = age >= ctx.settings.discovery.stratum_list_interval_seconds

    def listing_window(self, ctx, plan):
        """(earliest, latest, sample_ratio) of the source's listing: the slot window, or the anchored one unsampled."""
        if plan.anchor:
            earliest, latest = keys.anchored_window(ctx.settings, plan.src.get("last_event_time"))
            return earliest, latest, 1
        earliest, latest = ctx.windows["stratum_list"]
        return earliest, latest, int(ctx.settings.discovery.stratum_list_sample_ratio or 1)

    def list_due(self, ctx, plans):
        if not plans:
            return
        tasks = []
        for plan in plans:
            spl = listing_spl(plan.src_index, plan.search_sourcetype, plan.config_field)
            earliest, latest, ratio = self.listing_window(ctx, plan)
            plan.window, plan.ratio = (earliest, latest), ratio

            def job(spl=spl, subject=plan.source_key, earliest=earliest, latest=latest, ratio=ratio):
                return ctx.client.search(spl, earliest=earliest, latest=latest, sample_ratio=ratio, step=self.name, subject_key=subject)
            tasks.append((plan.source_key, job))
        results, deferred = ctx.budget.map(self.name, tasks)
        for plan, result in zip(plans, results):
            if isinstance(result, Exception):
                ctx.error(self.name, plan.source_key, "listing not run: %s: %s" % (result.__class__.__name__, result))
                continue
            if not result.ok:
                ctx.error(self.name, plan.source_key, "listing %s: %s" % (result.status, "; ".join(str(m.get("text", "")) for m in result.messages[:3])))
                continue
            plan.listing = result
            plan.listed = self.parse_listing(ctx, plan)

    def parse_listing(self, ctx, plan):
        """OrderedDict stratum_value -> listed_events of one successful listing, skipping unusable rows."""
        listed = collections.OrderedDict()
        for row in plan.listing.results:
            value = parse_listed_value(row.get(LISTING_FIELD))
            try:
                keys.check_identity(value, "stratum_value")
                if value == keys.ALL:
                    raise keys.IdentityError("stratum_value __all__ is reserved")
            except keys.IdentityError as exc:
                ctx.error(self.name, plan.source_key, "listed value skipped: %s" % exc)
                continue
            count = _count(row.get("count"))
            if count is None:
                ctx.error(self.name, plan.source_key, "listed value skipped: %r has no positive count (%r)" % (value, row.get("count")))
                continue
            listed[value] = listed.get(value, 0) + count
        return listed

    # Applying.

    def apply(self, ctx, plan):
        if plan.rekey and not plan.rerun_rekey and plan.config_field != keys.ALL and plan.listing is not None and not plan.listed:
            ctx.error(self.name, plan.source_key, "listing under stratum_field %r returned no values; key change not applied" % plan.config_field)
            plan.listing = None
        if plan.rekey and not plan.rerun_rekey and plan.config_field != keys.ALL and plan.listing is None:
            # The new stratified key has no successful listing yet: stay on the stored key.
            plan.field = plan.previous_field
            plan.version_field = plan.stored_source.get("version_field") or ""
            applied = False
        else:
            plan.field, plan.version_field = plan.config_field, plan.config_version
            applied = plan.rekey
        if applied:
            ctx.state["rekeyed_sources"][plan.source_key] = {"previous_stratum_field": plan.previous_field, "stratum_field": plan.field}
            for doc in plan.stored.values():
                if doc.get("level") == "stratum" and doc.get("stratum_field") != plan.field and doc.get("state") != "retired":
                    self.retire(ctx, plan, doc)
            if plan.field == keys.ALL:
                earliest, latest = ctx.windows["stratum_list"]
                all_key = keys.stratum_key(plan.src_index, plan.src_sourcetype, keys.ALL, keys.ALL)
                ctx.stage(self.listing_row(ctx, plan, keys.ALL, all_key, 0, 1, earliest, latest, ""))
        all_values = {"state": "active", "first_seen_run": ctx.run_id}
        if plan.field == keys.ALL:
            all_values["last_seen_run"] = ctx.run_id
        if plan.listing is not None and plan.field != keys.ALL:
            listed = self.apply_listing(ctx, plan)
            ratio = int(plan.listing.sample_ratio or 1)
            total = sum(listed.values())
            all_values.update(last_seen_run=ctx.run_id, listed_events=int(total), listed_sample_ratio=ratio,
                              rate_per_hour=self.rate(ctx, total, ratio, plan.window), share_of_source=1.0 if total > 0 else 0.0)
        self.stage_stratum(ctx, plan, rows.strata_doc(plan.src_index, plan.src_sourcetype, keys.ALL, keys.ALL, **all_values))
        self.publish(ctx, plan)

    def stage_stratum(self, ctx, plan, doc):
        ctx.stage_kv("matalog_strata", doc)
        plan.staged_keys.add(doc["_key"])

    def rate(self, ctx, listed_events, ratio, window=None):
        """rate_per_hour of a listed count over the listing window (the slot window unless an anchored one is given)."""
        seconds = float(window[1] - window[0]) if window else float(ctx.settings.discovery.stratum_list_window_seconds)
        return float(listed_events) * int(ratio) * 3600.0 / seconds if seconds > 0 else 0.0

    def apply_listing(self, ctx, plan):
        """Stage the strata of one successful listing; returns plan.listed."""
        result = plan.listing
        ratio = int(result.sample_ratio or 1)
        earliest, latest = plan.window or ctx.windows["stratum_list"]
        anchor = rows.ANCHOR_LAST_EVENT if plan.anchor else None
        listed = plan.listed
        pool = []
        for value, count in listed.items():
            key = keys.stratum_key(plan.src_index, plan.src_sourcetype, plan.field, value)
            pool.append((key, value, count, self.rate(ctx, count, ratio, plan.window), True))
        retire_after = int(ctx.settings.retention.stratum_retire_days) * 86400
        listed_keys = set(p[0] for p in pool)
        for key, doc in plan.stored.items():
            if key in listed_keys or doc.get("level") != "stratum" or doc.get("stratum_field") != plan.field or doc.get("state") == "retired":
                continue
            last = doc.get("last_seen_run") or doc.get("first_seen_run")
            if last and ctx.slot_start - keys.slot_start_of(last) >= retire_after:
                self.retire(ctx, plan, doc)
                continue
            count = _int(doc.get("listed_events"), 0) or 0
            rate = _float(doc.get("rate_per_hour"))
            if rate is None:
                rate = self.rate(ctx, count, _int(doc.get("listed_sample_ratio"), 1) or 1)
            pool.append((key, doc.get("stratum_value"), count, rate, False))
        pool.sort(key=lambda p: (-p[2], str(p[1])))
        cap = int(ctx.settings.discovery.max_strata_per_source)
        total_rate = sum(p[3] for p in pool)
        for position, (key, value, count, rate, is_listed) in enumerate(pool):
            stored = plan.stored.get(key) or {}
            if position < cap:
                state = "active"
            else:
                state = "deferred"
            if stored.get("state") == "retired":
                (self.reactivate_strata if state in TARGET_STATES else self.defer_strata).add(key)
            elif stored.get("state") in TARGET_STATES and state == "deferred":
                self.defer_strata.add(key)
            share = (rate / total_rate) if total_rate > 0 else 0.0
            if is_listed:
                doc = rows.strata_doc(plan.src_index, plan.src_sourcetype, plan.field, value, state=state, listed_events=int(count),
                                      listed_sample_ratio=ratio, rate_per_hour=rate, share_of_source=share,
                                      first_seen_run=ctx.run_id, last_seen_run=ctx.run_id, retired_run=None)
                if anchor:
                    doc["window_anchor"] = anchor
                self.stage_stratum(ctx, plan, doc)
                ctx.stage(self.listing_row(ctx, plan, value, key, count, ratio, earliest, latest, result.sid, window_anchor=anchor))
            else:
                self.stage_stratum(ctx, plan, rows.kv_doc("matalog_strata", key, state=state, share_of_source=share))
        return listed

    def listing_row(self, ctx, plan, value, key, count, ratio, earliest, latest, sid, window_anchor=None):
        """kind=stratum mode=listing summary row for one listed value."""
        ident = rows.stratum_identity(plan.src_index, plan.src_sourcetype, plan.field, value)
        values = collections.OrderedDict(ident)
        values.update({
            "kind": "stratum", "run_id": ctx.run_id, "attempt": ctx.attempt, "profiled_as": ctx.profiled_as,
            "row_id": keys.k(ctx.run_id, "listing", key), "mode": "listing",
            "earliest": float(earliest), "latest": float(latest), "sample_ratio": int(ratio), "events_seen": int(count),
            "events_scanned": None, "scan_ratio": None, "fields_found": None, "truncated": None, "fields_truncated": None,
            "prunable": keys.prunable(value), "version_top": [], "version_top_counts": [],
            "sid": sid or "", "search_seconds": None, "window_anchor": window_anchor,
        })
        row = collections.OrderedDict((column, values.get(column)) for column in rows.columns_for(kind="stratum"))
        return rows.validate(row, kind="stratum")

    def retire(self, ctx, plan, doc):
        self.stage_stratum(ctx, plan, rows.kv_doc("matalog_strata", doc["_key"], state="retired", retired_run=ctx.run_id))
        self.retire_strata.add(doc["_key"])
        self.reactivate_strata.discard(doc["_key"])

    # Outputs.

    def publish(self, ctx, plan):
        """Merged view of the source's strata: targets into ctx.state, counts onto the source."""
        all_key = keys.stratum_key(plan.src_index, plan.src_sourcetype, keys.ALL, keys.ALL)
        merged = [writer.apply_roll("matalog_strata", ctx.kv["matalog_strata"].get(key) or {}, plan.stored.get(key))
                  for key in sorted(set(plan.stored) | plan.staged_keys)]
        if plan.field == keys.ALL:
            targets = [d for d in merged if d.get("_key") == all_key]
            deferred = []
        else:
            current = [d for d in merged if d.get("level") == "stratum" and d.get("stratum_field") == plan.field]
            targets = [d for d in current if d.get("state") in TARGET_STATES]
            deferred = [d for d in current if d.get("state") == "deferred"]
        targets.sort(key=lambda d: (-(_int(d.get("listed_events"), 0) or 0), str(d.get("stratum_value"))))
        order = []
        for rank, doc in enumerate(targets):
            entry = collections.OrderedDict(doc)
            entry.update(filter=keys.stratum_filter(entry["stratum_field"], entry["stratum_value"]), search_sourcetype=plan.search_sourcetype,
                         version_field=plan.version_field, priority=plan.priority, rank=rank)
            ctx.state["strata_by_key"][doc["_key"]] = entry
            order.append(entry)
        ctx.state["strata"][plan.source_key] = order
        strata_count = len(targets)
        strata_deferred = len(deferred)
        self.total += strata_count + strata_deferred
        self.over_cap += strata_deferred
        ctx.stage_kv("matalog_sources", rows.sources_doc(plan.src_index, plan.src_sourcetype, stratum_field=plan.field,
                                                         version_field=plan.version_field, strata_count=strata_count,
                                                         strata_deferred=strata_deferred))
        plan.src.update(stratum_field=plan.field, version_field=plan.version_field, strata_count=strata_count, strata_deferred=strata_deferred)

    def update_field_rows(self, ctx):
        """Retire, reactivate or delete the field rows of strata whose state changed this run."""
        wanted = self.retire_strata | self.reactivate_strata | self.defer_strata
        if not wanted:
            return
        for doc in _query_by_keys(ctx.client, "matalog_fields", "stratum_key", wanted, fields=["_key", "stratum_key", "presence"]):
            stratum = doc.get("stratum_key")
            if stratum in self.retire_strata:
                ctx.stage_kv("matalog_fields", rows.kv_doc("matalog_fields", doc["_key"], presence="retired", retired_run=ctx.run_id))
            elif stratum in self.defer_strata:
                ctx.delete_kv("matalog_fields", doc["_key"])
            elif stratum in self.reactivate_strata and doc.get("presence") == "retired":
                ctx.stage_kv("matalog_fields", rows.kv_doc("matalog_fields", doc["_key"], presence="unobserved", retired_run=None))
