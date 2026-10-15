"""S1 enumerate_sources.

Searches, all on windows pinned to the slot (keys.windows):

- one `| tstats count max(_time)` by index and sourcetype on source_day and
  one on source_cycle; either failing fails the step, since every later
  step plans from these counts;
- one `| eventcount` listing the indexes the account can search (internal
  ones included); matalog_profiles is not enumerated;
- one licence search over license_usage.log on source_day, and the
  licenser pools endpoint only when that search returns no rows;
- one search over committed kind=source rows of matalog_profiles before
  this run, the last HISTORY_ROWS per source, for base_rate_per_hour; its
  earliest bound is the slot start of the oldest of the last HISTORY_ROWS
  committed runs in matalog_runs, so an outage does not empty the history;
- last, one `| metadata type=sourcetypes` per index whose scan is due,
  through the job pool: an index is due when a stored source of it has no
  index_scan_run or one older than budget.index_scan_interval_seconds, or
  when it has no stored source and no committed run inside the interval
  listed it in indexes_sourceless (a listed index whose metadata read and
  tstats reported no sourcetype, a metrics index); never-scanned indexes
  first, then by the highest stored source priority, cut at ceil(indexes *
  cycle_seconds / interval), at least 1;
- apps/local through the client, no search.

A budget ceiling on a tstats job fails the step. On the listing, licence or
history search it takes the same degraded path as a failed job, with an
error recorded; on the metadata jobs it defers those jobs.

ctx.state written:

- "sources": list of the sources due this run, priority descending (then
  daily_events descending, then source_key); S2, S3 and S4 plan from it.
  Skipped sources are left out: no events in the trailing cycle and no open
  work, or state gone.
- "sources_all": OrderedDict source_key -> entry for every enumerated
  source in the same order, skipped ones included; S2 gives each one its
  __all__ stratum row.
- An entry (the same dict object in both) is the stored matalog_sources doc
  with this run's S1 columns laid over it, so _key, source_key, src_index,
  src_sourcetype, priority, daily_events, events_last_cycle, profile_mode,
  state and the columns of later steps (stratum_field, last_profiled_run,
  next_profile_due, search_sourcetype, ...) are all top level. Plan fields, which are not matalog_sources columns:
    plan_due: False for a skipped source;
    plan_new: no stored doc existed;
    plan_profile_due: next_profile_due is empty or at or before the slot start;
    plan_cycles_since_discovered, plan_usage_count: the priority inputs;
    plan_sample_ratio: profile.sample_ratio when profile_mode is sampled, else 1;
    plan_anchor: True for an anchored first discovery, see below.
- "app_versions": OrderedDict app name -> version text ("" when the app
  declares none), in the order apps/local returned them.
- "apps_local": the client.apps_local() entries, for S5; not set when the
  read failed.
- "indexes": every listed index with events; "indexes_due": the ones whose
  scan runs this run, for S5 and the config reserve.

ctx.counts written: sources_total (entries in ctx.state["sources_all"]),
sources_due (entries in ctx.state["sources"]), indexes_total and
indexes_sourceless.

Open work for a source with no events in the trailing cycle is a profile due
(plan_profile_due) on a source with events in the trailing day: the discovery
window lies inside the cycle and would find nothing.

Anchored first discovery (plan_anchor): an active source with no events in
the trailing day, a last_event_time and no stored last_discovered_run is due
once so S2 and S3 can list and discover it on a window ending at
last_event_time; S4 leaves it alone that run. Once discovered it follows the
slot-pinned rule above like any other source.
"""
import collections
import math

from .. import keys
from .. import rows as rows_mod
from .. import writer as writer_mod
from ..budget import BudgetExhausted
from ..client import ClientError, JobResult
from ..runner import Step, StepFailed

HISTORY_ROWS = 7
HISTORY_MIN_SECONDS = 86400
HISTORY_MIN_CYCLES = 28

EVENTCOUNT_SPL = "| eventcount summarize=false index=* index=_* | stats sum(count) as count by index"
TSTATS_SPL = "| tstats count max(_time) as last_time where (index=* OR index=_*) by index sourcetype"
LICENCE_SPL = "search index=_internal source=*license_usage.log* type=Usage | stats sum(b) as b max(_time) as last_time by idx st"

EXCLUDED_INDEXES = (writer_mod.PROFILES_INDEX,)

STATE_ACTIVE, STATE_GONE = "active", "gone"
BYTES_OK, BYTES_UNREADABLE, BYTES_STALE, BYTES_UNAVAILABLE = "ok", "unreadable", "stale", "unavailable"


def history_spl(run_id):
    """Committed kind=source rows before run_id, one per run, the newest HISTORY_ROWS per source."""
    return '%s | where run_id<"%s" | dedup source_key run_id | dedup %d source_key | table source_key run_id events_last_cycle' % (
        writer_mod.committed_rows_spl(["source"]).rstrip(), writer_mod.spl_quote(run_id), HISTORY_ROWS)


def metadata_spl(index):
    return "| metadata type=sourcetypes index=%s" % keys._spl_quote(index)


def _int(value):
    if value is None or value == "":
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _float(value):
    if value is None or value == "":
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if math.isnan(number) or math.isinf(number):
        return None
    return number


def _list(value):
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def _first(value):
    return value[0] if isinstance(value, list) and value else value


def _identity(index, sourcetype):
    """(source_key, src_index, src_sourcetype), or None for a row without a usable identity."""
    index, sourcetype = _first(index), _first(sourcetype)
    if not isinstance(index, str) or not isinstance(sourcetype, str):
        return None
    try:
        src_index = keys.norm_index(index)
        src_sourcetype = keys.norm_sourcetype(sourcetype)
    except keys.IdentityError:
        return None
    return keys.source_key(src_index, src_sourcetype), src_index, src_sourcetype


def median(values):
    ordered = sorted(values)
    n = len(ordered)
    if n == 0:
        return None
    mid = n // 2
    if n % 2:
        return float(ordered[mid])
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def priority(daily_events, usage_count, cycles_since_discovered, settings):
    """log10(daily_events + 1) * (1 + priority_usage_weight * usage_count) * (1 + cycles_since_discovered / max_staleness_cycles)."""
    b = settings.budget
    return (math.log10(max(int(daily_events), 0) + 1)
            * (1 + b.priority_usage_weight * max(int(usage_count or 0), 0))
            * (1 + float(cycles_since_discovered) / max(int(b.max_staleness_cycles), 1)))


class EnumerateSources(Step):
    """Enumerate every source and compute this run's priorities; see the module docstring for the contract."""

    name = "S1"
    label = "enumerate_sources"
    required = True

    def run(self, ctx):
        if ctx.run_mode != "normal":
            return
        stored = self.read_stored(ctx)
        day = self.read_counts(ctx, "source_day")
        cycle = self.read_counts(ctx, "source_cycle")
        indexes = self.list_indexes(ctx, stored, day)
        due = self.indexes_due(ctx, indexes, stored, self.sourceless_known(ctx))
        ctx.state["indexes"] = list(indexes)
        ctx.state["indexes_due"] = due
        ctx.counts["indexes_total"] = len(indexes)
        licence = self.read_licence(ctx, day)
        history = self.read_history(ctx)
        meta = self.read_metadata(ctx, due)
        with_sources = set(v[0].lower() for table in (meta, day, cycle) for v in table.values())
        ctx.counts["indexes_sourceless"] = sorted(i for i in due if i.lower() in self.metadata_read and i.lower() not in with_sources)
        ctx.state["app_versions"] = self.read_apps(ctx)

        entries = []
        for key in self.enumerated_keys(stored, meta, day, cycle):
            entries.append(self.build(ctx, key, stored.get(key), meta, day, cycle, licence, history))
        entries.sort(key=lambda e: (-e["priority"], -e["daily_events"], e["source_key"]))
        ctx.state["sources_all"] = collections.OrderedDict((e["source_key"], e) for e in entries)
        ctx.state["sources"] = [e for e in entries if e["plan_due"]]
        ctx.counts["sources_total"] = len(entries)
        ctx.counts["sources_due"] = len(ctx.state["sources"])

    # Reads.

    def read_stored(self, ctx):
        """Every stored matalog_sources doc: committed state, so usage_count is the previous committed run's."""
        return collections.OrderedDict((d["_key"], d) for d in ctx.client.kv_query("matalog_sources") if d.get("_key"))

    def read_counts(self, ctx, window):
        """source_key -> (src_index, src_sourcetype, count, last_time) from one tstats job; a failed job fails the step."""
        earliest, latest = ctx.windows[window]
        try:
            result = ctx.client.search(TSTATS_SPL, earliest=earliest, latest=latest, step=self.name, subject_key=window)
        except BudgetExhausted as exc:
            raise StepFailed("tstats on %s: budget ceiling %s" % (window, exc.ceiling))
        if not result.ok:
            raise StepFailed("tstats on %s failed: %s" % (window, result.status))
        out = collections.OrderedDict()
        for row in result.results:
            ident = _identity(row.get("index"), row.get("sourcetype"))
            if ident is None or ident[1] in EXCLUDED_INDEXES:
                continue
            key, src_index, src_sourcetype = ident
            count = _int(row.get("count")) or 0
            last = _float(_first(row.get("last_time")))
            if key in out:
                prev = out[key]
                count += prev[2]
                last = max(x for x in (last, prev[3]) if x is not None) if (last is not None or prev[3] is not None) else None
            out[key] = (src_index, src_sourcetype, count, last)
        return out

    def list_indexes(self, ctx, stored, day):
        """Indexes with events the account can search; on a failed listing, the indexes already known."""
        result = self.search_or_budget(ctx, EVENTCOUNT_SPL, subject_key="indexes")
        names = []
        if result.ok:
            for row in result.results:
                index = _first(row.get("index"))
                if isinstance(index, str) and index and (_int(row.get("count")) or 0) > 0:
                    names.append(index)
        else:
            ctx.error(self.name, "indexes", "index listing failed: %s" % result.status)
            names = [d.get("src_index") for d in stored.values()] + [v[0] for v in day.values()]
        seen = set()
        out = []
        for index in names:
            if not index or index.lower() in EXCLUDED_INDEXES or index.lower() in seen:
                continue
            seen.add(index.lower())
            out.append(index)
        return out

    def sourceless_known(self, ctx):
        """index (lower case) -> slot start of the newest committed run inside the scan interval that listed it sourceless."""
        b = ctx.settings.budget
        interval = max(int(b.index_scan_interval_seconds), 1)
        limit = int(math.ceil(float(interval) / max(int(b.cycle_seconds), 1))) + 1
        try:
            docs = ctx.client.kv_query("matalog_runs", query={"committed": 1, "run_id": {"$lt": ctx.run_id}},
                                       fields=["run_id", "indexes_sourceless"], sort="run_id:-1", limit=limit)
        except ClientError as exc:
            ctx.error(self.name, "indexes", "committed runs unreadable: %s" % exc)
            return {}
        out = {}
        for doc in docs:
            try:
                slot = keys.slot_start_of(str(doc.get("run_id") or ""))
            except ValueError:
                continue
            if slot + interval <= ctx.slot_start:
                continue
            for index in _list(doc.get("indexes_sourceless")):
                out[str(index).lower()] = max(slot, out.get(str(index).lower(), 0))
        return out

    def indexes_due(self, ctx, indexes, stored, sourceless=None):
        """The slice of indexes scanned this run: never scanned first, then stale scans by stored source priority, cut at the slice."""
        b = ctx.settings.budget
        interval = max(int(b.index_scan_interval_seconds), 1)
        slice_size = max(1, int(math.ceil(len(indexes) * float(b.cycle_seconds) / interval)))
        by_index = collections.defaultdict(list)
        for doc in stored.values():
            if doc.get("state") != STATE_GONE and doc.get("src_index"):
                by_index[str(doc["src_index"]).lower()].append(doc)
        ranked = []
        for index in indexes:
            docs = by_index.get(index.lower(), [])
            if not docs:
                if index.lower() not in (sourceless or {}):
                    ranked.append((0, 0.0, index))
                continue
            stale = False
            for doc in docs:
                scan = str(doc.get("index_scan_run") or "")
                try:
                    stale = not scan or keys.slot_start_of(scan) + interval <= ctx.slot_start
                except ValueError:
                    stale = True
                if stale:
                    break
            if stale:
                ranked.append((1, -max(_float(d.get("priority")) or 0.0 for d in docs), index))
        ranked.sort()
        return [index for _, _, index in ranked[:slice_size]]

    def search_or_budget(self, ctx, spl, **kwargs):
        """ctx.client.search under step S1; a budget ceiling comes back as a JobResult with status "budget ceiling <name>"."""
        try:
            return ctx.client.search(spl, step=self.name, **kwargs)
        except BudgetExhausted as exc:
            return JobResult(status="budget ceiling %s" % exc.ceiling, spl=spl)

    def read_metadata(self, ctx, indexes):
        """source_key -> (src_index, src_sourcetype, first_time, last_time), one metadata job per index through the pool."""
        def task(index):
            return lambda: ctx.client.metadata_sourcetypes(index, step=self.name, subject_key=index)

        results, deferred = ctx.budget.map(self.name, [(index, task(index)) for index in indexes])
        out = collections.OrderedDict()
        self.metadata_read = set()
        for index, result in zip(indexes, results):
            if isinstance(result, BudgetExhausted):
                continue
            if isinstance(result, Exception):
                ctx.error(self.name, index, "metadata: %s: %s" % (result.__class__.__name__, result))
                continue
            if not result.ok:
                ctx.error(self.name, index, "metadata failed: %s" % result.status)
                continue
            self.metadata_read.add(index.lower())
            for row in result.results:
                ident = _identity(index, row.get("sourcetype"))
                if ident is None:
                    continue
                key, src_index, src_sourcetype = ident
                first, last = _float(row.get("firstTime")), _float(row.get("lastTime"))
                if key in out:
                    pf, pl = out[key][2], out[key][3]
                    first = min(x for x in (first, pf) if x is not None) if (first is not None or pf is not None) else None
                    last = max(x for x in (last, pl) if x is not None) if (last is not None or pl is not None) else None
                out[key] = (src_index, src_sourcetype, first, last)
        if deferred:
            ctx.error(self.name, "metadata", "budget ceiling before metadata of %d index(es): %s" % (len(deferred), ", ".join(deferred[:10])))
        return out

    def read_licence(self, ctx, day):
        """{"readable", "by_source": {(src_index, src_sourcetype): (bytes, last_time)}, "squashed": set of src_index}.

        The licence search reads license_usage.log over source_day. An empty
        result is readable only when the day tstats shows _internal events
        (the account can read the log) and the licenser pools report no bytes
        used; otherwise it is unreadable.
        """
        earliest, latest = ctx.windows["source_day"]
        info = {"readable": False, "by_source": {}, "squashed": set()}
        result = self.search_or_budget(ctx, LICENCE_SPL, earliest=earliest, latest=latest, subject_key="licence")
        if result.status.startswith("budget"):
            ctx.error(self.name, "licence", "licence search not run: %s" % result.status)
        if not result.ok:
            return info
        for row in result.results:
            idx, st = _first(row.get("idx")), _first(row.get("st"))
            b = _int(row.get("b")) or 0
            last = _float(_first(row.get("last_time")))
            if not isinstance(idx, str) or not idx:
                continue
            if not isinstance(st, str) or not st:
                info["squashed"].add(idx.lower())
                continue
            ident = (idx.lower(), st)
            prev = info["by_source"].get(ident)
            if prev is not None:
                b += prev[0]
                last = max(x for x in (last, prev[1]) if x is not None) if (last is not None or prev[1] is not None) else None
            info["by_source"][ident] = (b, last)
        if result.results:
            info["readable"] = True
            return info
        if not any(v[0] == "_internal" and v[2] > 0 for v in day.values()):
            return info
        try:
            pools = ctx.client.licence_pools()
        except (ClientError, KeyError, TypeError, ValueError):
            return info
        info["readable"] = sum(int(p.get("used_bytes") or 0) for p in pools) == 0
        return info

    def history_start(self, ctx):
        """Slot start of the oldest of the last HISTORY_ROWS committed runs; a fixed trailing window when none is readable."""
        fallback = ctx.slot_start - max(HISTORY_MIN_SECONDS, HISTORY_MIN_CYCLES * ctx.settings.budget.cycle_seconds)
        try:
            docs = ctx.client.kv_query("matalog_runs", query={"committed": 1, "run_id": {"$lt": ctx.run_id}},
                                       sort="run_id:-1", limit=HISTORY_ROWS)
        except ClientError as exc:
            ctx.error(self.name, "history", "committed runs unreadable: %s" % exc)
            return fallback
        starts = []
        for doc in docs:
            try:
                starts.append(keys.slot_start_of(str(doc.get("run_id") or doc.get("_key") or "")))
            except (TypeError, ValueError):
                continue
        return min(starts) if starts else fallback

    def read_history(self, ctx):
        """source_key -> [events_last_cycle, ...] of the last committed rows, or None when the read failed."""
        start = self.history_start(ctx)
        result = self.search_or_budget(ctx, history_spl(ctx.run_id), earliest=start, latest=ctx.slot_start,
                                       subject_key="history", max_rows=ctx.settings.rebuild.rebuild_max_rows)
        if not result.ok:
            ctx.error(self.name, "history", "committed source rows unreadable: %s" % result.status)
            return None
        rows = collections.defaultdict(dict)
        for row in result.results:
            key = _first(row.get("source_key"))
            run_id = _first(row.get("run_id"))
            count = _int(_first(row.get("events_last_cycle")))
            if not key or not run_id or count is None or str(run_id) >= ctx.run_id:
                continue
            rows[key].setdefault(str(run_id), count)
        out = {}
        for key, by_run in rows.items():
            pairs = sorted(by_run.items(), reverse=True)
            out[key] = [count for _, count in pairs[:HISTORY_ROWS]]
        return out

    def read_apps(self, ctx):
        try:
            entries = list(ctx.client.apps_local())
        except ClientError as exc:
            ctx.error(self.name, "apps", "apps/local unreadable: %s" % exc)
            return collections.OrderedDict()
        ctx.state["apps_local"] = entries
        out = collections.OrderedDict()
        for entry in entries:
            name = entry.get("name")
            if name:
                version = (entry.get("content") or {}).get("version")
                out[name] = "" if version is None else str(version)
        return out

    # Per source.

    def enumerated_keys(self, stored, meta, day, cycle):
        """Sources reported this run, plus stored sources not yet gone."""
        keys_out = collections.OrderedDict()
        for table in (meta, day, cycle):
            for key in table:
                keys_out[key] = True
        for key, doc in stored.items():
            if doc.get("state") != STATE_GONE and doc.get("src_index") and doc.get("src_sourcetype"):
                keys_out[key] = True
        return list(keys_out)

    def build(self, ctx, key, stored_doc, meta, day, cycle, licence, history):
        s = ctx.settings
        stored_doc = stored_doc or {}
        ident = (meta.get(key) or day.get(key) or cycle.get(key) or (stored_doc.get("src_index"), stored_doc.get("src_sourcetype")))
        src_index, src_sourcetype = ident[0], ident[1]
        daily = day[key][2] if key in day else 0
        elc = cycle[key][2] if key in cycle else 0
        latest = ctx.windows["source_day"][1]

        values = collections.OrderedDict()
        values["profiled_as"] = ctx.profiled_as
        values["first_seen_run"] = stored_doc.get("first_seen_run") or ctx.run_id
        if daily > 0 or elc > 0:
            values["last_seen_run"] = ctx.run_id
        if key in meta and meta[key][2] is not None:
            values["first_event_time"] = meta[key][2]

        last_event = None
        if key in day and day[key][3] is not None:
            last_event = day[key][3]
        elif key in cycle and cycle[key][3] is not None:
            last_event = cycle[key][3]
        else:
            known = [_float(stored_doc.get("last_event_time")), meta[key][3] if key in meta else None]
            known = [x for x in known if x is not None]
            last_event = max(known) if known else None
        if last_event is not None:
            values["last_event_time"] = last_event

        values["events_last_cycle"] = elc
        values["daily_events"] = daily
        daily_bytes, status = self.licence_for(licence, src_index, src_sourcetype, elc, latest, s, daily_events=daily)
        values["daily_bytes"] = daily_bytes
        values["daily_bytes_status"] = status

        if history is not None and history.get(key):
            base_rate = median([c * 3600.0 / s.budget.cycle_seconds for c in history[key]])
            values["base_rate_per_hour"] = base_rate
        else:
            base_rate = _float(stored_doc.get("base_rate_per_hour"))

        gone_before = latest - s.retention.gone_after_days * 86400
        if daily == 0 and elc == 0 and last_event is not None and last_event < gone_before:
            state = STATE_GONE
        elif daily == 0 and elc == 0 and last_event is None and stored_doc.get("state") == STATE_GONE:
            state = STATE_GONE
        else:
            state = STATE_ACTIVE
        values["state"] = state

        profile_mode = "sampled" if daily >= s.profile.sample_volume_threshold else "unsampled"
        values["profile_mode"] = profile_mode
        usage_count = _int(stored_doc.get("usage_count")) or 0
        last_discovered = stored_doc.get("last_discovered_run")
        if last_discovered:
            try:
                since = max(0, keys.slots_between(last_discovered, ctx.run_id, s.budget.cycle_seconds))
            except ValueError:
                since = s.budget.max_staleness_cycles
        else:
            since = s.budget.max_staleness_cycles
        prio = priority(daily, usage_count, since, s)
        values["priority"] = prio

        doc = rows_mod.sources_doc(src_index, src_sourcetype, **values)
        ctx.stage_kv("matalog_sources", doc)
        ctx.stage(rows_mod.source_row(
            ctx.run, src_index, src_sourcetype, events_last_cycle=elc, daily_events=daily, daily_bytes=daily_bytes,
            last_event_time=last_event,
            config_apps=_list(stored_doc.get("config_apps")),
            version_top=_list(stored_doc.get("version_top")),
            version_top_counts=_list(stored_doc.get("version_top_counts"))))

        next_due = _float(stored_doc.get("next_profile_due"))
        profile_due = next_due is None or next_due <= ctx.slot_start
        # A rerun of the run that anchored sees its own last_discovered_run stored and anchors again.
        never_discovered = not last_discovered or str(last_discovered) == ctx.run_id
        anchor = state != STATE_GONE and daily == 0 and elc == 0 and last_event is not None and never_discovered
        due = state != STATE_GONE and (elc > 0 or (daily > 0 and profile_due) or anchor)
        entry = collections.OrderedDict(stored_doc)
        entry.update(doc)
        if "base_rate_per_hour" not in values:
            entry["base_rate_per_hour"] = base_rate
        entry.update([
            ("plan_due", due), ("plan_new", not stored_doc), ("plan_profile_due", profile_due and not anchor),
            ("plan_cycles_since_discovered", since), ("plan_usage_count", usage_count),
            ("plan_sample_ratio", s.profile.sample_ratio if profile_mode == "sampled" else 1),
            ("plan_anchor", anchor),
        ])
        return entry

    def licence_for(self, licence, src_index, src_sourcetype, events_last_cycle, latest, settings, daily_events=0):
        """(daily_bytes, daily_bytes_status) for one source; bytes are never estimated.

        unreadable: the licence log could not be read, or the index's rows are
        squashed so bytes cannot be attributed. unavailable: the log was read
        and holds no row for the source, whatever its events and index
        (internal indexes and sourcetype=stash never get one). stale: the
        source has events in the trailing cycle but its newest licence entry
        is older than the cycle. ok with 0 only when the log has a row for the
        source with 0 bytes.
        """
        if not licence["readable"]:
            return None, BYTES_UNREADABLE
        entry = licence["by_source"].get((src_index, src_sourcetype))
        if entry is None:
            if src_index in licence["squashed"]:
                return None, BYTES_UNREADABLE
            return None, BYTES_UNAVAILABLE
        b, last = entry
        if events_last_cycle > 0 and (last is None or last < latest - settings.budget.cycle_seconds):
            return b, BYTES_STALE
        return b, BYTES_OK
