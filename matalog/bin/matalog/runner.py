"""Step interface, run context, step order, crash replay, rebuild and the run record lifecycle.

A Step has a name and run(ctx); it stages summary rows and KV documents on the
context and writes nothing itself. commit(ctx) is the commit protocol. run_once
drives one attempt of one run_id end to end.
"""
import collections
import logging
import os
import socket
import threading
import time
import traceback

from . import budget as budget_mod
from . import keys
from . import rows as rows_mod
from . import settings as settings_mod
from . import writer as writer_mod

LOG = logging.getLogger("matalog")

STEP_ORDER = ("S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "S10")
STEP_LABELS = collections.OrderedDict([
    ("S1", "enumerate_sources"), ("S2", "enumerate_strata"), ("S3", "discover"), ("S4", "profile"), ("S5", "read_config"),
    ("S6", "parse_usage"), ("S7", "classify"), ("S8", "derive_meaning"), ("S10", "commit"),
])
REBUILD_STEP = "R0"
MAX_ERRORS = 50
LOCK_COLLECTION = "matalog_run_lock"
SUMMARY_KINDS_REBUILT = ("source", "stratum", "field")
# Run record columns that claim work whose KV writes a crash replay does not restore (usage pass, type versions, CIM
# coverage); a replayed record drops them so S6, S7 and S8 redo that work on the next run.
REPLAY_UNCLAIMED = ("objects_total", "objects_parsed", "objects_partial", "objects_failed", "audit_watermark",
                    "type_versions", "type_versions_hash", "reclassified_types", "cim_datasets", "cim_datasets_unresolved", "cim_mapped")


class StepFailed(Exception):
    """A step raised; the run continues as partial unless the step is required."""


class Step(object):
    """Base class of every profiler step.

    name is S1 to S10 (REBUILD_STEP for the rebuild reader); label is the
    contract's step name. run(ctx) returns nothing and writes only to ctx.
    """

    name = ""
    label = ""
    required = False

    def run(self, ctx):
        raise NotImplementedError("%s.run" % self.__class__.__name__)


class RunContext(object):
    """Everything a step reads and writes.

    settings, client, budget: the run's configuration, REST client and job pool.
    run_id, attempt, slot_start, now, run_mode, profiled_as, app_context: run identity.
    windows: name -> (earliest, latest) from keys.windows.
    summary: kind -> list of staged summary rows (stage()).
    kv: collection -> OrderedDict(_key -> partial doc) staged for S10 (stage_kv()).
    kv_deletes: collection -> set of keys to delete at S10 (delete_kv()).
    errors: list of {step, subject, message} (error()).
    state: free dict for data passed between steps; keys are agreed between
    step authors (sources, strata, planned, replayed, previous_attempt are the names in use).
    counts: run record counters a step owns (sources_total, strata_due, ...);
    a rows.RunCounts, so a name that is not a matalog_runs column raises in the step that sets it.
    run_record: the matalog_runs document of this attempt.
    previous_run: the last committed matalog_runs document before this run_id,
    set after crash replay, so a replayed run counts as committed.

    Staged summary rows are written to the index as they accumulate: once the
    unwritten rows reach write.write_batch_rows or write.write_batch_bytes a
    batch goes out under the current step. While hold_origin is set (a normal
    run until S5 has run), full kind=field rows stay unwritten and out of that
    count, so S5 can set their origin before they reach the index.
    ctx.summary keeps every row staged this run, written or not.
    """

    def __init__(self, settings, client, budget, run_id, attempt, slot_start, now, run_mode="normal", profiled_as="", app_context=settings_mod.APP):
        self.settings = settings
        self.client = client
        self.budget = budget
        self.run_id = run_id
        self.attempt = attempt
        self.slot_start = slot_start
        self.now = now
        self.run_mode = run_mode
        self.profiled_as = profiled_as
        self.app_context = app_context
        self.windows = keys.windows(settings, slot_start)
        self.summary = collections.OrderedDict((kind, []) for kind in rows_mod.SUMMARY_KINDS)
        self.kv = collections.OrderedDict((c, collections.OrderedDict()) for c in rows_mod.COLLECTIONS)
        self.kv_deletes = collections.OrderedDict((c, set()) for c in rows_mod.COLLECTIONS)
        self.errors = []
        self.state = {}
        self.counts = rows_mod.RunCounts()
        self.run_record = None
        self.previous_run = None
        self.committed = False
        self.write_report = None
        self.rows_written = collections.OrderedDict()
        self.log = LOG
        self.summary_writer = writer_mod.SummaryWriter(client, settings, slot_start, run_id=run_id, attempt=attempt)
        self.kv_writer = writer_mod.KVWriter(client, settings)
        self.current_step = ""
        self.unwritten = []
        self.unwritten_bytes = 0
        self.hold_origin = run_mode == "normal"
        self.held_count = 0
        self.flush_reports = []
        self.commit_row_written = False
        self.flush_failed = False
        self._write_lock = threading.RLock()

    @property
    def run(self):
        """The identity dict row builders take."""
        return {"run_id": self.run_id, "attempt": self.attempt, "profiled_as": self.profiled_as}

    def stage(self, row):
        """Stage a validated summary row; the row must already fit profile.max_row_bytes.

        When the row would not fit the batch of unwritten rows, that batch is
        written first, so every write job in a step carries one full batch.
        Safe to call from budget.map callables: staging and writing hold one lock.
        """
        rows_mod.validate(row)
        if row["kind"] == "commit":
            raise rows_mod.RowError("the commit row is written by runner.commit only")
        if self.run_mode == "mirror":
            self.summary[row["kind"]].append(row)
            return row
        size = rows_mod.row_bytes(row)
        if size > self.settings.profile.max_row_bytes:
            raise rows_mod.RowError("row of kind %s is %d bytes, over profile.max_row_bytes" % (row["kind"], size))
        w = self.settings.write
        cost = writer_mod.payload_bytes(writer_mod.encode_line(row, self.slot_start))
        with self._write_lock:
            if self.held(row):
                self.summary[row["kind"]].append(row)
                self.unwritten.append(row)
                self.held_count += 1
                return row
            open_rows = len(self.unwritten) - self.held_count
            full = open_rows + 1 > w.write_batch_rows or self.unwritten_bytes + cost + 2 > w.write_batch_bytes
            if open_rows and full and not self.flush_failed:
                try:
                    self.flush(self.current_step or "S10")
                except writer_mod.WriteError as exc:
                    # The rows stay unwritten; commit() writes them or fails the run.
                    self.flush_failed = True
                    self.error(self.current_step or "S10", "write", str(exc))
            self.summary[row["kind"]].append(row)
            self.add_unwritten(row, cost)
        return row

    def held(self, row):
        return self.hold_origin and row.get("kind") == "field" and row.get("shape") == "full"

    def release_held(self):
        """End hold_origin: held rows count as unwritten again and go out with the next batch."""
        with self._write_lock:
            if not self.hold_origin:
                return
            self.hold_origin = False
            self.held_count = 0
            self.unwritten_bytes = sum(writer_mod.payload_bytes(writer_mod.encode_line(r, self.slot_start)) for r in self.unwritten)

    def add_unwritten(self, row, cost=None):
        if cost is None:
            cost = writer_mod.payload_bytes(writer_mod.encode_line(row, self.slot_start))
        with self._write_lock:
            self.unwritten.append(row)
            self.unwritten_bytes += cost

    def flush(self, step="S10"):
        """Write every unwritten row that is not held; returns the WriteReport. Raises writer.WriteError on a failed batch."""
        with self._write_lock:
            if self.hold_origin and self.held_count:
                kept = [r for r in self.unwritten if self.held(r)]
                pending = [r for r in self.unwritten if not self.held(r)]
                self.unwritten, self.unwritten_bytes, self.held_count = kept, 0, len(kept)
            else:
                pending, self.unwritten, self.unwritten_bytes = self.unwritten, [], 0
            if not pending:
                return writer_mod.WriteReport()
            try:
                report = self.summary_writer.write(pending, step=step)
            except writer_mod.WriteError as exc:
                if exc.report is not None:
                    self.flush_reports.append(exc.report)
                    done = exc.report.rows
                    for row in pending[done:]:
                        self.add_unwritten(row)
                raise
            self.flush_reports.append(report)
            return report

    def stage_kv(self, collection, doc):
        """Stage a partial KV document; later stages for the same _key update it column by column."""
        rows_mod.validate(doc, collection=collection, partial=True)
        staged = self.kv[collection].get(doc["_key"])
        if staged is None:
            self.kv[collection][doc["_key"]] = collections.OrderedDict(doc)
        else:
            staged.update(doc)
        self.kv_deletes[collection].discard(doc["_key"])
        return self.kv[collection][doc["_key"]]

    def staged(self, collection, key):
        return self.kv[collection].get(key)

    def delete_kv(self, collection, key):
        if collection not in self.kv:
            raise rows_mod.RowError("unknown collection %s" % collection)
        self.kv[collection].pop(key, None)
        self.kv_deletes[collection].add(key)

    def error(self, step, subject, message):
        """Record an error for the run record; the first MAX_ERRORS are kept."""
        entry = {"step": step, "subject": str(subject or ""), "message": str(message)[:1000]}
        if len(self.errors) < MAX_ERRORS:
            self.errors.append(entry)
        self.log.warning("%s %s: %s", step, subject, message)
        return entry

    def existing(self, collection, keys_list):
        """Stored documents for keys, as {_key: doc}."""
        return self.client.kv_get_many(collection, list(keys_list))

    def after_roll(self, collection, key, stored=None):
        """The document S10 will write for a staged key: the staged doc merged onto the stored one under the roll rule.

        For a run newer than the stored snapshot, base_* is the stored cur_*;
        on a rerun it is the stored base_*. stored is the stored doc when the
        caller already has it.
        """
        staged = self.kv[collection].get(key)
        if stored is None:
            stored = self.existing(collection, [key]).get(key)
        if staged is None:
            return stored
        return writer_mod.apply_roll(collection, staged, stored)

    def audit_window(self):
        """(earliest, latest) of this run's _audit read for S6.

        latest is the slot start less budget.window_lag_seconds, like every
        other window; earliest is the previous committed run's latest (its slot
        start less the same lag), so consecutive committed runs read adjoining
        windows, or usage.audit_initial_lookback_days before latest when no
        run has committed.
        """
        lag = self.settings.budget.window_lag_seconds
        latest = self.slot_start - lag
        if self.previous_run and self.previous_run.get("run_id"):
            earliest = keys.slot_start_of(self.previous_run["run_id"]) - lag
        else:
            earliest = latest - self.settings.usage.audit_initial_lookback_days * 86400
        return earliest, latest


def search_cost_sink(ctx):
    """The budget sink: every job's cost row lands on the context."""
    def cost_row(budget, step, subject_key, result):
        return rows_mod.search_cost_row(ctx.run, result, step, subject_key)

    def sink(row):
        ctx.summary["search_cost"].append(row)
        if ctx.run_mode != "mirror":
            ctx.add_unwritten(row)
    return cost_row, sink


def bind(ctx):
    """Wire the budget and client to the context's identity."""
    cost_row, sink = search_cost_sink(ctx)
    ctx.budget.cost_row = cost_row
    ctx.budget.sink = sink
    ctx.budget.bind(ctx.run_id, ctx.attempt, ctx.profiled_as)
    ctx.client.run_id = ctx.run_id
    ctx.client.budget = ctx.budget
    ctx.client.settings = ctx.settings
    return ctx


def new_context(settings, client, now=None, run_mode="normal", profiled_as=None, clock=None):
    """Build a RunContext for the slot containing now, with the attempt number from matalog_runs."""
    now = time.time() if now is None else float(now)
    slot = keys.slot_start(now, settings.budget.cycle_seconds)
    run_id = keys.run_id_of(slot)
    profiled_as = profiled_as or client.username or settings.usage.service_account
    previous = client.kv_get("matalog_runs", run_id)
    attempt = int(previous.get("attempt", 0)) + 1 if previous else 1
    budget = budget_mod.Budget(settings, clock=clock)
    ctx = RunContext(settings, client, budget, run_id, attempt, slot, now, run_mode=run_mode, profiled_as=profiled_as)
    ctx.state["previous_attempt"] = previous
    return bind(ctx)


# Run record lifecycle.

def open_run_record(ctx):
    """Write the matalog_runs row with status=running before any step runs.

    A rerun keeps the committed flag and committed_attempt of the attempt
    before it until its own commit row is written: that attempt's rows stay
    authoritative meanwhile.
    """
    settings = ctx.settings
    prior = ctx.state.get("previous_attempt") or {}
    doc = rows_mod.runs_doc(
        ctx.run_id, attempt=ctx.attempt, committed=1 if _int(prior.get("committed")) == 1 else 0,
        committed_attempt=_int(prior.get("committed_attempt")),
        run_mode=ctx.run_mode, status="running", profiled_as=ctx.profiled_as, app_context=ctx.app_context,
        started_at=float(ctx.budget.started_at), budget=settings.budget_json(), errors=[])
    ctx.run_record = doc
    plan_run_record(ctx)
    return doc


def plan_run_record(ctx):
    """Set previous_run, the write reserve and config_hash from the current KV state, and save the run record.

    run_once calls it when the record opens and again after the seed upsert
    and crash replay, so a replayed run is the previous run and the seeds are hashed.
    """
    settings = ctx.settings
    stratum_rows = ctx.client.kv_query("matalog_stratum_config")
    decl_keys = [d["_key"] for d in ctx.client.kv_query("matalog_declarations", fields=["_key"])]
    previous = last_committed_run(ctx)
    ctx.previous_run = previous
    ctx.budget.write_reserve = budget_mod.compute_write_reserve(settings, previous)
    doc = ctx.run_record
    doc["config_hash"] = settings.config_hash(stratum_rows, decl_keys)
    doc["write_reserve"] = ctx.budget.write_reserve
    ctx.client.kv_batch_save("matalog_runs", [writer_mod.kv_encode(doc)])
    return doc


def _int(value):
    if value is None or value == "":
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def last_committed_run(ctx):
    """The newest committed matalog_runs row before this run_id, or None."""
    docs = ctx.client.kv_query("matalog_runs", query={"committed": 1, "run_id": {"$lt": ctx.run_id}}, sort="run_id:-1", limit=1)
    return docs[0] if docs else None


def finalize_run_record(ctx, status):
    """Write the final matalog_runs row: counters, cost, status and errors.

    A counter that does not validate is dropped and recorded as an error, and
    the run becomes failed, so the record never stays at status=running.
    """
    doc = collections.OrderedDict(ctx.run_record or {})
    doc.update(ctx.budget.snapshot())
    write_bytes = sum(int(r.write_bytes) for r in ctx.flush_reports)
    doc.update({
        "status": status, "finished_at": float(ctx.budget.clock()),
        "write_bytes": write_bytes,
        "rows_written": dict(ctx.rows_written),
    })
    if ctx.committed:
        doc.update({"committed": 1, "committed_attempt": ctx.attempt})
    for column, value in ctx.counts.items():
        trial = collections.OrderedDict([("_key", ctx.run_id), (column, value)])
        try:
            rows_mod.validate(trial, collection="matalog_runs", partial=True)
        except rows_mod.RowError as exc:
            ctx.error("S10", column, "run record counter dropped: %s" % exc)
            doc["status"] = "failed"
            continue
        doc[column] = value
    doc["errors"] = list(ctx.errors)
    doc["wall_seconds"] = round(float(doc["finished_at"]) - float(doc["started_at"]), 3)
    try:
        rows_mod.validate(doc, collection="matalog_runs", partial=True)
    except rows_mod.RowError as exc:
        ctx.error("S10", "run_record", str(exc))
        doc = collections.OrderedDict((c, v) for c, v in doc.items() if c in rows_mod.COLLECTIONS["matalog_runs"] or c == "_key")
        doc.update({"status": "failed", "errors": list(ctx.errors)})
    ctx.run_record = doc
    ctx.client.kv_batch_save("matalog_runs", [writer_mod.kv_encode(doc)])
    return doc


# The run lock: one attempt at a time per catalog.

def lock_doc(ctx):
    return collections.OrderedDict([
        ("_key", rows_mod.LOCK_KEY), ("run_id", ctx.run_id), ("attempt", ctx.attempt), ("pid", os.getpid()),
        ("host", socket.gethostname()), ("started_at", float(ctx.budget.started_at))])


def lock_is_live(ctx, held):
    """A lock younger than budget.max_wall_seconds_per_cycle; an older one is stale and taken over."""
    started = _float(held.get("started_at"))
    if started is None:
        return False
    return float(ctx.budget.started_at) - started < ctx.settings.budget.max_wall_seconds_per_cycle


def acquire_lock(ctx):
    """Take the lock for this attempt; returns the live lock document of another attempt when one holds it."""
    held = ctx.client.kv_get(LOCK_COLLECTION, rows_mod.LOCK_KEY)
    if held and lock_is_live(ctx, held) and not (held.get("run_id") == ctx.run_id and _int(held.get("pid")) == os.getpid()):
        return held
    ctx.client.kv_batch_save(LOCK_COLLECTION, [lock_doc(ctx)])
    return None


def release_lock(ctx):
    """Delete the lock when this attempt still holds it; a lock taken over by a later attempt is left alone."""
    held = ctx.client.kv_get(LOCK_COLLECTION, rows_mod.LOCK_KEY)
    if held and held.get("run_id") == ctx.run_id and _int(held.get("attempt")) == ctx.attempt and _int(held.get("pid")) == os.getpid():
        ctx.client.kv_delete(LOCK_COLLECTION, {"_key": rows_mod.LOCK_KEY})


def skipped_run_record(ctx, held):
    """The matalog_runs document of an attempt that found a live lock: status skipped_locked, saved unless the holder is this run_id.

    The holder of the same slot owns the record of that run_id; its record is left to it.
    """
    now = float(ctx.budget.clock())
    message = "live lock held by run %s attempt %s pid %s on %s since %s" % (
        held.get("run_id"), held.get("attempt"), held.get("pid"), held.get("host"), keys.stamp(_float(held.get("started_at")) or 0.0))
    ctx.error("run", "lock", message)
    doc = rows_mod.runs_doc(
        ctx.run_id, attempt=ctx.attempt, committed=0, run_mode=ctx.run_mode, status="skipped_locked", profiled_as=ctx.profiled_as,
        app_context=ctx.app_context, started_at=float(ctx.budget.started_at), finished_at=now, wall_seconds=round(now - float(ctx.budget.started_at), 3),
        errors=list(ctx.errors))
    ctx.run_record = doc
    if held.get("run_id") != ctx.run_id:
        ctx.client.kv_batch_save("matalog_runs", [writer_mod.kv_encode(doc)])
    return doc


def _float(value):
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


# Seeds and crash replay, done before S1.

def seed_stratum_config(ctx):
    """Upsert the [stratum:<sourcetype>] seed stanzas; a user row with the same key wins."""
    seeds = ctx.settings.stratum_seeds
    if not seeds:
        return 0
    docs = [rows_mod.stratum_config_doc(s["index_pattern"], s["src_sourcetype"], s["stratum_field"], s["version_field"], set_at=float(ctx.now)) for s in seeds]
    existing = ctx.client.kv_get_many("matalog_stratum_config", [d["_key"] for d in docs])
    to_save = []
    for doc in docs:
        stored = existing.get(doc["_key"])
        if stored and stored.get("origin") == "user":
            continue
        if stored and stored.get("origin") == "seed":
            doc["enabled"] = int(stored.get("enabled", 1))
            same = all(stored.get(c) == doc.get(c) for c in ("index_pattern", "src_sourcetype", "stratum_field", "version_field"))
            if same and stored.get("set_at") is not None:
                doc["set_at"] = stored["set_at"]
        else:
            doc["enabled"] = 1
        to_save.append(writer_mod.kv_encode(doc))
    if to_save:
        ctx.client.kv_batch_save("matalog_stratum_config", to_save)
    return len(to_save)


def replay_candidates(ctx):
    """Run records of other run_ids that may need replay: still running (the process died), or committed=0
    with committed_attempt set (the commit row was written, a KV batch was not)."""
    found = collections.OrderedDict()
    for query in ({"status": "running"}, {"committed": 0, "committed_attempt": {"$gt": 0}}):
        for run in ctx.client.kv_query("matalog_runs", query=query):
            if run.get("run_id") and run.get("run_id") != ctx.run_id:
                found[run["run_id"]] = run
    return [found[r] for r in sorted(found)]


def replay_uncommitted(ctx):
    """Finish runs that crashed after their commit row: replay their KV writes from committed rows.

    A record still at status=running is probed once (one job for all of
    them) for its highest attempt with a commit row. With none, or none newer
    than the attempt already committed, it is marked failed and never probed
    again; KV was untouched. A run whose commit row exists but whose KV writes
    did not finish is replayed as a bounded rebuild of that attempt, oldest
    rows first through the roll rule, then marked committed. The replay
    restores sources, strata and fields only, so the record drops the columns
    in REPLAY_UNCLAIMED and the next run redoes the usage pass, the type
    version check and CIM coverage. Returns the run_ids replayed.
    """
    replayed = []
    candidates = replay_candidates(ctx)
    if not candidates:
        return replayed
    running = [r["run_id"] for r in candidates if r.get("status") == "running"]
    probed = {}
    if running:
        probe = ctx.client.search(writer_mod.committed_attempts_spl(running), step="S1", subject_key="replay")
        if not probe.ok:
            ctx.error("S1", "replay", "commit probe failed: %s" % probe.status)
            running = []
        for row in probe.results if probe.ok else []:
            attempt = _int(row.get("attempt"))
            if row.get("run_id") and attempt:
                probed[row["run_id"]] = attempt
    for run in candidates:
        try:
            if replay_one(ctx, run, running, probed):
                replayed.append(run["run_id"])
        except Exception as exc:
            ctx.error("S1", "replay:%s" % run.get("run_id"), "%s: %s" % (exc.__class__.__name__, exc))
    return replayed


def close_stale_records(ctx):
    """A mirror run replays nothing: a record left at status=running is marked failed, and this run rebuilds everything."""
    for run in replay_candidates(ctx):
        if run.get("status") != "running":
            continue
        errors = list(run.get("errors") or [])
        errors.append({"step": "S1", "subject": "mirror", "message": "the run did not finish; this mirror run rebuilds every collection"})
        run.update({"status": "failed", "errors": errors[:MAX_ERRORS]})
        ctx.client.kv_batch_save("matalog_runs", [writer_mod.kv_encode(run)])
    return []


def replay_one(ctx, run, running, probed):
    """Replay or close one candidate record; True when its KV writes were replayed."""
    run_id = run["run_id"]
    committed_attempt = _int(run.get("committed_attempt")) or 0
    if run.get("status") == "running":
        if run_id not in running:
            return False
        attempt = probed.get(run_id, 0)
        needs_replay = attempt > committed_attempt or (attempt == committed_attempt and attempt > 0 and _int(run.get("committed")) != 1)
        if not needs_replay:
            run["status"] = "failed"
            ctx.client.kv_batch_save("matalog_runs", [writer_mod.kv_encode(run)])
            return False
    else:
        attempt = committed_attempt
    max_rows = ctx.settings.rebuild.rebuild_max_rows
    result = ctx.client.search(writer_mod.run_rows_spl(run_id, attempt, SUMMARY_KINDS_REBUILT, max_rows),
                               step="S1", subject_key="replay:%s" % run_id, max_rows=max_rows)
    if not result.ok:
        ctx.error("S1", "replay:%s" % run_id, "could not read committed rows: %s" % result.status)
        return False
    if len(result.results) >= max_rows:
        ctx.error("S1", "replay:%s" % run_id, "rebuild.rebuild_max_rows reached; replay is incomplete")
        return False
    for collection, docs in kv_from_rows(result.results, ctx.settings).items():
        ctx.kv_writer.write(collection, list(docs.values()))
    for column in REPLAY_UNCLAIMED:
        run.pop(column, None)
    errors = list(run.get("errors") or [])
    errors.append({"step": "S1", "subject": "replay",
                   "message": "replayed sources, strata and fields from the committed rows; the usage pass, type versions and CIM coverage of this run are redone by the next run"})
    run["errors"] = errors[:MAX_ERRORS]
    run.update({"committed": 1, "committed_attempt": attempt, "status": "ok" if run.get("status") == "running" else run.get("status")})
    ctx.client.kv_batch_save("matalog_runs", [writer_mod.kv_encode(run)])
    return True


def kv_from_rows(results, settings=None):
    """KV documents implied by committed summary rows: collection -> OrderedDict(_key -> doc).

    Rows of one key are folded oldest first (by run_id, discovery before
    profile) through writer.merge_snapshots, so cur_* comes from the newest row
    of each mode, base_* from the one before, and shared columns from the
    newest row that carries them. With settings, kind=stratum mode=listing rows
    become strata state through steps.s10_commit.listing_strata; without, they
    are left out.
    """
    grouped = collections.OrderedDict()
    listings = []
    for raw in results:
        row = writer_mod.summary_row_from_result(raw)
        if row and row.get("kind") == "stratum" and row.get("mode") == "listing":
            listings.append(row)
            continue
        mapped = rows_mod.kv_from_summary(row) if row else None
        if not mapped:
            continue
        collection, doc = mapped
        order = (str(row.get("run_id")), 1 if row.get("mode") == "profile" else 0, 1 if row.get("shape") == "full" else 0)
        grouped.setdefault(collection, collections.OrderedDict()).setdefault(doc["_key"], []).append((order, doc))
    out = collections.OrderedDict()
    for collection, by_key in grouped.items():
        out[collection] = collections.OrderedDict()
        for key, entries in by_key.items():
            entries.sort(key=lambda e: e[0])
            out[collection][key] = writer_mod.merge_snapshots(collection, [doc for _, doc in entries])
    if listings and settings is not None:
        from .steps import s10_commit
        strata = out.setdefault("matalog_strata", collections.OrderedDict())
        for key, doc in s10_commit.listing_strata(settings, listings).items():
            strata[key] = writer_mod.apply_roll("matalog_strata", doc, strata.get(key))
    return out


# Commit protocol (S10 calls this).

def flush_summary(ctx, step="S10"):
    """Write every unwritten summary row, repeating while the write jobs add search_cost rows.

    Returns the WriteReport of this flush. The cost rows of the last jobs stay
    unwritten; commit() writes them in the commit row's batch.
    """
    ctx.release_held()
    report = writer_mod.WriteReport()
    while any(row["kind"] != "search_cost" for row in ctx.unwritten):
        _add_report(report, ctx.flush(step))
    return report


def _add_report(total, part):
    total.rows += part.rows
    total.write_bytes += part.write_bytes
    total.write_searches += part.write_searches
    total.sids.extend(part.sids)
    for kind, count in part.rows_by_kind.items():
        total.rows_by_kind[kind] = total.rows_by_kind.get(kind, 0) + count


def rows_written_by_kind(ctx):
    out = collections.OrderedDict()
    for report in ctx.flush_reports:
        for kind, count in report.rows_by_kind.items():
            out[kind] = out.get(kind, 0) + count
    return out


def commit(ctx, type_versions_hash="", before_kv=None):
    """The commit protocol: summary rows, the commit row, the KV batches, then committed=1.

    The search_cost rows of the last write jobs go in the commit row's batch,
    ahead of it; only the commit job's own cost row is not written. Once the
    commit row is written the run record says committed=0 with
    committed_attempt set, which marks the attempt for replay if a KV batch
    then fails. Returns the commit row. Raises WriteError when a write failed;
    KV is then untouched if the failure was before the commit row. before_kv,
    when given, is called with ctx right before the KV batches (the human
    meaning mirror is read there). A mirror run takes commit_mirror.
    """
    if ctx.run_mode == "mirror":
        return commit_mirror(ctx, before_kv)
    flush_summary(ctx)
    for collection, docs in ctx.kv.items():
        if "updated_run_id" in rows_mod.COLLECTIONS[collection]:
            for doc in docs.values():
                doc["updated_run_id"] = ctx.run_id
    rows_written = rows_written_by_kind(ctx)
    pending_cost = [r for r in ctx.unwritten if r["kind"] == "search_cost"]
    if pending_cost:
        rows_written["search_cost"] = rows_written.get("search_cost", 0) + len(pending_cost)
    write_bytes = sum(int(r.write_bytes) for r in ctx.flush_reports)
    commit_doc = rows_mod.commit_row(ctx.run, ctx.run_mode, ctx.budget.clock(), (ctx.run_record or {}).get("config_hash", ""),
                                     rows_written, ctx.budget.snapshot(), write_bytes, type_versions_hash=type_versions_hash)
    rows_written["commit"] = 1
    ctx.unwritten, ctx.unwritten_bytes = [], 0
    try:
        commit_report = ctx.summary_writer.write(pending_cost + [commit_doc], step="S10")
    except writer_mod.WriteError as exc:
        if exc.report is not None:
            ctx.flush_reports.append(exc.report)
        raise
    ctx.flush_reports.append(commit_report)
    ctx.write_report = writer_mod.WriteReport()
    for report in ctx.flush_reports:
        _add_report(ctx.write_report, report)
    ctx.commit_row_written = True
    ctx.summary["commit"] = [commit_doc]
    run_doc = ctx.run_record
    run_doc.update({"committed": 0, "committed_attempt": ctx.attempt})
    ctx.client.kv_batch_save("matalog_runs", [writer_mod.kv_encode(run_doc)])
    if before_kv is not None:
        before_kv(ctx)
    kv_counts = collections.OrderedDict()
    for collection, docs in ctx.kv.items():
        if docs:
            kv_counts[collection] = ctx.kv_writer.write(collection, list(docs.values()))
            ctx.budget.rows_written("S10", len(docs))
    for collection, keys_set in ctx.kv_deletes.items():
        if keys_set:
            ctx.kv_writer.delete(collection, sorted(keys_set))
    ctx.rows_written = collections.OrderedDict(rows_written)
    ctx.rows_written.update(kv_counts)
    ctx.committed = True
    run_doc.update({"committed": 1, "committed_attempt": ctx.attempt})
    ctx.client.kv_batch_save("matalog_runs", [writer_mod.kv_encode(run_doc)])
    return commit_doc


def commit_mirror(ctx, before_kv=None):
    """The commit of a mirror run: the KV batches, then committed=1. Nothing reaches the summary index."""
    ctx.unwritten, ctx.unwritten_bytes = [], 0
    for collection, docs in ctx.kv.items():
        if "updated_run_id" in rows_mod.COLLECTIONS[collection]:
            for doc in docs.values():
                doc["updated_run_id"] = ctx.run_id
    if before_kv is not None:
        before_kv(ctx)
    kv_counts = collections.OrderedDict()
    for collection, docs in ctx.kv.items():
        if docs:
            kv_counts[collection] = ctx.kv_writer.write(collection, list(docs.values()))
            ctx.budget.rows_written("S10", len(docs))
    for collection, keys_set in ctx.kv_deletes.items():
        if keys_set:
            ctx.kv_writer.delete(collection, sorted(keys_set))
    ctx.rows_written = kv_counts
    ctx.committed = True
    run_doc = ctx.run_record
    run_doc.update({"committed": 1, "committed_attempt": ctx.attempt})
    ctx.client.kv_batch_save("matalog_runs", [writer_mod.kv_encode(run_doc)])
    return None


# Rebuild mode.

class RebuildStep(Step):
    """run_mode=rebuild: read the latest committed rows per subject and stage the KV documents they imply.

    Reads kind=source, stratum and field rows (at most rebuild.rebuild_max_rows
    per kind, newest first, two per subject and mode), maps each through
    rows.kv_from_summary and folds them per key with kv_from_rows: cur_* from
    the newest row of each mode, base_* from the one before, shared columns
    from the newest row carrying them. kind=stratum mode=listing rows bypass
    kv_from_summary: strata take state, rate_per_hour and share_of_source from
    them (steps.s10_commit.listing_strata). Field rows of retired strata get
    presence=retired, those of deferred strata are dropped, and is_rollup=1
    field rows are recomputed from their children (steps.s10_commit.rollup_fields).
    matalog_field_types and the field type columns are rebuilt from the full
    rows against the stored types (steps.s7_classify.rebuild_edges).
    matalog_cim_coverage and the cim_fields and cim_via columns are left as
    stored; the next normal run's S8 recomputes them. The usage_* columns of
    the source-level field rows and of the sources are summarized again from
    the stored matalog_objects and matalog_usage (steps.s6_parse_usage.rebuild_usage).
    The run's audit_watermark is set usage.audit_initial_lookback_days before
    its audit window end, so the next normal run rereads _audit and restores
    last_human_search_time and _user. Issues no search against data.
    """

    name = REBUILD_STEP
    label = "rebuild"
    required = True

    def run(self, ctx):
        from .steps import s10_commit
        max_rows = ctx.settings.rebuild.rebuild_max_rows
        results, listings = [], []
        for kind in SUMMARY_KINDS_REBUILT:
            result = ctx.client.search(writer_mod.latest_rows_spl(kind, max_rows), step=self.name, subject_key=kind, max_rows=max_rows)
            if not result.ok:
                raise StepFailed("rebuild read of kind=%s failed: %s" % (kind, result.status))
            if len(result.results) >= max_rows:
                ctx.error(self.name, kind, "rebuild.rebuild_max_rows reached; older subjects were not rebuilt")
            for raw in result.results:
                row = writer_mod.summary_row_from_result(raw)
                if row and row.get("kind") == "stratum" and row.get("mode") == "listing":
                    listings.append(row)
                else:
                    results.append(raw)
        # Values, samples and profile_id come from the newest full row, which can be older than the two newest rows per mode.
        full_rows = self.read(ctx, writer_mod.latest_full_rows_spl(max_rows), "full", max_rows)
        results.extend(full_rows)
        derived = kv_from_rows(results)
        strata = derived.setdefault("matalog_strata", collections.OrderedDict())
        for key, doc in s10_commit.listing_strata(ctx.settings, listings).items():
            strata[key] = writer_mod.apply_roll("matalog_strata", doc, strata.get(key))
        self.apply_first_seen(ctx, derived, self.read(ctx, writer_mod.first_seen_spl(max_rows), "first_seen", max_rows))
        fields = derived.setdefault("matalog_fields", collections.OrderedDict())
        unknown = sorted(set(d.get("stratum_key") for d in fields.values()
                             if d.get("stratum_value") not in (None, keys.ALL) and not (strata.get(d.get("stratum_key")) or {}).get("state")))
        stored = ctx.existing("matalog_strata", unknown) if unknown else {}
        stored_states = dict((key, doc.get("state")) for key, doc in stored.items())
        for key, doc in list(fields.items()):
            if doc.get("stratum_value") in (None, keys.ALL):
                continue
            stratum = strata.get(doc.get("stratum_key")) or {}
            state = stratum.get("state") or stored_states.get(doc.get("stratum_key"))
            if state == "deferred":
                del fields[key]
            elif state == "retired":
                doc.update(presence="retired", retired_run=stratum.get("retired_run") or doc.get("retired_run"))
        for doc in fields.values():
            # S5 sets these from the declarations on the next normal run; a field no declaration names keeps 0.
            doc.setdefault("declared", 0)
            doc.setdefault("origin_conflict", 0)
        apply_absence(ctx.settings, fields, strata)
        complete_strata(ctx.settings, derived.get("matalog_sources", {}), strata, fields, stored_states)
        rollups = s10_commit.rollup_fields(ctx.settings, fields, strata, stored_states)
        complete_sources(ctx.settings, derived.get("matalog_sources", {}), strata, fields, rollups)
        self.apply_usage(ctx, fields, rollups, derived.get("matalog_sources", {}))
        for collection, docs in derived.items():
            for doc in docs.values():
                ctx.stage_kv(collection, doc)
        for doc in rollups.values():
            ctx.stage_kv("matalog_fields", doc)
        self.rewind_audit(ctx)
        from .steps import s7_classify
        try:
            s7_classify.rebuild_edges(ctx, full_rows)
        except budget_mod.BudgetExhausted:
            raise
        except Exception as exc:
            ctx.error(self.name, "field_types", "edge rebuild raised %s: %s" % (exc.__class__.__name__, exc))

    def apply_usage(self, ctx, fields, rollups, sources):
        """usage_* columns of the source-level field rows and the sources from the stored objects and edges."""
        from .steps import s6_parse_usage
        docs = collections.OrderedDict(fields)
        docs.update(rollups)
        try:
            s6_parse_usage.rebuild_usage(ctx, docs, sources)
        except Exception as exc:
            ctx.error(self.name, "usage", "usage summary raised %s: %s" % (exc.__class__.__name__, exc))

    def rewind_audit(self, ctx):
        """No summary row carries last_human_search_*: the next run reads _audit again from usage.audit_initial_lookback_days."""
        from .steps import s6_parse_usage
        latest = ctx.audit_window()[1]
        s6_parse_usage.set_watermark(ctx, latest - ctx.settings.usage.audit_initial_lookback_days * 86400)

    def read(self, ctx, spl, subject, max_rows):
        """Rows of one supplementary rebuild read; a failed read is recorded and leaves the columns it feeds as the main reads left them."""
        try:
            result = ctx.client.search(spl, step=self.name, subject_key=subject, max_rows=max_rows)
        except budget_mod.BudgetExhausted:
            raise
        except Exception as exc:
            ctx.error(self.name, subject, "rebuild read raised %s: %s" % (exc.__class__.__name__, exc))
            return []
        if not result.ok:
            ctx.error(self.name, subject, "rebuild read %s" % result.status)
            return []
        if len(result.results) >= max_rows:
            ctx.error(self.name, subject, "rebuild.rebuild_max_rows reached")
        return result.results

    def apply_first_seen(self, ctx, derived, rows):
        """first_seen_run is the oldest committed run of the subject, which the two newest rows per subject do not show."""
        collection_of = {"source": "matalog_sources", "stratum": "matalog_strata", "field": "matalog_fields"}
        for row in rows:
            docs = derived.get(collection_of.get(row.get("kind")), {})
            doc = docs.get(row.get("matalog_subject"))
            first = row.get("first_seen_run")
            if doc is not None and first:
                doc["first_seen_run"] = min(str(first), str(doc.get("first_seen_run") or first))


def complete_strata(settings, sources, strata, fields, stored_states):
    """Stratum columns rebuild derives from the rebuilt rows themselves.

    Every source gets its __all__ row (state active; for a stratified source
    it is the rollup row, never searched, with the newest listing's totals); a
    searched stratum without listing state takes its stored state, else
    active, with last_seen_run its newest row; discovery_due_run is last_discovered_run plus
    budget.max_staleness_cycles slots; field_count counts present field rows.
    """
    b = settings.budget
    present = collections.Counter(d.get("stratum_key") for d in fields.values() if d.get("presence") == "present" and _int(d.get("is_rollup")) != 1)
    by_source = collections.defaultdict(list)
    for doc in strata.values():
        by_source[doc.get("source_key")].append(doc)
    for source_key, source in sources.items():
        all_key = keys.stratum_key(source["src_index"], source["src_sourcetype"], keys.ALL, keys.ALL)
        if all_key in strata:
            continue
        listed = [d for d in by_source.get(source_key, []) if d.get("level") == "stratum" and d.get("state") == "active"]
        if not listed:
            strata[all_key] = rows_mod.strata_doc(source["src_index"], source["src_sourcetype"], keys.ALL, keys.ALL, state="active",
                                                  first_seen_run=source.get("first_seen_run") or None)
            continue
        newest = max(str(d.get("last_seen_run") or "") for d in listed)
        current = [d for d in listed if str(d.get("last_seen_run") or "") == newest]
        total = sum(_int(d.get("listed_events")) or 0 for d in current)
        ratio = max([_int(d.get("listed_sample_ratio")) or 1 for d in current] or [1])
        strata[all_key] = rows_mod.strata_doc(
            source["src_index"], source["src_sourcetype"], keys.ALL, keys.ALL, state="active",
            first_seen_run=source.get("first_seen_run") or min(str(d.get("first_seen_run") or newest) for d in listed),
            last_seen_run=newest or None, listed_events=total, listed_sample_ratio=ratio,
            rate_per_hour=sum(float(d.get("rate_per_hour") or 0.0) for d in current), share_of_source=1.0 if total > 0 else 0.0)
    for key, doc in strata.items():
        if not doc.get("state"):
            doc["state"] = stored_states.get(key) or "active"
            seen = [str(doc[c]) for c in ("cur_run_id", "last_profiled_run") if doc.get(c)]
            if seen and not doc.get("last_seen_run"):
                doc["last_seen_run"] = max(seen)
        if doc.get("last_discovered_run"):
            doc["discovery_due_run"] = keys.run_id_add(str(doc["last_discovered_run"]), b.max_staleness_cycles, b.cycle_seconds)
            doc["field_count"] = present.get(key, 0)
        if doc.get("last_profiled_run"):
            try:
                doc["profile_due_run"] = keys.run_id_of(keys.slot_start_of(str(doc["last_profiled_run"])) + settings.profile.profile_interval_seconds)
            except ValueError:
                pass


def apply_absence(settings, fields, strata):
    """The S3 absence rule on rebuilt rows: a measured field the stratum's newest qualifying discovery did not return is unobserved.

    consecutive_unseen counts the qualifying discoveries after the field's
    last one among the two the stratum row keeps (cur_* and base_*), so a
    rebuild restores it up to 2. A row never discovered keeps it empty.
    """
    minimum = int(settings.discovery.min_events_for_absence)
    for doc in fields.values():
        if _int(doc.get("is_rollup")) == 1:
            continue
        doc.setdefault("is_rollup", 0)
        doc.setdefault("rollup_strata", 0)
        stratum = strata.get(doc.get("stratum_key")) or {}
        discovery_run = stratum.get("cur_run_id")
        seen_run = str(doc.get("cur_disc_run_id") or "")
        if not discovery_run or not seen_run:
            continue
        cur_qualifies = _int(stratum.get("cur_fields_truncated")) == 0 and (_int(stratum.get("cur_events_seen")) or 0) >= minimum
        unseen = 0
        if seen_run != str(discovery_run):
            unseen += 1 if cur_qualifies else 0
            base_run = str(stratum.get("base_run_id") or "")
            if base_run and seen_run < base_run and (_int(stratum.get("base_events_seen")) or 0) >= minimum:
                unseen += 1
            if doc.get("presence") == "present" and cur_qualifies:
                doc["presence"] = "unobserved"
        doc["consecutive_unseen"] = unseen


def complete_sources(settings, sources, strata, fields, rollups):
    """Source columns rebuild derives from the rebuilt strata and field rows."""
    threshold = settings.profile.sample_volume_threshold
    interval = settings.profile.profile_interval_seconds
    by_source = collections.defaultdict(list)
    for doc in strata.values():
        by_source[doc.get("source_key")].append(doc)
    field_counts = collections.Counter()
    for doc in list(fields.values()) + list(rollups.values()):
        if doc.get("level") == "source" and doc.get("presence") == "present":
            field_counts[doc.get("source_key")] += 1
    ratios = collections.defaultdict(dict)
    for doc in fields.values():
        if doc.get("cur_prof_run_id") and doc.get("cur_prof_sample_ratio") is not None:
            ratios[doc.get("source_key")][str(doc["cur_prof_run_id"])] = _int(doc.get("cur_prof_sample_ratio"))
    for key, source in sources.items():
        source.setdefault("state", "active")
        own = by_source.get(key, [])
        if not any(d.get("last_seen_run") or d.get("cur_run_id") or d.get("last_profiled_run") for d in own):
            # Never listed, discovered or profiled: the later steps' columns stay empty, as on the live row.
            continue
        stratified = [d for d in own if d.get("level") == "stratum" and d.get("state") != "retired"]
        source["stratum_field"] = stratified[0].get("stratum_field") if stratified else keys.ALL
        source["strata_count"] = sum(1 for d in (stratified or own) if d.get("state") == "active")
        source["strata_deferred"] = sum(1 for d in stratified if d.get("state") == "deferred")
        source["field_count"] = field_counts.get(key, 0)
        daily = _int(source.get("daily_events"))
        if daily is not None:
            source["profile_mode"] = "sampled" if daily >= threshold else "unsampled"
        # A source's profile is complete when every active stratum has one; the newest stratum profile is the run that completed it.
        searched = [d for d in (stratified or own) if d.get("state") == "active"]
        profiled = [str(d["last_profiled_run"]) for d in searched if d.get("last_profiled_run")]
        source["strata_profile_due"] = len(searched) - len(profiled)
        if searched and len(profiled) == len(searched):
            source["last_profiled_run"] = max(profiled)
            source["next_profile_due"] = float(keys.slot_start_of(max(profiled)) + interval)
            if ratios[key].get(max(profiled)) is not None:
                source["sample_ratio"] = ratios[key][max(profiled)]
        # last_discovered_run: the latest run after which every active stratum had a discovery, the oldest of their latest.
        discovered = [str(d["last_discovered_run"]) for d in searched if d.get("last_discovered_run")]
        if searched and len(discovered) == len(searched):
            source["last_discovered_run"] = min(discovered)


# Driving one attempt.

def default_steps():
    from . import steps
    return steps.all_steps()


def steps_for_mode(run_mode, steps=None):
    steps = list(steps if steps is not None else default_steps())
    if run_mode in rows_mod.REBUILD_MODES:
        by_name = dict((s.name, s) for s in steps)
        return [RebuildStep()] + [by_name[n] for n in ("S10",) if n in by_name]
    return steps


def run_steps(ctx, steps):
    """Run steps in order; a failed required step stops the run. Returns the status."""
    status = "ok"
    for step in steps:
        started = ctx.budget.clock()
        ctx.current_step = step.name
        try:
            ctx.log.info("%s %s start", step.name, step.label)
            if step.name == "S3":
                # S5 needs one walklex and one probe job per index after S3 and S4 have planned.
                sources = list(ctx.state.get("sources") or []) + [v for v in (ctx.state.get("sources_all") or {}).values() if v.get("state") != "gone"]
                indexes = set((v.get("src_index") if isinstance(v, dict) else None) for v in sources)
                due = ctx.state.get("indexes_due")
                if due is not None:
                    scanned = set(str(i).lower() for i in due)
                    indexes = set(i for i in indexes if i and str(i).lower() in scanned)
                ctx.budget.config_reserve = 2 * len([i for i in indexes if i])
                from .steps import s6_parse_usage
                ctx.budget.held_searches = s6_parse_usage.searches_held(ctx)
            step.run(ctx)
        except budget_mod.BudgetExhausted as exc:
            ctx.error(step.name, exc.subject_key, "budget ceiling %s" % exc.ceiling)
            status = "partial"
        except Exception as exc:
            ctx.error(step.name, "", "%s: %s" % (exc.__class__.__name__, exc))
            ctx.log.debug(traceback.format_exc())
            if step.required or step.name == "S10":
                return "failed"
            status = "partial"
        finally:
            ctx.budget.step_wall(step.name, ctx.budget.clock() - started)
            if step.name == "S5":
                ctx.release_held()
    if ctx.budget.exhausted and status == "ok":
        status = "partial"
    return status


def run_once(settings, client, now=None, run_mode="normal", steps=None, profiled_as=None, clock=None):
    """One attempt of the run whose slot contains now. Returns the final matalog_runs document."""
    if run_mode not in rows_mod.RUN_MODES:
        raise ValueError("run_mode must be normal, rebuild or mirror")
    ctx = new_context(settings, client, now=now, run_mode=run_mode, profiled_as=profiled_as, clock=clock)
    ctx.log.info("run %s attempt %d mode %s", ctx.run_id, ctx.attempt, run_mode)
    held = acquire_lock(ctx)
    if held is not None:
        ctx.log.warning("run %s attempt %d skipped: %s", ctx.run_id, ctx.attempt, "lock held by run %s" % held.get("run_id"))
        return skipped_run_record(ctx, held)
    open_run_record(ctx)
    status = "ok"
    try:
        try:
            writer_mod.clear_buffer(ctx.client, ctx.run_id, ctx.attempt)
            seed_stratum_config(ctx)
            ctx.state["replayed"] = close_stale_records(ctx) if run_mode == "mirror" else replay_uncommitted(ctx)
        except Exception as exc:
            ctx.error("S1", "replay", "%s: %s" % (exc.__class__.__name__, exc))
            ctx.log.debug(traceback.format_exc())
            status = "partial"
        plan_run_record(ctx)
        step_status = run_steps(ctx, steps_for_mode(run_mode, steps))
        if step_status == "failed" or status == "failed":
            status = "failed"
        elif step_status == "partial" or status == "partial":
            status = "partial"
        if status != "failed" and not ctx.committed:
            status = "failed"
            ctx.error("S10", "", "run finished without a commit")
    except Exception as exc:
        ctx.error("run", "", "%s: %s" % (exc.__class__.__name__, exc))
        ctx.log.debug(traceback.format_exc())
        status = "failed"
    try:
        return finalize_run_record(ctx, status)
    finally:
        try:
            release_lock(ctx)
        except Exception as exc:
            ctx.log.warning("run lock not released: %s: %s", exc.__class__.__name__, exc)
