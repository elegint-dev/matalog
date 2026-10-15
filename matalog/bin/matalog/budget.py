"""Search budget: the job pool, the ceilings, the write reserve and per-step cost accounting.

Every search job in a run passes through Budget.run_job, which checks the
ceilings before dispatch, bounds concurrency, and records one kind=search_cost
row through the sink the runner provides.
"""
import collections
import concurrent.futures
import math
import threading
import time

from .client import JobResult

CEILINGS = ("searches", "scanned", "search_seconds", "wall_seconds")
WRITE_SUBJECT = "write"


class BudgetExhausted(Exception):
    """Raised before dispatch when a ceiling is hit; the job's subject is deferred."""

    def __init__(self, ceiling, step="", subject_key=""):
        Exception.__init__(self, "budget ceiling hit: %s (step %s, subject %s)" % (ceiling, step, subject_key))
        self.ceiling = ceiling
        self.step = step
        self.subject_key = subject_key


def new_step_counters():
    return collections.OrderedDict([("searches", 0), ("scanned", 0), ("seconds", 0.0), ("rows_written", 0), ("wall_seconds", 0.0)])


def compute_write_reserve(settings, previous_run=None):
    """write_reserve = max(write_reserve_min, ceil(estimated_bytes / write_batch_bytes) + 2), at most half of max_searches_per_cycle.

    estimated_bytes is the previous committed run's write_bytes scaled by its
    strata planned over strata discovered. matalog_runs has no strata_planned
    column; strata_due (the strata S3 planned) stands for it. The floor alone
    when there is no previous run. The upper bound keeps one heavy run from
    starving the next run's discovery.
    """
    minimum = settings.write.write_reserve_min
    ceiling = max(minimum, int(settings.budget.max_searches_per_cycle) // 2)
    if not previous_run:
        return minimum
    write_bytes = float(previous_run.get("write_bytes") or 0)
    discovered = float(previous_run.get("strata_discovered") or 0)
    planned = float(previous_run.get("strata_due") or discovered)
    if write_bytes <= 0:
        return minimum
    scale = (planned / discovered) if discovered > 0 else 1.0
    estimated = write_bytes * scale
    return min(ceiling, max(minimum, int(math.ceil(estimated / float(settings.write.write_batch_bytes))) + 2))


def failed_result(exc, job=None):
    """The JobResult recorded for a job whose callable raised."""
    job = job or {}
    result = JobResult(status="failed", messages=[{"type": "ERROR", "text": "%s: %s" % (exc.__class__.__name__, exc)}],
                       spl_hash=job.get("spl_hash") or "", earliest=job.get("earliest"), latest=job.get("latest"),
                       sample_ratio=job.get("sample_ratio") or 1)
    result.error = exc.__class__.__name__
    return result


class Budget(object):
    """Ceilings, concurrency and accounting for one run.

    sink(row) receives one kind=search_cost row per job; bind() supplies the
    run identity those rows carry. clock() returns epoch seconds.
    """

    def __init__(self, settings, sink=None, clock=None, cost_row=None):
        self.settings = settings
        self.sink = sink
        self.clock = clock or time.time
        self.cost_row = cost_row
        self.max_concurrent = max(1, int(settings.budget.max_concurrent_searches))
        self.started_at = self.clock()
        self.run_id = ""
        self.attempt = 1
        self.profiled_as = ""
        self.write_reserve = settings.write.write_reserve_min
        # Searches held back from S3 and S4 planning; the runner sets them before S3
        # (S5's config jobs per index, S6's audit read).
        self.config_reserve = 0
        self.held_searches = 0
        self.exhausted = ""
        self.searches_issued = 0
        self.searches_failed = 0
        self.write_searches = 0
        self.events_scanned = 0
        self.events_matched = 0
        self.search_seconds = 0.0
        self.peak_concurrency = 0
        self.per_step = collections.OrderedDict()
        self._lock = threading.Lock()
        self._semaphore = threading.BoundedSemaphore(self.max_concurrent)
        self._running = 0

    def bind(self, run_id, attempt, profiled_as):
        self.run_id = run_id
        self.attempt = attempt
        self.profiled_as = profiled_as

    # Ceilings.

    def wall_seconds(self):
        return self.clock() - self.started_at

    def reserve_left(self):
        """The part of the write reserve not yet used by write jobs."""
        return max(0, self.write_reserve - self.write_searches)

    def plannable(self):
        """Searches S3 and S4 may still plan: max_searches_per_cycle - issued - the unused write reserve.

        Write jobs are issued out of the reserve, so a write already issued is not counted twice.
        config_reserve and held_searches are kept for the steps after S4.
        """
        return max(0, self.settings.budget.max_searches_per_cycle - self.searches_issued - self.reserve_left()
                   - int(self.config_reserve) - int(self.held_searches))

    def check(self, write=False):
        """The first ceiling a non-write job would hit, or "" when none.

        Write jobs count in searches_issued like any job but are never deferred:
        a deferred write would lose the run's rows. The write reserve is what
        keeps them inside max_searches_per_cycle.
        """
        if write:
            return ""
        with self._lock:
            return self._check_locked()

    def _check_locked(self):
        s = self.settings.budget
        if self.searches_issued >= s.max_searches_per_cycle - self.reserve_left():
            return "searches"
        if self.events_scanned >= s.max_events_scanned_per_cycle:
            return "scanned"
        if self.search_seconds >= s.max_search_seconds_per_cycle:
            return "search_seconds"
        if self.wall_seconds() >= s.max_wall_seconds_per_cycle:
            return "wall_seconds"
        return ""

    # Dispatch.

    def run_job(self, step, subject_key, fn, write=False, job=None):
        """Run fn() as one search job under the ceilings and the concurrency limit.

        fn returns a JobResult (see client.py). Raises BudgetExhausted before
        dispatch when a ceiling is hit; the first ceiling hit in the run is
        kept in self.exhausted. When fn raises, a failed JobResult carrying
        the exception class is recorded before the exception propagates; job
        holds the spl_hash, earliest, latest and sample_ratio it reports.
        """
        with self._lock:
            ceiling = "" if write else self._check_locked()
            if ceiling:
                if not self.exhausted:
                    self.exhausted = ceiling
                raise BudgetExhausted(ceiling, step, subject_key)
            self.searches_issued += 1
            if write:
                self.write_searches += 1
            counters = self.per_step.setdefault(step, new_step_counters())
            counters["searches"] += 1
        with self._semaphore:
            with self._lock:
                self._running += 1
                if self._running > self.peak_concurrency:
                    self.peak_concurrency = self._running
            try:
                result = fn()
            except Exception as exc:
                with self._lock:
                    self._running -= 1
                self.record(step, subject_key, failed_result(exc, job))
                raise
            with self._lock:
                self._running -= 1
        self.record(step, subject_key, result)
        return result

    def record(self, step, subject_key, result):
        """Add a finished job's cost and emit its search_cost row."""
        with self._lock:
            self.events_scanned += int(result.scan_count or 0)
            self.events_matched += int(result.event_count or 0)
            self.search_seconds += float(result.run_duration or 0.0)
            if result.status != "ok":
                self.searches_failed += 1
            counters = self.per_step.setdefault(step, new_step_counters())
            counters["scanned"] += int(result.scan_count or 0)
            counters["seconds"] += float(result.run_duration or 0.0)
        result.step = step
        result.subject_key = subject_key
        if self.sink is not None and self.cost_row is not None:
            self.sink(self.cost_row(self, step, subject_key, result))

    def map(self, step, tasks):
        """Run tasks concurrently: tasks are (subject_key, callable) pairs.

        Returns (results, deferred): results is a list aligned with tasks holding
        each callable's return value or the exception it raised; deferred lists
        the subject keys whose callable raised BudgetExhausted.
        """
        results = [None] * len(tasks)
        deferred = []
        if not tasks:
            return results, deferred

        def wrap(index, subject_key, fn):
            try:
                return index, fn(), None
            except BudgetExhausted as exc:
                return index, exc, subject_key
            except Exception as exc:
                return index, exc, None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_concurrent) as pool:
            futures = [pool.submit(wrap, i, subject, fn) for i, (subject, fn) in enumerate(tasks)]
            for future in futures:
                index, value, deferred_subject = future.result()
                results[index] = value
                if deferred_subject is not None:
                    deferred.append(deferred_subject)
        return results, deferred

    # Per-step accounting the runner and steps feed.

    def rows_written(self, step, count):
        with self._lock:
            self.per_step.setdefault(step, new_step_counters())["rows_written"] += int(count)

    def step_wall(self, step, seconds):
        with self._lock:
            self.per_step.setdefault(step, new_step_counters())["wall_seconds"] += float(seconds)

    def snapshot(self):
        """The run record columns this object owns."""
        with self._lock:
            per_step = collections.OrderedDict((step, dict(c)) for step, c in self.per_step.items())
            return collections.OrderedDict([
                ("searches_issued", self.searches_issued),
                ("searches_failed", self.searches_failed),
                ("write_searches", self.write_searches),
                ("write_reserve", self.write_reserve),
                ("events_scanned", self.events_scanned),
                ("events_matched", self.events_matched),
                ("search_seconds", round(self.search_seconds, 3)),
                ("wall_seconds", round(self.wall_seconds(), 3)),
                ("peak_concurrency", self.peak_concurrency),
                ("per_step", per_step),
                ("budget_exhausted", self.exhausted),
            ])
