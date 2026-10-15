import threading
import time
import unittest

import support
from matalog import budget as budget_mod
from matalog import client as client_mod
from matalog import rows


def job(scan=10, seconds=1.0, status="ok", sleep=0.0):
    def run():
        if sleep:
            time.sleep(sleep)
        return client_mod.JobResult(sid="s", status=status, scan_count=scan, event_count=scan, result_count=1, run_duration=seconds, spl="search x")
    return run


class Clock(object):
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def budget(sink=None, **overrides):
    s = support.settings(**overrides)
    clock = Clock()
    b = budget_mod.Budget(s, sink=sink, clock=clock)
    b.bind("20261013T1400Z", 1, "svc")
    return b, clock


class Ceilings(unittest.TestCase):
    def test_searches_ceiling_leaves_the_write_reserve_and_names_the_first_ceiling(self):
        b, _ = budget(**{"budget.max_searches_per_cycle": 12, "write.write_reserve_min": 10})
        self.assertEqual(b.plannable(), 2)
        b.run_job("S3", "a", job())
        b.run_job("S3", "b", job())
        self.assertEqual(b.plannable(), 0)
        with self.assertRaises(budget_mod.BudgetExhausted) as caught:
            b.run_job("S3", "c", job())
        self.assertEqual(caught.exception.ceiling, "searches")
        self.assertEqual(b.exhausted, "searches")
        self.assertEqual(b.searches_issued, 2)

    def test_write_jobs_are_never_deferred_but_are_counted(self):
        b, _ = budget(**{"budget.max_searches_per_cycle": 10, "write.write_reserve_min": 10})
        self.assertEqual(b.check(), "searches")
        b.run_job("S10", "write", job(), write=True)
        self.assertEqual((b.searches_issued, b.write_searches), (1, 1))

    def test_scanned_and_search_seconds_ceilings_defer_the_next_job(self):
        b, _ = budget(**{"budget.max_events_scanned_per_cycle": 15})
        b.run_job("S3", "a", job(scan=10))
        b.run_job("S3", "b", job(scan=10))
        with self.assertRaises(budget_mod.BudgetExhausted) as caught:
            b.run_job("S3", "c", job())
        self.assertEqual(caught.exception.ceiling, "scanned")
        b, _ = budget(**{"budget.max_search_seconds_per_cycle": 3})
        b.run_job("S4", "a", job(seconds=2.0))
        b.run_job("S4", "b", job(seconds=2.0))
        self.assertEqual(b.check(), "search_seconds")

    def test_wall_seconds_ceiling_follows_the_clock(self):
        b, clock = budget(**{"budget.max_wall_seconds_per_cycle": 100})
        self.assertEqual(b.check(), "")
        clock.t += 100
        self.assertEqual(b.check(), "wall_seconds")
        self.assertEqual(b.snapshot()["wall_seconds"], 100.0)

    def test_first_ceiling_is_kept_when_a_second_one_is_hit(self):
        b, clock = budget(**{"budget.max_events_scanned_per_cycle": 5, "budget.max_wall_seconds_per_cycle": 10})
        b.run_job("S3", "a", job(scan=5))
        with self.assertRaises(budget_mod.BudgetExhausted):
            b.run_job("S3", "b", job())
        clock.t += 100
        with self.assertRaises(budget_mod.BudgetExhausted):
            b.run_job("S3", "c", job())
        self.assertEqual(b.exhausted, "scanned")


class Accounting(unittest.TestCase):
    def test_every_job_records_a_search_cost_row_through_the_sink(self):
        rows_seen = []
        b, _ = budget(sink=rows_seen.append)
        b.cost_row = lambda bud, step, subject, result: rows.search_cost_row({"run_id": bud.run_id, "attempt": bud.attempt, "profiled_as": bud.profiled_as}, result, step, subject)
        b.run_job("S3", "stratum1", job(scan=7, seconds=0.5))
        b.run_job("S4", "src", job(status="failed"))
        self.assertEqual(len(rows_seen), 2)
        self.assertEqual((rows_seen[0]["kind"], rows_seen[0]["step"], rows_seen[0]["subject_key"], rows_seen[0]["scan_count"]), ("search_cost", "S3", "stratum1", 7))
        self.assertEqual(rows_seen[1]["status"], "failed")
        self.assertEqual(b.searches_failed, 1)

    def test_per_step_counters_and_snapshot_columns(self):
        b, _ = budget()
        b.run_job("S3", "a", job(scan=3, seconds=0.25))
        b.run_job("S3", "b", job(scan=4, seconds=0.25))
        b.rows_written("S3", 9)
        b.step_wall("S3", 1.5)
        snap = b.snapshot()
        self.assertEqual(snap["per_step"]["S3"], {"searches": 2, "scanned": 7, "seconds": 0.5, "rows_written": 9, "wall_seconds": 1.5})
        self.assertEqual((snap["searches_issued"], snap["events_scanned"], snap["events_matched"], snap["search_seconds"], snap["budget_exhausted"]), (2, 7, 7, 0.5, ""))
        self.assertEqual(set(snap), {"searches_issued", "searches_failed", "write_searches", "write_reserve", "events_scanned", "events_matched",
                                     "search_seconds", "wall_seconds", "peak_concurrency", "per_step", "budget_exhausted"})
        self.assertIsNone(rows.validate(rows.runs_doc("20261013T1400Z", **snap), collection="matalog_runs", partial=True).get("x"))


class Pool(unittest.TestCase):
    def test_map_runs_at_most_max_concurrent_jobs_and_records_the_peak(self):
        b, _ = budget(**{"budget.max_concurrent_searches": 2})
        active = {"n": 0, "peak": 0}
        lock = threading.Lock()

        def task():
            with lock:
                active["n"] += 1
                active["peak"] = max(active["peak"], active["n"])
            time.sleep(0.05)
            with lock:
                active["n"] -= 1
            return client_mod.JobResult(sid="s", scan_count=1, run_duration=0.01, spl="x")
        tasks = [("s%d" % i, lambda: b.run_job("S3", "s", task)) for i in range(6)]
        results, deferred = b.map("S3", tasks)
        self.assertEqual(active["peak"], 2)
        self.assertEqual(b.peak_concurrency, 2)
        self.assertEqual(deferred, [])
        self.assertTrue(all(isinstance(r, client_mod.JobResult) for r in results))

    def test_map_defers_subjects_once_a_ceiling_is_hit_and_keeps_other_errors(self):
        b, _ = budget(**{"budget.max_searches_per_cycle": 12, "write.write_reserve_min": 10, "budget.max_concurrent_searches": 1})

        def boom():
            raise ValueError("bad spl")
        tasks = [("a", lambda: b.run_job("S3", "a", job())), ("err", boom), ("b", lambda: b.run_job("S3", "b", job())),
                 ("c", lambda: b.run_job("S3", "c", job()))]
        results, deferred = b.map("S3", tasks)
        self.assertEqual(deferred, ["c"])
        self.assertIsInstance(results[1], ValueError)
        self.assertIsInstance(results[3], budget_mod.BudgetExhausted)
        self.assertEqual(b.searches_issued, 2)


class WriteReserve(unittest.TestCase):
    def test_reserve_is_the_floor_without_a_previous_run(self):
        s = support.settings()
        self.assertEqual(budget_mod.compute_write_reserve(s, None), 10)
        self.assertEqual(budget_mod.compute_write_reserve(s, {"write_bytes": 0}), 10)

    def test_reserve_scales_the_previous_write_bytes_by_planned_over_discovered(self):
        s = support.settings(**{"write.write_batch_bytes": 1000, "write.write_reserve_min": 2})
        previous = {"write_bytes": 5000, "strata_discovered": 50, "strata_due": 100}
        self.assertEqual(budget_mod.compute_write_reserve(s, previous), 12)
        self.assertEqual(budget_mod.compute_write_reserve(s, {"write_bytes": 500, "strata_discovered": 5, "strata_due": 5}), 3)


class ReserveUse(unittest.TestCase):
    def test_write_jobs_issued_out_of_the_reserve_are_not_counted_twice(self):
        s = support.settings(**{"budget.max_searches_per_cycle": 20, "write.write_reserve_min": 5})
        b = budget_mod.Budget(s)
        self.assertEqual(b.plannable(), 15)
        from matalog import client as client_mod
        for _ in range(3):
            b.run_job("S3", "write", lambda: client_mod.JobResult(sid="w"), write=True)
        self.assertEqual(b.plannable(), 15)
        b.run_job("S3", "k", lambda: client_mod.JobResult(sid="d"))
        self.assertEqual(b.plannable(), 14)

    def test_the_write_reserve_never_exceeds_half_the_search_ceiling(self):
        s = support.settings(**{"budget.max_searches_per_cycle": 400})
        heavy = {"write_bytes": 10 ** 10, "strata_discovered": 10, "strata_due": 10}
        self.assertEqual(budget_mod.compute_write_reserve(s, heavy), 200)


if __name__ == "__main__":
    unittest.main()
