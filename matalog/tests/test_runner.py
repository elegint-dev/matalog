import unittest

import support
from matalog import budget as budget_mod
from matalog import keys, rows, runner, writer
from matalog import steps as steps_pkg
import fake_client

IDENT = ("matalog_json", "crowdstrike:events:sensor", "event_simpleName", "ProcessRollup2")


class Recorder(runner.Step):
    """A step that stages what the test asks for and records that it ran."""

    def __init__(self, name, action=None, required=False):
        self.name = name
        self.label = name.lower()
        self.required = required
        self.action = action
        self.ran = False

    def run(self, ctx):
        self.ran = True
        if self.action:
            self.action(ctx)


def stage_some_rows(ctx):
    ctx.stage(rows.source_row(ctx.run, "main", "st", events_last_cycle=1, daily_events=2))
    ctx.stage_kv("matalog_sources", rows.sources_doc("main", "st", state="active", daily_events=2))
    ctx.stage(rows.field_row(ctx.run, "discovery", "slim", *IDENT, field_name="f", earliest=1.0, latest=2.0, sample_ratio=1, events_in_stratum=10,
                             count=5, distinct=2, distinct_exact=1, numeric_count=0, type_guess="string", identifier=0, values_hash="0" * 32, sid="s"))
    ctx.stage_kv("matalog_fields", rows.fields_doc(*IDENT, field_name="f", cur_disc_run_id=ctx.run_id, cur_disc_count=5, cur_disc_events=10, cur_disc_coverage=0.5, cur_disc_distinct=2, presence="present", observed=1))


def commit_step(ctx):
    runner.commit(ctx)


def pipeline(actions=None):
    actions = actions or {}
    steps = [Recorder(name, actions.get(name), required=name in ("S1", "S10")) for name in runner.STEP_ORDER]
    if "S10" not in actions:
        steps[-1].action = commit_step
    return steps


class Context(unittest.TestCase):
    def test_context_pins_the_slot_and_counts_attempts(self):
        ctx = support.context(now=support.SLOT + 1800)
        self.assertEqual((ctx.run_id, ctx.slot_start, ctx.attempt), ("20261013T1400Z", support.SLOT, 1))
        self.assertEqual(ctx.windows["discovery"][1], support.SLOT - 300)
        ctx.client.kv_batch_save("matalog_runs", [{"_key": ctx.run_id, "run_id": ctx.run_id, "attempt": 2, "committed": 1, "committed_attempt": 2}])
        again = runner.new_context(ctx.settings, ctx.client, now=support.SLOT + 5)
        self.assertEqual(again.attempt, 3)
        self.assertEqual(again.budget.run_id, again.run_id)
        self.assertIs(again.client.budget, again.budget)

    def test_staging_validates_rows_and_merges_kv_docs_by_key(self):
        ctx = support.context()
        with self.assertRaises(rows.RowError):
            ctx.stage({"kind": "source"})
        big = rows.field_row(ctx.run, "profile", "full", *IDENT, field_name="f", earliest=1.0, latest=2.0, sample_ratio=1, events_in_stratum=10, count=5, distinct=2,
                             distinct_exact=1, numeric_count=0, type_guess="string", identifier=0, values_hash="0" * 32, sid="s", sample_values=["x" * 120] * 100)
        with self.assertRaises(rows.RowError):
            ctx.stage(big)
        ctx.stage_kv("matalog_sources", rows.sources_doc("main", "st", state="active"))
        ctx.stage_kv("matalog_sources", rows.sources_doc("main", "st", daily_events=4))
        staged = ctx.staged("matalog_sources", keys.source_key("main", "st"))
        self.assertEqual((staged["state"], staged["daily_events"]), ("active", 4))
        self.assertEqual(len(ctx.kv["matalog_sources"]), 1)
        ctx.delete_kv("matalog_sources", staged["_key"])
        self.assertEqual(len(ctx.kv["matalog_sources"]), 0)
        self.assertIn(staged["_key"], ctx.kv_deletes["matalog_sources"])

    def test_errors_are_capped_at_fifty(self):
        ctx = support.context()
        for i in range(60):
            ctx.error("S3", "s%d" % i, "boom")
        self.assertEqual(len(ctx.errors), 50)
        self.assertEqual(ctx.errors[0], {"step": "S3", "subject": "s0", "message": "boom"})


class RunRecord(unittest.TestCase):
    def test_open_writes_a_running_record_with_budget_hash_and_reserve(self):
        ctx = support.context()
        ctx.client.kv_batch_save("matalog_runs", [{"_key": "20261013T1300Z", "run_id": "20261013T1300Z", "committed": 1, "committed_attempt": 1,
                                                   "write_bytes": 40000, "strata_discovered": 10, "strata_due": 10}])
        doc = runner.open_run_record(ctx)
        stored = ctx.client.kv_get("matalog_runs", ctx.run_id)
        self.assertEqual((stored["status"], stored["attempt"], stored["committed"], stored["run_mode"], stored["profiled_as"]), ("running", 1, 0, "normal", "svc_matalog"))
        self.assertEqual(stored["budget"]["budget"]["cycle_seconds"], 3600)
        self.assertEqual(len(stored["config_hash"]), 32)
        self.assertEqual(stored["write_reserve"], 10)
        self.assertEqual(ctx.previous_run["run_id"], "20261013T1300Z")
        self.assertEqual(doc["app_context"], "matalog")

    def test_finalize_writes_status_cost_counters_and_errors(self):
        ctx = support.context()
        runner.open_run_record(ctx)
        ctx.counts["sources_total"] = 6
        ctx.error("S3", "x", "late")
        ctx.client.search("| metadata type=sourcetypes index=matalog_json", step="S1")
        doc = runner.finalize_run_record(ctx, "partial")
        stored = ctx.client.kv_get("matalog_runs", ctx.run_id)
        self.assertEqual((stored["status"], stored["sources_total"], stored["searches_issued"], stored["committed"]), ("partial", 6, 1, 0))
        self.assertEqual(stored["errors"][0]["message"], "late")
        self.assertIn("finished_at", stored)
        self.assertEqual(doc["per_step"]["S1"]["searches"], 1)


class Seeds(unittest.TestCase):
    def test_seed_rows_are_upserted_and_user_rows_win(self):
        ctx = support.context()
        ctx.settings.stratum_seeds = [{"src_sourcetype": "a", "stratum_field": "f", "version_field": "", "index_pattern": "*"},
                                      {"src_sourcetype": "b", "stratum_field": "g", "version_field": "v", "index_pattern": "*"}]
        ctx.client.kv_batch_save("matalog_stratum_config", [{"_key": keys.k("*", "a"), "origin": "user", "stratum_field": "mine", "enabled": 1},
                                                            {"_key": keys.k("*", "b"), "origin": "seed", "stratum_field": "old", "enabled": 0}])
        self.assertEqual(runner.seed_stratum_config(ctx), 1)
        a = ctx.client.kv_get("matalog_stratum_config", keys.k("*", "a"))
        b = ctx.client.kv_get("matalog_stratum_config", keys.k("*", "b"))
        self.assertEqual((a["origin"], a["stratum_field"]), ("user", "mine"))
        self.assertEqual((b["origin"], b["stratum_field"], b["version_field"], b["enabled"], b["set_by"]), ("seed", "g", "v", 0, "matalog"))


class Commit(unittest.TestCase):
    def test_commit_writes_rows_then_the_commit_row_then_kv_then_committed(self):
        ctx = support.context()
        runner.open_run_record(ctx)
        stage_some_rows(ctx)
        ctx.client.search("| metadata type=sourcetypes index=matalog_json", step="S1")
        commit_doc = runner.commit(ctx)
        kinds = [r["kind"] for r in ctx.client.collected_rows()]
        self.assertEqual(kinds[:2], ["source", "field"])
        self.assertIn("search_cost", kinds)
        self.assertEqual(kinds[-1], "commit")
        self.assertLess(kinds.index("search_cost"), kinds.index("commit"))
        self.assertEqual(commit_doc["rows_kind"], ["source", "field", "search_cost"])
        self.assertEqual(ctx.rows_written["matalog_sources"], 1)
        self.assertEqual(ctx.rows_written["matalog_fields"], 1)
        self.assertEqual(ctx.client.kv_get("matalog_fields", keys.field_key(*IDENT, "f"))["cur_disc_count"], 5)
        run = ctx.client.kv_get("matalog_runs", ctx.run_id)
        self.assertEqual((run["committed"], run["committed_attempt"]), (1, 1))
        self.assertTrue(ctx.committed)
        self.assertEqual(ctx.write_report.write_bytes, run.get("write_bytes", ctx.write_report.write_bytes))

    def test_a_failed_collect_leaves_kv_untouched_and_uncommitted(self):
        ctx = support.context()
        runner.open_run_record(ctx)
        stage_some_rows(ctx)
        ctx.client.collect_failures = 1
        with self.assertRaises(writer.WriteError):
            runner.commit(ctx)
        self.assertEqual(ctx.client.kv_query("matalog_fields"), [])
        self.assertEqual(ctx.client.kv_get("matalog_runs", ctx.run_id)["committed"], 0)

    def test_every_write_job_but_the_commit_job_has_a_cost_row_in_the_index(self):
        ctx = support.context()
        runner.open_run_record(ctx)
        stage_some_rows(ctx)
        runner.commit(ctx)
        doc = runner.finalize_run_record(ctx, "ok")
        costs = [r for r in ctx.client.collected_rows() if r["kind"] == "search_cost"]
        self.assertEqual(doc["write_searches"], 2)
        self.assertEqual(len(costs), 1)
        self.assertEqual(doc["searches_issued"], 2)
        self.assertEqual(doc["rows_written"]["search_cost"], 1)


class RunOnce(unittest.TestCase):
    def test_a_full_run_commits_and_records_ok(self):
        client = fake_client.FakeClient()
        s = support.settings()
        client.settings = s
        steps = pipeline({"S3": stage_some_rows})
        record = runner.run_once(s, client, now=support.SLOT + 5, steps=steps)
        self.assertEqual((record["status"], record["committed"], record["committed_attempt"], record["run_id"]), ("ok", 1, 1, "20261013T1400Z"))
        self.assertTrue(all(step.ran for step in steps))
        self.assertEqual(record["rows_written"]["matalog_fields"], 1)
        self.assertEqual(record["errors"], [])
        self.assertGreater(record["wall_seconds"], -1)
        self.assertEqual(record["per_step"]["S3"]["rows_written"], 0)

    def test_a_failing_optional_step_makes_the_run_partial_and_later_steps_still_run(self):
        client = fake_client.FakeClient()
        s = support.settings()

        def boom(ctx):
            raise ValueError("no strata")
        steps = pipeline({"S2": boom, "S3": stage_some_rows})
        record = runner.run_once(s, client, now=support.SLOT, steps=steps)
        self.assertEqual((record["status"], record["committed"]), ("partial", 1))
        self.assertEqual(record["errors"][0]["step"], "S2")
        self.assertTrue(steps[2].ran)

    def test_a_failing_required_step_stops_the_run_as_failed(self):
        client = fake_client.FakeClient()
        s = support.settings()

        def boom(ctx):
            raise RuntimeError("metadata down")
        steps = pipeline({"S1": boom, "S3": stage_some_rows})
        record = runner.run_once(s, client, now=support.SLOT, steps=steps)
        self.assertEqual((record["status"], record["committed"]), ("failed", 0))
        self.assertFalse(steps[2].ran)
        self.assertEqual(client.collected, [])

    def test_budget_exhaustion_defers_work_and_marks_the_run_partial(self):
        client = fake_client.FakeClient()
        s = support.settings(**{"budget.max_searches_per_cycle": 11, "write.write_reserve_min": 10})

        def search_twice(ctx):
            ctx.client.search("| metadata type=sourcetypes index=matalog_json", step="S1")
            ctx.client.search("| metadata type=sourcetypes index=_internal", step="S1")
        steps = pipeline({"S1": search_twice, "S3": stage_some_rows})
        record = runner.run_once(s, client, now=support.SLOT, steps=steps)
        self.assertEqual((record["status"], record["budget_exhausted"], record["committed"]), ("partial", "searches", 1))
        self.assertGreaterEqual(record["write_searches"], 1)

    def test_a_required_step_that_raises_fails_the_run_at_s1_without_touching_kv(self):
        client = fake_client.FakeClient()
        s = support.settings()
        steps = steps_pkg.all_steps()
        steps[0].run = lambda ctx: (_ for _ in ()).throw(NotImplementedError("S1 enumerate_sources"))
        record = runner.run_once(s, client, now=support.SLOT, steps=steps)
        self.assertEqual(record["status"], "failed")
        self.assertIn("NotImplementedError", record["errors"][0]["message"])
        self.assertEqual([x.name for x in steps_pkg.all_steps()], list(runner.STEP_ORDER))
        self.assertEqual(client.kv_query("matalog_fields"), [])

    def test_a_rerun_of_the_same_slot_is_attempt_two_and_searches_the_same_window(self):
        client = fake_client.FakeClient()
        s = support.settings()
        windows = []
        runner.run_once(s, client, now=support.SLOT + 1, steps=pipeline({"S3": stage_some_rows, "S4": lambda ctx: windows.append(ctx.windows["discovery"])}))
        record = runner.run_once(s, client, now=support.SLOT + 3000, steps=pipeline({"S3": stage_some_rows, "S4": lambda ctx: windows.append(ctx.windows["discovery"])}))
        self.assertEqual((record["attempt"], record["committed_attempt"]), (2, 2))
        self.assertEqual(windows[0], windows[1])
        commits = [r for r in client.collected_rows() if r["kind"] == "commit"]
        self.assertEqual([c["attempt"] for c in commits], ["1", "2"])


class CrashReplay(unittest.TestCase):
    def test_a_run_with_a_commit_row_but_no_flag_is_replayed_into_kv(self):
        client = fake_client.FakeClient()
        s = support.settings()
        client.settings = s
        client.kv_batch_save("matalog_runs", [{"_key": "20261013T1300Z", "run_id": "20261013T1300Z", "attempt": 2, "committed": 0, "status": "running"}])
        old_run = {"run_id": "20261013T1300Z", "attempt": 2, "profiled_as": "svc"}
        committed_rows = [rows.source_row(old_run, "main", "st", events_last_cycle=1, daily_events=2),
                          rows.field_row(old_run, "discovery", "slim", *IDENT, field_name="f", earliest=1.0, latest=2.0, sample_ratio=1, events_in_stratum=10,
                                         count=5, distinct=2, distinct_exact=1, numeric_count=0, type_guess="string", identifier=0, values_hash="0" * 32, sid="s")]
        client.add_results([r'kind=commit run_id IN \("20261013T1300Z"\) \| stats max\(attempt\) as attempt by run_id'], [{"run_id": "20261013T1300Z", "attempt": "2"}])
        client.add_results([r"run_id=20261013T1300Z attempt=2"], [fake_client.parse_stash_line(writer.encode_line(r, support.SLOT - 3600)) for r in committed_rows])
        ctx = support.context(client=client)
        runner.open_run_record(ctx)
        self.assertEqual(runner.replay_uncommitted(ctx), ["20261013T1300Z"])
        run = client.kv_get("matalog_runs", "20261013T1300Z")
        self.assertEqual((run["committed"], run["committed_attempt"], run["status"]), (1, 2, "ok"))
        field = client.kv_get("matalog_fields", keys.field_key(*IDENT, "f"))
        self.assertEqual((field["cur_disc_run_id"], field["cur_disc_count"], field["presence"]), ("20261013T1300Z", 5, "present"))
        self.assertEqual(client.kv_get("matalog_sources", keys.source_key("main", "st"))["daily_events"], 2)

    def test_a_run_without_a_commit_row_is_marked_failed_and_kv_stays_untouched(self):
        client = fake_client.FakeClient()
        client.kv_batch_save("matalog_runs", [{"_key": "20261013T1200Z", "run_id": "20261013T1200Z", "attempt": 1, "committed": 0, "status": "running"}])
        client.add_results([r'kind=commit run_id IN \("20261013T1200Z"\)'], [])
        ctx = support.context(client=client)
        runner.open_run_record(ctx)
        self.assertEqual(runner.replay_uncommitted(ctx), [])
        self.assertEqual(client.kv_get("matalog_runs", "20261013T1200Z")["status"], "failed")
        self.assertEqual(client.kv_query("matalog_sources"), [])


class Rebuild(unittest.TestCase):
    def test_rebuild_reads_committed_rows_and_restores_cur_and_base_snapshots(self):
        client = fake_client.FakeClient()
        s = support.settings()
        client.settings = s
        newer = {"run_id": "20261013T1300Z", "attempt": 1, "profiled_as": "svc"}
        older = {"run_id": "20261013T1200Z", "attempt": 1, "profiled_as": "svc"}

        def frow(run, count):
            return rows.field_row(run, "discovery", "slim", *IDENT, field_name="f", earliest=1.0, latest=2.0, sample_ratio=1, events_in_stratum=10,
                                  count=count, distinct=2, distinct_exact=1, numeric_count=0, type_guess="string", identifier=0, values_hash="0" * 32, sid="s")
        lines = [writer.encode_line(frow(newer, 7), support.SLOT - 3600), writer.encode_line(frow(older, 3), support.SLOT - 7200)]
        client.add_results([r"kind=field", r"dedup 2 field_key mode"], [fake_client.parse_stash_line(l) for l in lines], scan_count=2)
        client.add_results([r"kind=source", r"dedup 2 source_key"], [fake_client.parse_stash_line(writer.encode_line(rows.source_row(newer, "main", "st", events_last_cycle=1, daily_events=9), support.SLOT - 3600))])
        client.add_results([r"kind=stratum", r"dedup 2 stratum_key mode"], [])
        record = runner.run_once(s, client, now=support.SLOT, run_mode="rebuild", steps=pipeline())
        self.assertEqual((record["status"], record["run_mode"], record["committed"]), ("ok", "rebuild", 1))
        field = client.kv_get("matalog_fields", keys.field_key(*IDENT, "f"))
        self.assertEqual((field["cur_disc_run_id"], field["cur_disc_count"], field["base_disc_run_id"], field["base_disc_count"]), ("20261013T1300Z", 7, "20261013T1200Z", 3))
        self.assertEqual(client.kv_get("matalog_sources", keys.source_key("main", "st"))["daily_events"], 9)
        searched = [c[1]["spl"] for c in client.calls if c[0] == "search"]
        self.assertTrue(all("index=matalog_profiles" in spl or "collect index=matalog_profiles" in spl for spl in searched))

    def test_rebuild_runs_only_the_reader_and_s10(self):
        steps = pipeline()
        chosen = runner.steps_for_mode("rebuild", steps)
        self.assertEqual([x.name for x in chosen], ["R0", "S10"])
        self.assertEqual([x.name for x in runner.steps_for_mode("normal", steps)], list(runner.STEP_ORDER))
        with self.assertRaises(ValueError):
            runner.run_once(support.settings(), fake_client.FakeClient(), run_mode="weekly")


def running_record(run_id, attempt=1, **extra):
    doc = {"_key": run_id, "run_id": run_id, "attempt": attempt, "committed": 0, "status": "running"}
    doc.update(extra)
    return doc


def probes(client):
    return [c for c in client.calls if c[0] == "search" and "kind=commit run_id IN" in c[1]["spl"]]


class ReplayBookkeeping(unittest.TestCase):
    def test_a_probed_run_without_a_commit_row_is_never_probed_again(self):
        client = fake_client.FakeClient()
        s = support.settings()
        client.settings = s
        client.kv_batch_save("matalog_runs", [running_record("20261013T%02d00Z" % h) for h in range(5, 10)])
        client.add_results(r"kind=commit run_id IN", [])
        runner.run_once(s, client, now=support.SLOT, steps=pipeline({"S3": stage_some_rows}))
        self.assertEqual(len(probes(client)), 1)
        self.assertEqual(set(r["status"] for r in client.kv_query("matalog_runs") if r["run_id"] < "20261013T1400Z"), {"failed"})
        runner.run_once(s, client, now=support.SLOT + 3600, steps=pipeline({"S3": stage_some_rows}))
        self.assertEqual(len(probes(client)), 1)

    def test_a_kv_failure_after_the_commit_row_is_replayed_by_the_next_run_which_then_sees_it_as_previous(self):
        client = fake_client.FakeClient()
        s = support.settings()
        client.settings = s

        def commit_then_kv_fails(ctx):
            def broken(collection, docs):
                raise writer.WriteError("kv down")
            ctx.kv_writer.write = broken
            runner.commit(ctx)
        first = runner.run_once(s, client, now=support.SLOT, steps=pipeline({"S3": stage_some_rows, "S10": commit_then_kv_fails}))
        self.assertEqual((first["status"], first["committed"], first["committed_attempt"]), ("failed", 0, 1))
        self.assertEqual(client.kv_query("matalog_fields"), [])
        committed = [fake_client.parse_stash_line(line) for line in client.collected]
        client.add_results([r"run_id=20261013T1400Z attempt=1 .*\| head \d+ \| table _raw"], [r for r in committed if r["kind"] in ("source", "field")])
        seen = {}
        second = runner.run_once(s, client, now=support.SLOT + 3600,
                                 steps=pipeline({"S1": lambda ctx: seen.update(previous=ctx.previous_run["run_id"])}))
        self.assertEqual(second["status"], "ok")
        self.assertEqual(probes(client), [])
        self.assertEqual(seen["previous"], "20261013T1400Z")
        replayed = client.kv_get("matalog_runs", "20261013T1400Z")
        self.assertEqual((replayed["committed"], replayed["committed_attempt"]), (1, 1))
        self.assertEqual(client.kv_get("matalog_fields", keys.field_key(*IDENT, "f"))["cur_disc_count"], 5)

    def test_a_rerun_keeps_the_previous_attempts_commit_until_its_own_commit_row(self):
        client = fake_client.FakeClient()
        s = support.settings()
        client.settings = s
        runner.run_once(s, client, now=support.SLOT, steps=pipeline({"S3": stage_some_rows}))

        def boom(ctx):
            raise RuntimeError("down")
        again = runner.run_once(s, client, now=support.SLOT + 60, steps=pipeline({"S1": boom}))
        self.assertEqual((again["attempt"], again["status"], again["committed"], again["committed_attempt"]), (2, "failed", 1, 1))

    def test_config_hash_counts_the_seeds_from_the_first_run(self):
        client = fake_client.FakeClient()
        s = support.settings()
        s.stratum_seeds = [{"src_sourcetype": "a", "stratum_field": "f", "version_field": "", "index_pattern": "*"}]
        client.settings = s
        one = runner.run_once(s, client, now=support.SLOT, steps=pipeline({"S3": stage_some_rows}))
        two = runner.run_once(s, client, now=support.SLOT + 3600, steps=pipeline({"S3": stage_some_rows}))
        self.assertEqual(one["config_hash"], two["config_hash"])
        self.assertEqual(one["config_hash"], s.config_hash(client.kv_query("matalog_stratum_config"), []))


class Counters(unittest.TestCase):
    def test_an_unknown_counter_fails_its_own_step_and_the_record_is_finalized(self):
        client = fake_client.FakeClient()
        s = support.settings()

        def bad_counter(ctx):
            ctx.counts["strata_planned"] = 3
        record = runner.run_once(s, client, now=support.SLOT, steps=pipeline({"S3": bad_counter}))
        self.assertEqual((record["status"], record["committed"]), ("partial", 1))
        self.assertEqual(record["errors"][0]["step"], "S3")
        self.assertEqual(client.kv_get("matalog_runs", record["run_id"])["status"], "partial")

    def test_finalize_never_leaves_the_record_running(self):
        ctx = support.context()
        runner.open_run_record(ctx)
        collections_mod = __import__("collections")
        collections_mod.OrderedDict.__setitem__(ctx.counts, "strata_planned", 1)
        doc = runner.finalize_run_record(ctx, "ok")
        self.assertEqual(doc["status"], "failed")
        self.assertNotIn("strata_planned", doc)
        self.assertEqual(ctx.client.kv_get("matalog_runs", ctx.run_id)["status"], "failed")


class StreamingWrites(unittest.TestCase):
    def test_rows_are_written_in_full_batches_while_steps_run(self):
        client = fake_client.FakeClient()
        s = support.settings(**{"write.write_batch_rows": 2})
        seen = {}

        def three_sources(ctx):
            for i in range(3):
                ctx.stage(rows.source_row(ctx.run, "main", "st%d" % i, events_last_cycle=1, daily_events=1))

        def look(ctx):
            seen["sources"] = len([r for r in client.collected_rows() if r["kind"] == "source"])
            seen["s3_writes"] = ctx.budget.per_step["S3"]["searches"]
        record = runner.run_once(s, client, now=support.SLOT, steps=pipeline({"S3": three_sources, "S4": look}))
        self.assertEqual((seen["sources"], seen["s3_writes"]), (2, 1))
        self.assertEqual(record["status"], "ok")
        self.assertEqual(len([r for r in client.collected_rows() if r["kind"] == "source"]), 3)


class DuplicateRows(unittest.TestCase):
    def test_two_identical_sid_less_cost_rows_still_commit(self):
        from matalog import client as client_mod
        ctx = support.context()
        runner.open_run_record(ctx)
        stage_some_rows(ctx)
        for _ in range(2):
            ctx.budget.record("S3", "k", client_mod.JobResult(status="failed", spl="search x", earliest=1, latest=2))
        runner.commit(ctx)
        self.assertTrue(ctx.committed)
        costs = [r for r in ctx.client.collected_rows() if r["kind"] == "search_cost" and r["step"] == "S3"]
        self.assertEqual(len(costs), 1)


class ConcurrentStaging(unittest.TestCase):
    def test_rows_staged_from_pool_threads_are_each_written_once(self):
        ctx = support.context(**{"write.write_batch_rows": 3})
        runner.open_run_record(ctx)
        tasks = [("st%d" % i, (lambda i=i: ctx.stage(rows.source_row(ctx.run, "main", "st%d" % i, events_last_cycle=1, daily_events=1))))
                 for i in range(20)]
        ctx.budget.map("S3", tasks)
        runner.commit(ctx)
        sources = sorted(r["src_sourcetype"] for r in ctx.client.collected_rows() if r["kind"] == "source")
        self.assertEqual(sources, sorted("st%d" % i for i in range(20)))


class StepHelpers(unittest.TestCase):
    def test_the_audit_window_starts_where_the_previous_committed_run_ended(self):
        ctx = support.context()
        lag = ctx.settings.budget.window_lag_seconds
        self.assertEqual(ctx.audit_window(), (support.SLOT - lag - 30 * 86400, support.SLOT - lag))
        ctx.previous_run = {"run_id": "20261013T1100Z"}
        self.assertEqual(ctx.audit_window(), (support.SLOT - 3 * 3600 - lag, support.SLOT - lag))

    def test_after_roll_shows_the_stored_cur_as_base_for_a_newer_run(self):
        ctx = support.context()
        key = keys.field_key(*IDENT, "f")
        ctx.client.kv_batch_save("matalog_fields", [{"_key": key, "cur_disc_run_id": "20261013T1300Z", "cur_disc_count": 4}])
        ctx.stage_kv("matalog_fields", rows.fields_doc(*IDENT, field_name="f", cur_disc_run_id=ctx.run_id, cur_disc_count=9))
        doc = ctx.after_roll("matalog_fields", key)
        self.assertEqual((doc["cur_disc_count"], doc["base_disc_run_id"], doc["base_disc_count"]), (9, "20261013T1300Z", 4))


class RebuildMerge(unittest.TestCase):
    def test_rebuild_takes_shared_columns_from_the_newest_row_of_either_mode(self):
        client = fake_client.FakeClient()
        s = support.settings()
        client.settings = s
        newer = {"run_id": "20261013T1300Z", "attempt": 1, "profiled_as": "svc"}
        older = {"run_id": "20261013T1100Z", "attempt": 1, "profiled_as": "svc"}
        slim = rows.field_row(newer, "discovery", "slim", *IDENT, field_name="f", earliest=1.0, latest=5.0, sample_ratio=1, events_in_stratum=10,
                              count=7, distinct=2, distinct_exact=1, numeric_count=7, type_guess="integer", identifier=0, values_hash="1" * 32, sid="s")
        full = rows.field_row(older, "profile", "full", *IDENT, field_name="f", earliest=1.0, latest=3.0, sample_ratio=1, events_in_stratum=10,
                              count=3, distinct=2, distinct_exact=1, numeric_count=0, type_guess="string", identifier=0, values_hash="2" * 32, sid="s",
                              top_values=["a"], top_counts=["3"], sample_values=["a"])
        results = [fake_client.parse_stash_line(writer.encode_line(slim, support.SLOT - 3600)),
                   fake_client.parse_stash_line(writer.encode_line(full, support.SLOT - 10800))]
        client.add_results([r"kind=field", r"dedup 2 field_key mode"], results)
        client.add_results([r"kind=source", r"dedup 2 source_key"], [])
        client.add_results([r"kind=stratum", r"dedup 2 stratum_key mode"], [])
        record = runner.run_once(s, client, now=support.SLOT, run_mode="rebuild", steps=pipeline())
        self.assertEqual(record["status"], "ok")
        field = client.kv_get("matalog_fields", keys.field_key(*IDENT, "f"))
        self.assertEqual((field["last_seen_run"], field["cur_disc_run_id"], field["cur_prof_run_id"]), ("20261013T1300Z", "20261013T1300Z", "20261013T1100Z"))
        self.assertEqual((field["type_guess"], field["values_hash"], field["last_seen_time"]), ("integer", "1" * 32, 5.0))
        self.assertEqual((field["top_values"], field["numeric_count"], field["first_seen_run"]), (["a"], 0, "20261013T1100Z"))
        self.assertEqual(field["updated_run_id"], "20261013T1400Z")


if __name__ == "__main__":
    unittest.main()
