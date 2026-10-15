"""S1 enumerate_sources against the captured sandbox fixtures and synthetic scenarios."""
import math
import re
import unittest

import support  # noqa: F401  (puts bin/ on the path)
import fake_client

from matalog import client as client_mod
from matalog import keys
from matalog import rows as rows_mod
from matalog import runner
from matalog import steps as steps_pkg
from matalog import writer as writer_mod
from matalog.steps import s1_enumerate_sources as s1

# Slot the s1_* fixtures were captured for: the corpus and the licence log both fall in its day window.
CAPTURED_SLOT = fake_client.load_fixture("s1_tstats_day")["captured_slot"]
SLOT = support.SLOT
DAY = 86400


def captured_context(**overrides):
    """A context on the captured slot whose tstats jobs are served per window from s1_tstats_day and s1_tstats_cycle."""
    overrides.setdefault("budget.index_scan_interval_seconds", 3600)
    ctx = support.context(now=CAPTURED_SLOT + 10, **overrides)
    day = fake_client.load_fixture("s1_tstats_day")
    cycle = fake_client.load_fixture("s1_tstats_cycle")
    serve_tstats(ctx.client, day["results"], cycle["results"])
    return ctx


def serve_tstats(client, day_rows, cycle_rows, fail=()):
    """Serve the two tstats jobs by window length: day rows for 86400 s, cycle rows otherwise."""
    def handler(spec):
        window = "source_day" if float(spec["latest"]) - float(spec["earliest"]) == DAY else "source_cycle"
        if window in fail:
            return client_mod.JobResult(status="failed", spl=spec["spl"], earliest=spec["earliest"], latest=spec["latest"])
        rows = day_rows if window == "source_day" else cycle_rows
        return client_mod.JobResult(status="ok", results=[dict(r) for r in rows], result_count=len(rows), spl=spec["spl"],
                                    spl_hash=spec.get("spl_hash"), earliest=spec["earliest"], latest=spec["latest"])
    client.add_search([r"^\| tstats count max\(_time\) as last_time"], handler)


def tstats_rows(table):
    """{(index, sourcetype): (count, last_time)} -> tstats result rows."""
    return [{"index": i, "sourcetype": st, "count": str(c), "last_time": "" if t is None else str(t)} for (i, st), (c, t) in table.items()]


def scenario(day=None, cycle=None, metadata=None, licence=None, history=None, stored=None, now=SLOT + 10,
             eventcount=None, apps=None, pools=None, run_mode="normal", **overrides):
    """A context over synthetic data.

    day, cycle: {(index, sourcetype): (count, last_time)}; metadata: {index: [(sourcetype, first, last)]};
    licence: list of {idx, st, b, last_time} rows, or "fail"; history: list of {source_key, run_id,
    events_last_cycle}, or "fail"; stored: matalog_sources docs already in KV.
    """
    overrides.setdefault("budget.index_scan_interval_seconds", 3600)
    s = support.settings(**overrides)
    client = fake_client.FakeClient(settings=s)
    day = day or {}
    cycle = cycle or {}
    metadata = metadata if metadata is not None else {}
    indexes = sorted(set(list(metadata) + [i for i, _ in day]))
    if eventcount is None:
        client.add_results([r"^\| eventcount "], [{"index": i, "count": "10"} for i in indexes])
    elif eventcount == "fail":
        client.add_search([r"^\| eventcount "], lambda spec: client_mod.JobResult(status="failed", spl=spec["spl"]))
    else:
        client.add_results([r"^\| eventcount "], eventcount)
    for index in indexes:
        rows = [{"sourcetype": st, "firstTime": str(f), "lastTime": str(l), "totalCount": "1", "type": "sourcetypes"}
                for st, f, l in metadata.get(index, [])]
        client.add_results([r'^\| metadata type=sourcetypes index="%s"$' % re.escape(index)], rows)
    serve_tstats(client, tstats_rows(day), tstats_rows(cycle))
    if licence == "fail":
        client.add_search([r"license_usage\.log"], lambda spec: client_mod.JobResult(status="failed", spl=spec["spl"]))
    else:
        client.add_results([r"license_usage\.log"], licence if licence is not None else [])
    if history == "fail":
        client.add_search([r"^search index=matalog_profiles kind=source "], lambda spec: client_mod.JobResult(status="failed", spl=spec["spl"]))
    else:
        client.add_results([r"^search index=matalog_profiles kind=source "], history or [])
    if apps is not None:
        client.conf["apps_local"] = apps
    if pools is not None:
        client.pools = pools
    for doc in stored or []:
        client.kv["matalog_sources"][doc["_key"]] = dict(doc)
    return support.context(client=client, now=now, run_mode=run_mode, **overrides)


def run_s1(ctx):
    s1.EnumerateSources().run(ctx)
    return ctx


def skey(index, sourcetype):
    return keys.source_key(index, sourcetype)


def stored_source(index, sourcetype, **values):
    doc = rows_mod.sources_doc(index, sourcetype, **values)
    return writer_mod.kv_encode(doc)


def searches(client, pattern):
    return [c[1] for c in client.calls if c[0] == "search" and re.search(pattern, c[1]["spl"])]


def latest_of(ctx):
    return ctx.windows["source_day"][1]


class CapturedSandbox(unittest.TestCase):

    def test_every_searchable_index_with_events_is_enumerated_including_internal_indexes(self):
        ctx = run_s1(captured_context())
        indexes = set(e["src_index"] for e in ctx.state["sources_all"].values())
        for index in ("_audit", "_internal", "_introspection", "matalog_json", "reach", "summary"):
            self.assertIn(index, indexes)
        self.assertIn(skey("_internal", "splunkd"), ctx.state["sources_all"])
        self.assertIn(skey("matalog_json", "crowdstrike:events:sensor"), ctx.state["sources_all"])

    def test_one_metadata_job_runs_per_index_with_events_and_none_for_empty_indexes(self):
        ctx = run_s1(captured_context())
        jobs = [c["spl"] for c in searches(ctx.client, r"^\| metadata type=sourcetypes")]
        listed = fake_client.load_fixture("s1_eventcount")["results"]
        expected = sorted(r["index"] for r in listed if int(r["count"]) > 0 and r["index"] != "matalog_profiles")
        self.assertEqual(sorted(re.search(r'index="([^"]+)"', spl).group(1) for spl in jobs), expected)

    def test_the_profiles_index_is_never_enumerated(self):
        ctx = run_s1(captured_context())
        self.assertNotIn("matalog_profiles", set(e["src_index"] for e in ctx.state["sources_all"].values()))
        self.assertFalse(searches(ctx.client, r'index="matalog_profiles"$'))

    def test_captured_counts_and_licence_bytes_land_on_the_source(self):
        ctx = run_s1(captured_context())
        entry = ctx.state["sources_all"][skey("matalog_json", "crowdstrike:events:sensor")]
        day = [r for r in fake_client.load_fixture("s1_tstats_day")["results"] if r["sourcetype"] == "crowdstrike:events:sensor" and r["index"] == "matalog_json"][0]
        cycle = [r for r in fake_client.load_fixture("s1_tstats_cycle")["results"] if r["sourcetype"] == "crowdstrike:events:sensor" and r["index"] == "matalog_json"][0]
        lic = [r for r in fake_client.load_fixture("s1_licence_usage")["results"] if r["st"] == "crowdstrike:events:sensor"][0]
        self.assertEqual(entry["daily_events"], int(day["count"]))
        self.assertEqual(entry["events_last_cycle"], int(cycle["count"]))
        self.assertEqual(entry["last_event_time"], float(day["last_time"]))
        self.assertEqual((entry["daily_bytes"], entry["daily_bytes_status"]), (int(lic["b"]), "ok"))

    def test_sources_absent_from_a_readable_licence_log_are_unavailable_whatever_their_index(self):
        ctx = run_s1(captured_context())
        entry = ctx.state["sources_all"][skey("_internal", "splunkd")]
        self.assertEqual((entry["daily_bytes"], entry["daily_bytes_status"]), (None, "unavailable"))

    def test_the_default_fixtures_run_s1_without_errors(self):
        ctx = support.context(now=SLOT + 10)
        run_s1(ctx)
        self.assertEqual(ctx.errors, [])
        self.assertGreater(ctx.counts["sources_total"], 0)


class Windows(unittest.TestCase):

    def test_tstats_jobs_search_the_source_day_and_source_cycle_windows_pinned_to_the_slot(self):
        ctx = run_s1(scenario(day={("main", "a"): (10, SLOT - 400)}, metadata={"main": [("a", SLOT - 9000, SLOT - 400)]}))
        windows = sorted((c["earliest"], c["latest"]) for c in searches(ctx.client, r"^\| tstats "))
        self.assertEqual(windows, sorted([ctx.windows["source_day"], ctx.windows["source_cycle"]]))
        self.assertEqual(ctx.windows["source_day"][1], SLOT - ctx.settings.budget.window_lag_seconds)

    def test_daily_events_and_events_last_cycle_come_from_their_own_windows(self):
        ctx = run_s1(scenario(day={("main", "a"): (500, SLOT - 400)}, cycle={("main", "a"): (20, SLOT - 400)}))
        entry = ctx.state["sources_all"][skey("main", "a")]
        self.assertEqual((entry["daily_events"], entry["events_last_cycle"]), (500, 20))

    def test_the_licence_search_covers_the_source_day_window(self):
        ctx = run_s1(scenario(day={("main", "a"): (5, SLOT - 400)}))
        jobs = searches(ctx.client, r"license_usage\.log")
        self.assertEqual([(c["earliest"], c["latest"]) for c in jobs], [ctx.windows["source_day"]])

    def test_every_s1_search_is_costed_under_step_s1(self):
        ctx = run_s1(scenario(day={("main", "a"): (5, SLOT - 400)}, metadata={"main": [("a", 1, 2)]}))
        steps = set(r["step"] for r in ctx.summary["search_cost"])
        self.assertEqual(steps, {"S1"})
        self.assertEqual(len(ctx.summary["search_cost"]), len([c for c in ctx.client.calls if c[0] == "search"]))

    def test_a_run_issues_two_tstats_one_listing_one_licence_one_history_and_one_metadata_per_index(self):
        ctx = run_s1(scenario(day={("main", "a"): (5, SLOT - 400), ("web", "b"): (5, SLOT - 400)},
                              metadata={"main": [("a", 1, 2)], "web": [("b", 1, 2)]}))
        spls = [c[1]["spl"] for c in ctx.client.calls if c[0] == "search"]
        self.assertEqual(len(spls), 2 + 1 + 1 + 1 + 2)


class Rows(unittest.TestCase):

    def test_one_source_summary_row_and_one_sources_doc_are_staged_per_source(self):
        ctx = run_s1(scenario(day={("main", "a"): (5, SLOT - 400), ("main", "b"): (7, SLOT - 500)}))
        self.assertEqual(len(ctx.summary["source"]), 2)
        self.assertEqual(set(ctx.kv["matalog_sources"]), {skey("main", "a"), skey("main", "b")})
        row = [r for r in ctx.summary["source"] if r["src_sourcetype"] == "b"][0]
        self.assertEqual((row["run_id"], row["daily_events"], row["row_id"]), (ctx.run_id, 7, keys.k(ctx.run_id, "source", skey("main", "b"))))

    def test_staged_sources_docs_hold_only_the_columns_s1_owns(self):
        ctx = run_s1(scenario(day={("main", "a"): (5, SLOT - 400)}, metadata={"main": [("a", SLOT - 9000, SLOT - 400)]}))
        owned = {"_key", "source_key", "src_index", "src_sourcetype", "profiled_as", "state", "first_seen_run", "last_seen_run",
                 "first_event_time", "last_event_time", "events_last_cycle", "daily_events", "daily_bytes", "daily_bytes_status",
                 "base_rate_per_hour", "profile_mode", "priority"}
        doc = ctx.kv["matalog_sources"][skey("main", "a")]
        self.assertTrue(set(doc) <= owned, set(doc) - owned)
        self.assertEqual(doc["profiled_as"], "svc_matalog")

    def test_index_names_are_lowercased_and_sourcetypes_kept_verbatim(self):
        ctx = run_s1(scenario(day={("Main", "Cisco:ASA"): (5, SLOT - 400)}))
        entry = ctx.state["sources_all"][skey("main", "Cisco:ASA")]
        self.assertEqual((entry["src_index"], entry["src_sourcetype"]), ("main", "Cisco:ASA"))

    def test_the_summary_row_maps_back_to_the_staged_counts(self):
        ctx = run_s1(scenario(day={("main", "a"): (5, SLOT - 400)}, cycle={("main", "a"): (2, SLOT - 400)}))
        collection, doc = rows_mod.kv_from_summary(ctx.summary["source"][0])
        staged = ctx.kv["matalog_sources"][skey("main", "a")]
        self.assertEqual(collection, "matalog_sources")
        for column in ("events_last_cycle", "daily_events", "daily_bytes", "last_event_time", "last_seen_run"):
            self.assertEqual(doc[column], staged[column], column)

    def test_the_summary_row_carries_the_stored_config_apps_and_version_top(self):
        key = skey("main", "a")
        ctx = run_s1(scenario(day={("main", "a"): (5, SLOT - 400)},
                              stored=[stored_source("main", "a", config_apps=["TA@1.0"], version_top=["7.1"], version_top_counts=["3"])]))
        row = ctx.summary["source"][0]
        self.assertEqual((row["source_key"], row["config_apps"], row["version_top"], row["version_top_counts"]), (key, ["TA@1.0"], ["7.1"], ["3"]))


class RunIdentity(unittest.TestCase):

    def test_first_seen_run_is_this_run_for_a_new_source_and_kept_for_a_known_one(self):
        ctx = run_s1(scenario(day={("main", "a"): (5, SLOT - 400), ("main", "b"): (5, SLOT - 400)},
                              stored=[stored_source("main", "b", first_seen_run="20261001T0000Z", state="active")]))
        self.assertEqual(ctx.kv["matalog_sources"][skey("main", "a")]["first_seen_run"], ctx.run_id)
        self.assertEqual(ctx.kv["matalog_sources"][skey("main", "b")]["first_seen_run"], "20261001T0000Z")

    def test_last_seen_run_moves_only_when_tstats_returned_events(self):
        ctx = run_s1(scenario(day={("main", "a"): (5, SLOT - 400)}, metadata={"main": [("a", 1, SLOT - 400), ("b", 1, SLOT - 5 * DAY)]},
                              stored=[stored_source("main", "b", first_seen_run="20261001T0000Z", last_seen_run="20261008T0000Z", state="active")]))
        self.assertEqual(ctx.kv["matalog_sources"][skey("main", "a")]["last_seen_run"], ctx.run_id)
        self.assertNotIn("last_seen_run", ctx.kv["matalog_sources"][skey("main", "b")])
        self.assertEqual(ctx.after_roll("matalog_sources", skey("main", "b"))["last_seen_run"], "20261008T0000Z")

    def test_first_event_time_is_the_metadata_first_time(self):
        ctx = run_s1(scenario(day={("main", "a"): (5, SLOT - 400)}, metadata={"main": [("a", SLOT - 40 * DAY, SLOT - 400)]}))
        self.assertEqual(ctx.kv["matalog_sources"][skey("main", "a")]["first_event_time"], float(SLOT - 40 * DAY))

    def test_last_event_time_is_the_day_tstats_max_time(self):
        ctx = run_s1(scenario(day={("main", "a"): (5, SLOT - 777)}, metadata={"main": [("a", 1, SLOT + 999)]}))
        self.assertEqual(ctx.kv["matalog_sources"][skey("main", "a")]["last_event_time"], float(SLOT - 777))

    def test_a_source_without_events_keeps_its_stored_last_event_time(self):
        stored = stored_source("main", "b", first_seen_run="20261001T0000Z", last_event_time=float(SLOT - 3 * DAY), state="active")
        ctx = run_s1(scenario(metadata={"main": [("b", 1, SLOT - 4 * DAY)]}, stored=[stored]))
        self.assertEqual(ctx.after_roll("matalog_sources", skey("main", "b"))["last_event_time"], float(SLOT - 3 * DAY))


class BaseRate(unittest.TestCase):

    def history(self, key, counts):
        """Rows newest first, one per earlier hourly run."""
        return [{"source_key": key, "run_id": keys.run_id_of(SLOT - 3600 * (i + 1)), "events_last_cycle": str(c)} for i, c in enumerate(counts)]

    def test_base_rate_is_the_median_hourly_rate_of_the_last_seven_committed_rows(self):
        key = skey("main", "a")
        ctx = run_s1(scenario(day={("main", "a"): (5, SLOT - 400)}, history=self.history(key, [10, 20, 30, 40, 50, 60, 70, 1000, 2000])))
        self.assertEqual(ctx.kv["matalog_sources"][key]["base_rate_per_hour"], 40.0)

    def test_base_rate_of_an_even_number_of_rows_is_the_mean_of_the_middle_two(self):
        key = skey("main", "a")
        ctx = run_s1(scenario(day={("main", "a"): (5, SLOT - 400)}, history=self.history(key, [10, 20, 30, 40])))
        self.assertEqual(ctx.kv["matalog_sources"][key]["base_rate_per_hour"], 25.0)

    def test_base_rate_scales_events_last_cycle_to_an_hour(self):
        key = skey("main", "a")
        rows = [{"source_key": key, "run_id": keys.run_id_of(SLOT - 1800 * (i + 1)), "events_last_cycle": "10"} for i in range(3)]
        ctx = run_s1(scenario(day={("main", "a"): (5, SLOT - 400)}, history=rows, **{"budget.cycle_seconds": 1800, "budget.max_wall_seconds_per_cycle": 1700}))
        self.assertEqual(ctx.kv["matalog_sources"][key]["base_rate_per_hour"], 20.0)

    def test_history_is_one_search_over_committed_rows_before_this_run(self):
        ctx = run_s1(scenario(day={("main", "a"): (5, SLOT - 400), ("main", "b"): (5, SLOT - 400)}))
        jobs = searches(ctx.client, r"^search index=matalog_profiles kind=source ")
        self.assertEqual(len(jobs), 1)
        self.assertIn(writer_mod.committed_subsearch(), jobs[0]["spl"])
        self.assertIn('run_id<"%s"' % ctx.run_id, jobs[0]["spl"])
        self.assertEqual(jobs[0]["latest"], ctx.slot_start)

    def test_rows_of_this_run_id_never_enter_the_base_rate(self):
        key = skey("main", "a")
        rows = self.history(key, [10, 10, 10]) + [{"source_key": key, "run_id": keys.run_id_of(SLOT), "events_last_cycle": "999999"}]
        ctx = run_s1(scenario(day={("main", "a"): (5, SLOT - 400)}, history=rows))
        self.assertEqual(ctx.kv["matalog_sources"][key]["base_rate_per_hour"], 10.0)

    def test_a_source_without_history_rows_keeps_the_stored_base_rate_in_kv(self):
        key = skey("main", "a")
        stored = stored_source("main", "a", first_seen_run="20261001T0000Z", base_rate_per_hour=120.0, state="active")
        ctx = run_s1(scenario(day={("main", "a"): (5, SLOT - 400)}, history=[], stored=[stored]))
        self.assertNotIn("base_rate_per_hour", ctx.kv["matalog_sources"][key])
        merged = writer_mod.kv_encode(writer_mod.apply_roll("matalog_sources", ctx.kv["matalog_sources"][key], stored))
        self.assertEqual(merged["base_rate_per_hour"], 120.0)
        self.assertEqual(ctx.state["sources_all"][key]["base_rate_per_hour"], 120.0)

    def committed_runs(self, ctx, slots):
        for slot in slots:
            run_id = keys.run_id_of(slot)
            ctx.client.kv["matalog_runs"][run_id] = {"_key": run_id, "run_id": run_id, "committed": 1}

    def test_history_starts_at_the_oldest_of_the_last_seven_committed_runs(self):
        ctx = scenario(day={("main", "a"): (5, SLOT - 400)})
        self.committed_runs(ctx, [SLOT - 3600 * h for h in (1, 2, 40, 41, 42, 43, 44, 45, 46)])
        run_s1(ctx)
        job = searches(ctx.client, r"^search index=matalog_profiles kind=source ")[0]
        self.assertEqual(float(job["earliest"]), SLOT - 3600 * 44)

    def test_history_after_an_outage_reaches_the_rows_before_it(self):
        key = skey("main", "a")
        ctx = scenario(day={("main", "a"): (5, SLOT - 400)},
                       history=self.history(key, [0]) + [{"source_key": key, "run_id": keys.run_id_of(SLOT - 3600 * h), "events_last_cycle": "100"}
                                                         for h in range(40, 46)])
        self.committed_runs(ctx, [SLOT - 3600] + [SLOT - 3600 * h for h in range(40, 46)])
        run_s1(ctx)
        job = searches(ctx.client, r"^search index=matalog_profiles kind=source ")[0]
        self.assertLessEqual(float(job["earliest"]), SLOT - 3600 * 45)
        self.assertEqual(ctx.kv["matalog_sources"][key]["base_rate_per_hour"], 100.0)

    def test_without_committed_runs_history_reads_a_trailing_window_of_at_least_a_day(self):
        ctx = run_s1(scenario(day={("main", "a"): (5, SLOT - 400)}))
        job = searches(ctx.client, r"^search index=matalog_profiles kind=source ")[0]
        self.assertLessEqual(float(job["earliest"]), SLOT - DAY)

    def test_a_run_counts_once_in_the_base_rate_when_its_row_is_duplicated(self):
        key = skey("main", "a")
        rows = self.history(key, [10, 10, 10])
        rows = rows[:1] * 4 + rows
        rows[0] = dict(rows[0], events_last_cycle="1000")
        rows[1] = dict(rows[1], events_last_cycle="1000")
        ctx = run_s1(scenario(day={("main", "a"): (5, SLOT - 400)}, history=rows))
        self.assertEqual(ctx.kv["matalog_sources"][key]["base_rate_per_hour"], 10.0)
        job = searches(ctx.client, r"^search index=matalog_profiles kind=source ")[0]
        self.assertIn("| dedup source_key run_id | dedup 7 source_key", job["spl"])

    def test_a_failed_history_read_keeps_the_stored_base_rate(self):
        key = skey("main", "a")
        ctx = run_s1(scenario(day={("main", "a"): (5, SLOT - 400)}, history="fail",
                              stored=[stored_source("main", "a", first_seen_run="20261001T0000Z", base_rate_per_hour=12.5, state="active")]))
        self.assertNotIn("base_rate_per_hour", ctx.kv["matalog_sources"][key])
        self.assertEqual(ctx.state["sources_all"][key]["base_rate_per_hour"], 12.5)
        self.assertEqual([e["subject"] for e in ctx.errors], ["history"])


class ProfileMode(unittest.TestCase):

    def test_profile_mode_is_sampled_at_or_above_the_volume_threshold(self):
        ctx = run_s1(scenario(day={("main", "a"): (100, SLOT - 400), ("main", "b"): (99, SLOT - 400)}, **{"profile.sample_volume_threshold": 100}))
        a, b = ctx.state["sources_all"][skey("main", "a")], ctx.state["sources_all"][skey("main", "b")]
        self.assertEqual((a["profile_mode"], a["plan_sample_ratio"]), ("sampled", ctx.settings.profile.sample_ratio))
        self.assertEqual((b["profile_mode"], b["plan_sample_ratio"]), ("unsampled", 1))


class State(unittest.TestCase):

    def test_a_source_without_events_for_gone_after_days_is_gone(self):
        ctx = run_s1(scenario(metadata={"main": [("old", 1, SLOT - 31 * DAY), ("recent", 1, SLOT - 29 * DAY)]}))
        self.assertEqual(ctx.kv["matalog_sources"][skey("main", "old")]["state"], "gone")
        self.assertEqual(ctx.kv["matalog_sources"][skey("main", "recent")]["state"], "active")

    def test_gone_follows_retention_gone_after_days(self):
        ctx = run_s1(scenario(metadata={"main": [("a", 1, SLOT - 3 * DAY)]}, **{"retention.gone_after_days": 2}))
        self.assertEqual(ctx.kv["matalog_sources"][skey("main", "a")]["state"], "gone")

    def test_a_gone_source_with_events_again_is_active(self):
        ctx = run_s1(scenario(day={("main", "a"): (3, SLOT - 400)},
                              stored=[stored_source("main", "a", first_seen_run="20260101T0000Z", state="gone", last_event_time=1.0)]))
        self.assertEqual(ctx.kv["matalog_sources"][skey("main", "a")]["state"], "active")

    def test_a_stored_source_metadata_no_longer_reports_is_still_enumerated_until_gone(self):
        stored = stored_source("main", "a", first_seen_run="20260901T0000Z", state="active", last_event_time=float(SLOT - 40 * DAY))
        ctx = run_s1(scenario(stored=[stored]))
        self.assertEqual(ctx.kv["matalog_sources"][skey("main", "a")]["state"], "gone")
        self.assertEqual(ctx.counts["sources_total"], 1)

    def test_a_stored_gone_source_not_reported_again_is_not_enumerated(self):
        stored = stored_source("main", "a", first_seen_run="20260901T0000Z", state="gone", last_event_time=float(SLOT - 90 * DAY))
        ctx = run_s1(scenario(stored=[stored]))
        self.assertEqual(ctx.counts["sources_total"], 0)
        self.assertEqual(ctx.summary["source"], [])


class Priority(unittest.TestCase):

    def test_priority_follows_the_formula_with_the_stored_usage_count_and_cycles_since_discovered(self):
        last = keys.run_id_of(SLOT - 6 * 3600)
        stored = stored_source("main", "a", first_seen_run="20261001T0000Z", state="active", usage_count=3, last_discovered_run=last)
        ctx = run_s1(scenario(day={("main", "a"): (999, SLOT - 400)}, stored=[stored], **{"budget.priority_usage_weight": 0.5}))
        expected = math.log10(1000) * (1 + 0.5 * 3) * (1 + 6.0 / 24)
        self.assertAlmostEqual(ctx.kv["matalog_sources"][skey("main", "a")]["priority"], expected)

    def test_a_never_discovered_source_counts_max_staleness_cycles(self):
        ctx = run_s1(scenario(day={("main", "a"): (9, SLOT - 400)}))
        entry = ctx.state["sources_all"][skey("main", "a")]
        self.assertEqual(entry["plan_cycles_since_discovered"], 24)
        self.assertAlmostEqual(entry["priority"], math.log10(10) * 2)

    def test_sources_are_ordered_by_priority_descending(self):
        ctx = run_s1(scenario(day={("main", "small"): (10, SLOT - 400), ("main", "big"): (10000, SLOT - 400), ("main", "mid"): (500, SLOT - 400)},
                              cycle={("main", "small"): (1, SLOT - 400), ("main", "big"): (1, SLOT - 400), ("main", "mid"): (1, SLOT - 400)}))
        self.assertEqual([e["src_sourcetype"] for e in ctx.state["sources"]], ["big", "mid", "small"])
        self.assertEqual(list(ctx.state["sources_all"]), [e["source_key"] for e in ctx.state["sources"]])


class Skip(unittest.TestCase):

    def test_a_source_without_cycle_events_and_no_open_work_is_skipped_but_kept_in_sources_all(self):
        stored = stored_source("main", "a", first_seen_run="20261001T0000Z", state="active", next_profile_due=float(SLOT + 3600))
        ctx = run_s1(scenario(day={("main", "a"): (50, SLOT - 7200)}, stored=[stored]))
        key = skey("main", "a")
        self.assertNotIn(key, [e["source_key"] for e in ctx.state["sources"]])
        self.assertFalse(ctx.state["sources_all"][key]["plan_due"])
        self.assertIn(key, ctx.kv["matalog_sources"])

    def test_a_source_with_day_events_and_a_profile_due_is_not_skipped(self):
        stored = stored_source("main", "a", first_seen_run="20261001T0000Z", state="active", next_profile_due=float(SLOT))
        ctx = run_s1(scenario(day={("main", "a"): (50, SLOT - 7200)}, stored=[stored]))
        self.assertEqual([e["source_key"] for e in ctx.state["sources"]], [skey("main", "a")])

    def test_a_source_with_cycle_events_is_due(self):
        stored = stored_source("main", "a", first_seen_run="20261001T0000Z", state="active", next_profile_due=float(SLOT + 3600))
        ctx = run_s1(scenario(day={("main", "a"): (50, SLOT - 400)}, cycle={("main", "a"): (5, SLOT - 400)}, stored=[stored]))
        self.assertTrue(ctx.state["sources_all"][skey("main", "a")]["plan_due"])

    def test_a_discovered_source_without_any_events_is_skipped(self):
        stored = stored_source("main", "a", first_seen_run="20261001T0000Z", state="active", last_discovered_run="20261001T0000Z")
        ctx = run_s1(scenario(metadata={"main": [("a", 1, SLOT - 2 * DAY)]}, stored=[stored]))
        self.assertEqual(ctx.state["sources"], [])

    def test_counts_hold_sources_total_and_sources_due(self):
        ctx = run_s1(scenario(day={("main", "a"): (5, SLOT - 400), ("main", "b"): (5, SLOT - 7200)}, cycle={("main", "a"): (1, SLOT - 400)},
                              metadata={"main": [("c", 1, SLOT - 3 * DAY)]},
                              stored=[stored_source("main", "b", first_seen_run="20261001T0000Z", state="active", next_profile_due=float(SLOT + 60))]))
        self.assertEqual((ctx.counts["sources_total"], ctx.counts["sources_due"]), (3, 2))

    def test_entries_carry_stored_columns_of_later_steps(self):
        stored = stored_source("main", "a", first_seen_run="20261001T0000Z", state="active", stratum_field="eventName", search_sourcetype="x")
        ctx = run_s1(scenario(day={("main", "a"): (5, SLOT - 400)}, cycle={("main", "a"): (1, SLOT - 400)}, stored=[stored]))
        entry = ctx.state["sources"][0]
        self.assertEqual((entry["_key"], entry["stratum_field"], entry["search_sourcetype"], entry["daily_events"]),
                         (skey("main", "a"), "eventName", "x", 5))
        self.assertFalse(entry["plan_new"])


class Licence(unittest.TestCase):

    def test_licensed_bytes_are_attributed_by_index_and_sourcetype(self):
        ctx = run_s1(scenario(day={("main", "a"): (5, SLOT - 400), ("web", "a"): (5, SLOT - 400)},
                              licence=[{"idx": "main", "st": "a", "b": "1234", "last_time": str(SLOT - 400)},
                                       {"idx": "web", "st": "a", "b": "99", "last_time": str(SLOT - 400)}]))
        self.assertEqual(ctx.kv["matalog_sources"][skey("main", "a")]["daily_bytes"], 1234)
        self.assertEqual(ctx.kv["matalog_sources"][skey("web", "a")]["daily_bytes"], 99)
        self.assertEqual(ctx.kv["matalog_sources"][skey("main", "a")]["daily_bytes_status"], "ok")

    def test_a_failed_licence_search_states_unreadable_and_stores_no_bytes(self):
        ctx = run_s1(scenario(day={("main", "a"): (5, SLOT - 400)}, licence="fail"))
        doc = ctx.kv["matalog_sources"][skey("main", "a")]
        self.assertEqual((doc["daily_bytes"], doc["daily_bytes_status"]), (None, "unreadable"))

    def test_an_empty_licence_log_while_the_pools_show_usage_is_unreadable(self):
        ctx = run_s1(scenario(day={("main", "a"): (5, SLOT - 400)}, licence=[], pools=[{"name": "p", "used_bytes": 10, "quota": 100}]))
        doc = ctx.kv["matalog_sources"][skey("main", "a")]
        self.assertEqual((doc["daily_bytes"], doc["daily_bytes_status"]), (None, "unreadable"))

    def test_an_empty_licence_log_readable_through_internal_leaves_a_source_with_events_unavailable(self):
        ctx = run_s1(scenario(day={("main", "a"): (5, SLOT - 400), ("_internal", "splunkd"): (9, SLOT - 400)}, licence=[],
                              pools=[{"name": "p", "used_bytes": 0, "quota": 100}]))
        doc = ctx.kv["matalog_sources"][skey("main", "a")]
        self.assertEqual((doc["daily_bytes"], doc["daily_bytes_status"]), (None, "unavailable"))

    def test_an_empty_licence_log_without_internal_events_is_unreadable_even_when_the_pools_show_nothing_used(self):
        ctx = run_s1(scenario(day={("main", "a"): (5, SLOT - 400)}, licence=[], pools=[{"name": "p", "used_bytes": 0, "quota": 100}]))
        doc = ctx.kv["matalog_sources"][skey("main", "a")]
        self.assertEqual((doc["daily_bytes"], doc["daily_bytes_status"]), (None, "unreadable"))
        self.assertEqual([c for c in ctx.client.calls if c[0] == "licence_pools"], [])

    def test_an_empty_licence_log_with_unreadable_pools_is_unreadable(self):
        ctx = scenario(day={("main", "a"): (5, SLOT - 400), ("_internal", "splunkd"): (9, SLOT - 400)}, licence=[])

        def fail():
            raise client_mod.ClientError("pools forbidden", status=403)
        ctx.client.licence_pools = fail
        run_s1(ctx)
        doc = ctx.kv["matalog_sources"][skey("main", "a")]
        self.assertEqual((doc["daily_bytes"], doc["daily_bytes_status"]), (None, "unreadable"))

    def test_unreadable_daily_bytes_clear_a_stored_value_once_rolled_into_kv(self):
        stored = stored_source("main", "a", first_seen_run="20261001T0000Z", state="active", daily_bytes=500, daily_bytes_status="ok")
        ctx = run_s1(scenario(day={("main", "a"): (5, SLOT - 400)}, licence="fail", stored=[stored]))
        key = skey("main", "a")
        merged = writer_mod.kv_encode(writer_mod.apply_roll("matalog_sources", ctx.kv["matalog_sources"][key], stored))
        self.assertIsNone(merged.get("daily_bytes"))
        self.assertEqual(merged["daily_bytes_status"], "unreadable")

    def test_a_licence_entry_older_than_the_cycle_for_a_source_with_cycle_events_is_stale(self):
        latest = SLOT - 300
        ctx = run_s1(scenario(day={("main", "a"): (5, SLOT - 400)}, cycle={("main", "a"): (5, SLOT - 400)},
                              licence=[{"idx": "main", "st": "a", "b": "50", "last_time": str(latest - 3601)}]))
        doc = ctx.kv["matalog_sources"][skey("main", "a")]
        self.assertEqual((doc["daily_bytes"], doc["daily_bytes_status"]), (50, "stale"))

    def test_squashed_licence_rows_make_unattributed_sources_of_that_index_unreadable(self):
        ctx = run_s1(scenario(day={("main", "a"): (5, SLOT - 400), ("main", "b"): (5, SLOT - 400)},
                              licence=[{"idx": "main", "st": "", "b": "500", "last_time": str(SLOT - 400)},
                                       {"idx": "main", "st": "a", "b": "7", "last_time": str(SLOT - 400)}]))
        self.assertEqual(ctx.kv["matalog_sources"][skey("main", "a")]["daily_bytes_status"], "ok")
        self.assertEqual(ctx.kv["matalog_sources"][skey("main", "b")]["daily_bytes_status"], "unreadable")


class Apps(unittest.TestCase):

    def test_app_versions_from_apps_local_are_staged_for_s5(self):
        ctx = run_s1(scenario(day={("main", "a"): (5, SLOT - 400)},
                              apps=[{"name": "Splunk_TA_aws", "content": {"version": "7.1.0"}, "acl": {}}, {"name": "bare", "content": {}, "acl": {}}]))
        self.assertEqual(dict(ctx.state["app_versions"]), {"Splunk_TA_aws": "7.1.0", "bare": ""})

    def test_apps_local_entries_are_handed_to_s5(self):
        apps = [{"name": "Splunk_TA_aws", "content": {"version": "7.1.0"}, "acl": {}}]
        ctx = run_s1(scenario(day={("main", "a"): (5, SLOT - 400)}, apps=apps))
        self.assertEqual(ctx.state["apps_local"], apps)

    def test_an_unreadable_apps_local_is_an_error_and_leaves_s5_to_read_it(self):
        ctx = scenario(day={("main", "a"): (5, SLOT - 400)})

        def fail():
            raise client_mod.ClientError("apps forbidden", status=403)
        ctx.client.apps_local = fail
        run_s1(ctx)
        self.assertEqual(dict(ctx.state["app_versions"]), {})
        self.assertNotIn("apps_local", ctx.state)
        self.assertEqual([e["subject"] for e in ctx.errors], ["apps"])
        self.assertIn(skey("main", "a"), ctx.state["sources_all"])

    def test_captured_apps_local_versions_are_staged(self):
        ctx = run_s1(captured_context())
        self.assertEqual(ctx.state["app_versions"]["alert_logevent"], "10.4.3")


def s1_and_commit():
    return [step for step in steps_pkg.all_steps() if step.name in ("S1", "S10")]


class Replay(unittest.TestCase):

    def test_a_rerun_of_the_same_run_id_leaves_matalog_sources_unchanged(self):
        s = support.settings(**{"budget.index_scan_interval_seconds": 3600})
        client = fake_client.FakeClient(settings=s)
        first = runner.run_once(s, client, now=SLOT + 5, steps=s1_and_commit())
        before = {k: dict(v) for k, v in client.kv["matalog_sources"].items()}
        again = runner.run_once(s, client, now=SLOT + 5, steps=s1_and_commit())
        self.assertEqual((first["status"], again["status"]), ("ok", "ok"))
        self.assertTrue(before)
        self.assertEqual({k: dict(v) for k, v in client.kv["matalog_sources"].items()}, before)

    def test_a_later_run_over_the_same_data_changes_only_run_columns_of_matalog_sources(self):
        s = support.settings()
        client = fake_client.FakeClient(settings=s)
        runner.run_once(s, client, now=SLOT + 5, steps=s1_and_commit())
        before = {k: dict(v) for k, v in client.kv["matalog_sources"].items()}
        runner.run_once(s, client, now=SLOT + 3605, steps=s1_and_commit())
        after = client.kv["matalog_sources"]
        changed = set()
        for key, doc in before.items():
            for column in set(doc) | set(after[key]):
                if doc.get(column) != after[key].get(column):
                    changed.add(column)
        self.assertLessEqual(changed, {"last_seen_run", "updated_run_id", "base_rate_per_hour"})


class Failures(unittest.TestCase):

    def test_a_failed_day_tstats_fails_the_step(self):
        ctx = scenario(day={("main", "a"): (5, SLOT - 400)})
        serve_tstats(ctx.client, [], [], fail=("source_day",))
        with self.assertRaises(runner.StepFailed):
            run_s1(ctx)

    def test_a_failed_cycle_tstats_fails_the_step(self):
        ctx = scenario(day={("main", "a"): (5, SLOT - 400)})
        serve_tstats(ctx.client, [], [], fail=("source_cycle",))
        with self.assertRaises(runner.StepFailed):
            run_s1(ctx)

    def test_a_failed_index_listing_falls_back_to_known_indexes(self):
        stored = stored_source("web", "b", first_seen_run="20261001T0000Z", state="active")
        ctx = scenario(day={("main", "a"): (5, SLOT - 400)}, metadata={"main": [("a", 1, 2)], "web": [("b", 1, SLOT - 400)]},
                       eventcount="fail", stored=[stored])
        run_s1(ctx)
        jobs = sorted(re.search(r'index="([^"]+)"', c["spl"]).group(1) for c in searches(ctx.client, r"^\| metadata "))
        self.assertEqual(jobs, ["main", "web"])
        self.assertEqual([e["subject"] for e in ctx.errors], ["indexes"])

    def test_a_failed_metadata_job_is_an_error_and_its_sources_still_come_from_tstats(self):
        ctx = scenario(day={("main", "a"): (5, SLOT - 400)}, metadata={"main": [("a", 1, 2)]})
        ctx.client.add_search([r'^\| metadata type=sourcetypes index="main"$'], lambda spec: client_mod.JobResult(status="failed", spl=spec["spl"]))
        run_s1(ctx)
        self.assertIn(skey("main", "a"), ctx.state["sources_all"])
        self.assertEqual([e["subject"] for e in ctx.errors], ["main"])

    def test_a_budget_ceiling_defers_only_metadata_jobs_and_every_source_is_still_staged(self):
        day = {("app", "a"): (5, SLOT - 400), ("main", "a"): (5, SLOT - 400), ("web", "a"): (5, SLOT - 400)}
        ctx = scenario(day=day, metadata={"app": [("a", 1, 2)], "main": [("a", 1, 2)], "web": [("a", 1, 2)]},
                       **{"budget.max_searches_per_cycle": 16, "write.write_reserve_min": 10})
        run_s1(ctx)
        self.assertEqual(len(searches(ctx.client, r"^\| metadata ")), 1)
        self.assertEqual(len(ctx.kv["matalog_sources"]), 3)
        self.assertEqual(ctx.counts["sources_total"], 3)
        self.assertEqual([e["subject"] for e in ctx.errors], ["metadata"])

    def test_a_budget_ceiling_on_listing_licence_and_history_degrades_and_every_source_is_still_staged(self):
        stored = stored_source("main", "a", first_seen_run="20261001T0000Z", base_rate_per_hour=12.5, state="active")
        ctx = scenario(day={("main", "a"): (5, SLOT - 400), ("web", "b"): (5, SLOT - 400)}, stored=[stored],
                       **{"budget.max_searches_per_cycle": 2, "write.write_reserve_min": 0})
        run_s1(ctx)
        self.assertEqual(set(ctx.state["sources_all"]), {skey("main", "a"), skey("web", "b")})
        self.assertEqual(ctx.counts["sources_total"], 2)
        self.assertEqual(ctx.kv["matalog_sources"][skey("main", "a")]["daily_bytes_status"], "unreadable")
        self.assertEqual(ctx.state["sources_all"][skey("main", "a")]["base_rate_per_hour"], 12.5)
        self.assertEqual(len(ctx.summary["source"]), 2)
        self.assertEqual([e["subject"] for e in ctx.errors], ["indexes", "licence", "history", "metadata"])

    def test_a_budget_ceiling_on_a_tstats_job_fails_the_step(self):
        ctx = scenario(day={("main", "a"): (5, SLOT - 400)}, **{"budget.max_searches_per_cycle": 1, "write.write_reserve_min": 0})
        with self.assertRaises(runner.StepFailed):
            run_s1(ctx)

    def test_rebuild_mode_issues_no_search(self):
        ctx = scenario(day={("main", "a"): (5, SLOT - 400)}, run_mode="rebuild")
        run_s1(ctx)
        self.assertEqual([c for c in ctx.client.calls if c[0] == "search"], [])
        self.assertNotIn("sources", ctx.state)


if __name__ == "__main__":
    unittest.main()
