import json
import math
import unittest

import support
from matalog import client as client_mod
from matalog import keys, rows, writer
from matalog.steps import s4_profile
from matalog.steps.s4_profile import Profile
import fake_client

CS = ("matalog_json", "crowdstrike:events:sensor")
SPLUNKD = ("_internal", "splunkd")
CS_KEY = keys.source_key(*CS)
SPLUNKD_KEY = keys.source_key(*SPLUNKD)
STRATA = ("ProcessRollup2", "FileDeleteInfo")
WEEK_MATCH = [r"index=matalog_profiles kind=field mode=profile", r"matalog_d=abs"]


def fixture_fields(name):
    """The fieldsummary rows a profile writes field rows for: non-zero count, counters excluded."""
    data = fake_client.load_fixture(name)
    return [r for r in data["results"] if r["field"] not in ("matalog_n", "matalog_t") and int(r["count"]) > 0]


def fixture_events(name):
    data = fake_client.load_fixture(name)
    return [int(r["count"]) for r in data["results"] if r["field"] == "matalog_n"][0]


def source_doc(ident, priority=1.0, profile_mode="unsampled", daily_events=20000, stratum_field=None):
    values = dict(state="active", priority=priority, profile_mode=profile_mode, daily_events=daily_events)
    if stratum_field:
        values["stratum_field"] = stratum_field
    return rows.sources_doc(ident[0], ident[1], **values)


def strata_docs(ident, values, state="active"):
    out = [rows.strata_doc(ident[0], ident[1], keys.ALL, keys.ALL, state="active")]
    for value in values:
        out.append(rows.strata_doc(ident[0], ident[1], "event_simpleName", value, state=state))
    return out


def context(client=None, sources=None, strata=None, stored=None, now=support.SLOT + 10, **overrides):
    ctx = support.context(client=client, now=now, **overrides)
    ctx.state["sources"] = sources if sources is not None else [source_doc(CS, stratum_field="event_simpleName")]
    ctx.state["strata"] = strata if strata is not None else {CS_KEY: strata_docs(CS, STRATA)}
    for key, doc in (stored or {}).items():
        merged = dict(doc)
        merged["_key"] = key
        ctx.client.kv["matalog_sources"][key] = merged
    return ctx


def profile_searches(ctx):
    return [c[1] for c in ctx.client.calls if c[0] == "search" and c[1].get("step") == "S4" and c[1].get("subject_key") != "week_baseline"
            and not str(c[1].get("subject_key")).startswith(s4_profile.PROBE_SUBJECT)]


def week_searches(ctx):
    return [c[1] for c in ctx.client.calls if c[0] == "search" and c[1].get("subject_key") == "week_baseline"]


def field_rows(ctx, stratum_value=None):
    return [r for r in ctx.summary["field"] if stratum_value is None or r["stratum_value"] == stratum_value]


def run(ctx):
    Profile().run(ctx)
    return ctx


class Due(unittest.TestCase):
    def test_only_sources_due_at_or_before_the_slot_start_are_profiled(self):
        cases = [("on_time", support.SLOT), ("overdue", support.SLOT - 3600), ("future", support.SLOT + 3600), ("never", None)]
        sources, strata, stored = [], {}, {}
        for name, due in cases:
            ident = ("idx_" + name, "st")
            key = keys.source_key(*ident)
            sources.append(source_doc(ident))
            strata[key] = [rows.strata_doc(ident[0], ident[1], keys.ALL, keys.ALL, state="active")]
            if due is not None:
                stored[key] = {"next_profile_due": float(due)}
                strata[key][0]["last_profiled_run"] = keys.run_id_of(due - 86400)
        client = fake_client.FakeClient(settings=support.settings())
        client.add_results([r"sourcetype=\"st\" \| head 100000 ", r"fieldsummary"], [{"field": "matalog_n", "count": "10", "distinct_count": "1", "is_exact": "1", "numeric_count": "10", "values": "[]"}])
        ctx = run(context(client=client, sources=sources, strata=strata, stored=stored))
        searched = sorted(s["spl"].split()[1] for s in profile_searches(ctx))
        self.assertEqual(searched, ['index="idx_never"', 'index="idx_on_time"', 'index="idx_overdue"'])
        self.assertEqual((ctx.counts["sources_profiled"], ctx.counts["sources_deferred"]), (3, 0))
        self.assertNotIn("sources_due", ctx.counts)


class Jobs(unittest.TestCase):
    def test_one_job_per_active_stratum_on_the_profile_window_with_head_counter_and_fieldsummary(self):
        strata = {CS_KEY: strata_docs(CS, STRATA) + [rows.strata_doc(CS[0], CS[1], "event_simpleName", "DmpFileWritten", state="deferred")]}
        ctx = run(context(strata=strata))
        searches = profile_searches(ctx)
        self.assertEqual(len(searches), 2)
        expected_keys = set(keys.stratum_key(CS[0], CS[1], "event_simpleName", v) for v in STRATA)
        self.assertEqual(set(s["subject_key"] for s in searches), expected_keys)
        for spec in searches:
            self.assertEqual((spec["earliest"], spec["latest"]), ctx.windows["profile"])
            self.assertEqual(spec["sample_ratio"], 1)
            self.assertIn('search index="matalog_json" sourcetype="crowdstrike:events:sensor" event_simpleName=', spec["spl"])
            self.assertIn("| head 100000 | eval matalog_n=1, matalog_t=_time | fieldsummary maxvals=100", spec["spl"])
        self.assertNotIn("DmpFileWritten", " ".join(s["spl"] for s in searches))

    def test_sampled_sources_search_at_the_profile_sample_ratio_and_record_it(self):
        ctx = run(context(sources=[source_doc(CS, profile_mode="sampled", daily_events=5000000, stratum_field="event_simpleName")],
                          **{"profile.sample_ratio": 10}))
        self.assertEqual(set(s["sample_ratio"] for s in profile_searches(ctx)), {10})
        self.assertEqual(set(r["sample_ratio"] for r in ctx.summary["stratum"]), {10})
        self.assertEqual(ctx.staged("matalog_sources", CS_KEY)["sample_ratio"], 10)
        docs = [d for d in ctx.kv["matalog_fields"].values() if d.get("level") == "stratum"]
        self.assertEqual(set(d["cur_prof_sample_ratio"] for d in docs), {10})

    def test_unsampled_sources_search_without_sampling_and_record_ratio_one(self):
        ctx = run(context())
        self.assertEqual(set(s["sample_ratio"] for s in profile_searches(ctx)), {1})
        self.assertEqual(ctx.staged("matalog_sources", CS_KEY)["sample_ratio"], 1)

    def test_profile_mode_falls_back_to_the_volume_threshold_when_the_source_doc_lacks_it(self):
        doc = source_doc(CS, stratum_field="event_simpleName", daily_events=2000000)
        del doc["profile_mode"]
        ctx = run(context(sources=[doc]))
        self.assertEqual(set(s["sample_ratio"] for s in profile_searches(ctx)), {100})

    def test_an_unstratified_source_profiles_its_whole_source_stratum(self):
        ctx = run(context(sources=[source_doc(SPLUNKD)], strata={}))
        searches = profile_searches(ctx)
        self.assertEqual(len(searches), 1)
        self.assertEqual(searches[0]["subject_key"], keys.stratum_key(SPLUNKD[0], SPLUNKD[1], keys.ALL, keys.ALL))
        self.assertTrue(searches[0]["spl"].startswith('search index="_internal" sourcetype="splunkd" | head 100000 '))


class Rows(unittest.TestCase):
    def test_each_stratum_writes_one_profile_stratum_row_and_one_full_field_row_per_field(self):
        ctx = run(context())
        self.assertEqual(sorted(r["stratum_value"] for r in ctx.summary["stratum"]), sorted(STRATA))
        for row in ctx.summary["stratum"]:
            name = "s4_crowdstrike_%s_profile" % row["stratum_value"]
            fields = fixture_fields(name)
            self.assertEqual(row["mode"], "profile")
            self.assertEqual(row["events_seen"], fixture_events(name))
            self.assertEqual(row["events_scanned"], fake_client.load_fixture(name)["job"]["scanCount"])
            self.assertEqual(row["fields_found"], len(fields))
            self.assertEqual((row["truncated"], row["fields_truncated"]), (0, 0))
            written = field_rows(ctx, row["stratum_value"])
            self.assertEqual(sorted(r["field_name"] for r in written), sorted(f["field"] for f in fields))
            self.assertTrue(all(r["mode"] == "profile" and r["shape"] == "full" for r in written))
            self.assertTrue(all(r["events_in_stratum"] == row["events_seen"] for r in written))

    def test_counter_fields_and_zero_count_fields_get_no_field_row(self):
        ctx = run(context())
        names = set(r["field_name"] for r in field_rows(ctx))
        self.assertFalse(names & {"matalog_n", "matalog_t", "eventtype", "tag"})

    def test_rows_fit_max_row_bytes_and_validate(self):
        ctx = run(context())
        for row in ctx.summary["field"] + ctx.summary["stratum"]:
            rows.validate(row)
            self.assertLessEqual(rows.row_bytes(row), ctx.settings.profile.max_row_bytes)

    def test_head_truncation_marks_the_row_and_records_the_window_actually_covered(self):
        ctx = run(context(strata={CS_KEY: strata_docs(CS, ["ProcessRollup2"])}, **{"profile.profile_head_events": 5000}))
        row = ctx.summary["stratum"][0]
        data = fake_client.load_fixture("s4_crowdstrike_ProcessRollup2_profile_head")
        oldest = [float(r["min"]) for r in data["results"] if r["field"] == "matalog_t"][0]
        self.assertEqual(row["truncated"], 1)
        self.assertEqual(row["earliest"], float(math.floor(oldest)))
        self.assertEqual(row["latest"], float(ctx.windows["profile"][1]))
        self.assertTrue(all(r["earliest"] == row["earliest"] for r in field_rows(ctx)))

    def test_fields_over_max_fields_per_stratum_are_counted_not_stored(self):
        ctx = run(context(strata={CS_KEY: strata_docs(CS, ["FileDeleteInfo"])}, **{"discovery.max_fields_per_stratum": 5}))
        row = ctx.summary["stratum"][0]
        self.assertEqual(row["fields_truncated"], 1)
        self.assertEqual(row["fields_found"], len(fixture_fields("s4_crowdstrike_FileDeleteInfo_profile")))
        self.assertEqual(len(field_rows(ctx)), 5)

    def test_version_top_on_the_profile_stratum_row_comes_from_the_version_field(self):
        doc = source_doc(CS, stratum_field="event_simpleName")
        doc["version_field"] = "ConfigBuild"
        ctx = run(context(sources=[doc]))
        for row in ctx.summary["stratum"]:
            self.assertTrue(row["version_top"])
            self.assertEqual(len(row["version_top"]), len(row["version_top_counts"]))
        self.assertNotIn("version_top", ctx.staged("matalog_strata", ctx.summary["stratum"][0]["stratum_key"]))

    def test_the_full_row_carries_the_stored_origin(self):
        client = fake_client.FakeClient(settings=support.settings())
        key = keys.field_key(CS[0], CS[1], "event_simpleName", "FileDeleteInfo", "aid")
        client.kv["matalog_fields"][key] = {"_key": key, "origin": "json_auto", "origin_app": "TA-crowdstrike", "presence": "present"}
        ctx = run(context(client=client, strata={CS_KEY: strata_docs(CS, ["FileDeleteInfo"])}))
        row = [r for r in field_rows(ctx) if r["field_name"] == "aid"][0]
        self.assertEqual((row["origin"], row["origin_app"]), ("json_auto", "TA-crowdstrike"))
        self.assertNotIn("origin", ctx.staged("matalog_fields", key))


class FieldDocs(unittest.TestCase):
    def test_field_snapshots_hold_raw_counts_not_scaled_by_the_sample_ratio(self):
        ctx = run(context(sources=[source_doc(CS, profile_mode="sampled", stratum_field="event_simpleName")]))
        fields = dict((f["field"], f) for f in fixture_fields("s4_crowdstrike_FileDeleteInfo_profile"))
        events = fixture_events("s4_crowdstrike_FileDeleteInfo_profile")
        doc = ctx.staged("matalog_fields", keys.field_key(CS[0], CS[1], "event_simpleName", "FileDeleteInfo", "aid"))
        self.assertEqual(doc["cur_prof_count"], int(fields["aid"]["count"]))
        self.assertEqual(doc["cur_prof_events"], events)
        self.assertEqual(doc["cur_prof_distinct"], int(fields["aid"]["distinct_count"]))
        self.assertEqual(doc["cur_prof_sample_ratio"], 100)

    def test_field_docs_equal_the_rebuild_mapping_of_their_rows_plus_week_and_measured_flags(self):
        ctx = run(context())
        for row in field_rows(ctx):
            _, expected = rows.kv_from_summary(row)
            staged = ctx.staged("matalog_fields", row["field_key"])
            for column, value in expected.items():
                if column in ("origin", "origin_app"):
                    continue
                self.assertEqual(staged[column], value, column)
            self.assertEqual(staged["profile_id"], row["profile_id"])
            self.assertEqual(staged["cur_prof_distinct_exact"], row["distinct_exact"])
            self.assertEqual((staged["is_rollup"], staged["rollup_strata"], staged["observed"]), (0, 0, 1))
            self.assertEqual((staged["last_seen_run"], staged["last_seen_time"]), (ctx.run_id, row["latest"]))
            for suffix in s4_profile.PROF_SUFFIXES:
                self.assertIn("week_prof_" + suffix, staged)

    def test_presence_and_first_seen_run_staged_by_discovery_are_kept(self):
        ctx = context(strata={CS_KEY: strata_docs(CS, ["FileDeleteInfo"])})
        key = keys.field_key(CS[0], CS[1], "event_simpleName", "FileDeleteInfo", "aid")
        ctx.stage_kv("matalog_fields", rows.fields_doc(CS[0], CS[1], "event_simpleName", "FileDeleteInfo", "aid",
                                                       presence="unobserved", first_seen_run="20261001T0000Z"))
        run(ctx)
        staged = ctx.staged("matalog_fields", key)
        self.assertEqual((staged["presence"], staged["first_seen_run"]), ("unobserved", "20261001T0000Z"))
        other = ctx.staged("matalog_fields", keys.field_key(CS[0], CS[1], "event_simpleName", "FileDeleteInfo", "cid"))
        self.assertEqual((other["presence"], other["first_seen_run"]), ("present", ctx.run_id))

    def test_a_later_profile_rolls_the_current_snapshot_into_base(self):
        first = run(context())
        key = keys.field_key(CS[0], CS[1], "event_simpleName", "FileDeleteInfo", "aid")
        first.kv_writer.write("matalog_fields", [first.staged("matalog_fields", key)])
        second = context(client=first.client, now=support.SLOT + 86400 + 10)
        run(second)
        after = second.after_roll("matalog_fields", key)
        self.assertEqual(after["cur_prof_run_id"], second.run_id)
        self.assertEqual(after["base_prof_run_id"], first.run_id)
        self.assertEqual(after["base_prof_count"], first.staged("matalog_fields", key)["cur_prof_count"])


class SourceAndStrata(unittest.TestCase):
    def test_a_profiled_source_records_ratio_last_run_and_next_due_one_interval_after_the_slot(self):
        ctx = run(context())
        doc = ctx.staged("matalog_sources", CS_KEY)
        self.assertEqual(doc["last_profiled_run"], ctx.run_id)
        self.assertEqual(doc["next_profile_due"], float(support.SLOT + 86400))
        for value in STRATA:
            strata = ctx.staged("matalog_strata", keys.stratum_key(CS[0], CS[1], "event_simpleName", value))
            self.assertEqual(strata["last_profiled_run"], ctx.run_id)
        self.assertEqual(ctx.state["profiled_sources"], [CS_KEY])
        self.assertEqual(ctx.state["profile_deferred"], [])

    def test_a_stratified_source_gets_rollup_rows_over_its_profiled_strata(self):
        ctx = run(context())
        per = dict((v, dict((f["field"], f) for f in fixture_fields("s4_crowdstrike_%s_profile" % v))) for v in STRATA)
        rollup = ctx.staged("matalog_fields", keys.source_field_key(CS[0], CS[1], "aid"))
        self.assertEqual((rollup["level"], rollup["is_rollup"], rollup["rollup_strata"]), ("source", 1, 2))
        self.assertEqual(rollup["cur_prof_count"], sum(int(per[v]["aid"]["count"]) for v in STRATA))
        self.assertEqual(rollup["cur_prof_events"], sum(fixture_events("s4_crowdstrike_%s_profile" % v) for v in STRATA))
        self.assertEqual(rollup["cur_prof_distinct"], max(int(per[v]["aid"]["distinct_count"]) for v in STRATA))
        self.assertEqual(rollup["cur_prof_run_id"], ctx.run_id)
        self.assertAlmostEqual(rollup["cur_prof_coverage"], float(rollup["cur_prof_count"]) / rollup["cur_prof_events"])
        only_one = [f for f in per["ProcessRollup2"] if f not in per["FileDeleteInfo"]][0]
        self.assertEqual(ctx.staged("matalog_fields", keys.source_field_key(CS[0], CS[1], only_one))["rollup_strata"], 1)
        name_rollup = ctx.staged("matalog_fields", keys.source_field_key(CS[0], CS[1], "event_simpleName"))
        self.assertEqual(name_rollup["is_stratum_field"], 1)
        self.assertEqual(sorted(name_rollup["top_values"]), sorted(STRATA))
        self.assertFalse([r for r in ctx.summary["field"] if r["stratum_value"] == keys.ALL])

    def test_an_unstratified_source_gets_no_rollup_rows(self):
        ctx = run(context(sources=[source_doc(SPLUNKD)], strata={}))
        self.assertFalse([d for d in ctx.kv["matalog_fields"].values() if d.get("is_rollup") == 1])


class Budget(unittest.TestCase):
    def test_a_source_that_does_not_fit_is_profiled_in_part_and_stays_due_ahead_of_smaller_ones_after_it(self):
        sources = [source_doc(CS, priority=5.0, stratum_field="event_simpleName"), source_doc(SPLUNKD, priority=1.0)]
        stored = {CS_KEY: {"next_profile_due": float(support.SLOT)}}
        ctx = context(sources=sources, stored=stored, **{"budget.max_searches_per_cycle": 12, "write.write_reserve_min": 10})
        self.assertEqual(ctx.budget.plannable(), 2)
        run(ctx)
        staged = ctx.staged("matalog_sources", CS_KEY)
        self.assertEqual((staged.get("strata_profile_due"), staged.get("last_profiled_run")), (1, None))
        self.assertEqual(ctx.state["profiled_sources"], [CS_KEY])
        self.assertEqual(ctx.state["profile_deferred"], [CS_KEY, SPLUNKD_KEY])
        self.assertEqual((ctx.counts["sources_profiled"], ctx.counts["sources_deferred"]), (1, 2))
        self.assertEqual((ctx.counts["strata_profile_due"], ctx.counts["strata_profiled"]), (3, 1))
        self.assertEqual(len(week_searches(ctx)), 1)
        self.assertEqual(len(set(r["stratum_value"] for r in ctx.summary["field"] if r["source_key"] == CS_KEY)), 1)

    def test_one_search_is_held_for_the_week_baseline(self):
        ctx = context(**{"budget.max_searches_per_cycle": 13, "write.write_reserve_min": 10})
        self.assertEqual(ctx.budget.plannable(), 3)
        run(ctx)
        self.assertEqual((len(profile_searches(ctx)), len(week_searches(ctx))), (2, 1))
        tight = context(**{"budget.max_searches_per_cycle": 12, "write.write_reserve_min": 10})
        run(tight)
        self.assertEqual((len(profile_searches(tight)), len(week_searches(tight)), tight.counts["sources_deferred"]), (1, 1, 1))

    def test_a_source_overdue_from_an_earlier_slot_is_planned_before_higher_priority_sources(self):
        sources = [source_doc(SPLUNKD, priority=9.0), source_doc(CS, priority=1.0, stratum_field="event_simpleName")]
        stored = {CS_KEY: {"next_profile_due": float(support.SLOT - 3600)}, SPLUNKD_KEY: {"next_profile_due": float(support.SLOT)}}
        ctx = run(context(sources=sources, stored=stored, **{"budget.max_searches_per_cycle": 13, "write.write_reserve_min": 10}))
        self.assertEqual(ctx.state["profiled_sources"], [CS_KEY])
        self.assertEqual(ctx.state["profile_deferred"], [SPLUNKD_KEY])

    def test_a_failed_job_defers_its_stratum_only_and_the_source_stays_due(self):
        client = fake_client.FakeClient(settings=support.settings())
        client.add_search([r'event_simpleName="FileDeleteInfo"', r"matalog_t=_time"], {"results": [], "job": {"status": "failed"}})
        ctx = run(context(client=client))
        staged = ctx.staged("matalog_sources", CS_KEY)
        self.assertEqual((staged.get("strata_profile_due"), staged.get("last_profiled_run")), (1, None))
        self.assertEqual(set(r["stratum_value"] for r in ctx.summary["field"] + ctx.summary["stratum"]), {"ProcessRollup2"})
        self.assertFalse([d for d in ctx.kv["matalog_fields"].values() if d.get("stratum_value") == "FileDeleteInfo"])
        self.assertEqual(ctx.counts["sources_deferred"], 1)
        self.assertTrue(any(e["step"] == "S4" and e["subject"] == CS_KEY for e in ctx.errors))
        self.assertEqual(len(week_searches(ctx)), 1)

    def test_a_ceiling_hit_mid_source_defers_the_rest_of_its_strata(self):
        ctx = context(**{"budget.max_events_scanned_per_cycle": 1})
        ctx.budget.max_concurrent = 1
        run(ctx)
        self.assertEqual(ctx.counts["sources_deferred"], 1)
        self.assertEqual(ctx.staged("matalog_sources", CS_KEY).get("strata_profile_due"), 1)
        self.assertEqual(ctx.budget.exhausted, "scanned")


class WeekBaseline(unittest.TestCase):
    def week_rows(self, ctx, values):
        out = []
        for value, count, events in values:
            out.append({"field_key": keys.field_key(CS[0], CS[1], "event_simpleName", value, "aid"), "run_id": "20261006T1400Z",
                        "count": str(count), "events_in_stratum": str(events), "coverage": str(float(count) / events),
                        "distinct": "40", "distinct_exact": "1", "sample_ratio": "1"})
        return out

    def test_week_baseline_comes_from_one_search_over_committed_profile_rows_of_the_profiled_sources(self):
        client = fake_client.FakeClient(settings=support.settings())
        ctx = context(client=client, sources=[source_doc(CS, stratum_field="event_simpleName"), source_doc(SPLUNKD)])
        client.add_results(WEEK_MATCH, self.week_rows(ctx, [("ProcessRollup2", 80, 100), ("FileDeleteInfo", 30, 60)]))
        run(ctx)
        searches = week_searches(ctx)
        self.assertEqual(len(searches), 1)
        spl = searches[0]["spl"]
        self.assertIn(CS_KEY, spl)
        self.assertIn(SPLUNKD_KEY, spl)
        self.assertIn(writer.committed_subsearch(), spl)
        self.assertIn('NOT run_id="%s"' % ctx.run_id, spl)
        target = support.SLOT - 7 * 86400
        self.assertIn("abs(_time-%d)" % target, spl)
        self.assertEqual((searches[0]["earliest"], searches[0]["latest"]), (target - 86400, target + 86400))
        self.assertEqual(searches[0]["max_rows"], ctx.settings.rebuild.rebuild_max_rows)
        doc = ctx.staged("matalog_fields", keys.field_key(CS[0], CS[1], "event_simpleName", "ProcessRollup2", "aid"))
        self.assertEqual((doc["week_prof_run_id"], doc["week_prof_count"], doc["week_prof_events"], doc["week_prof_distinct_exact"]),
                         ("20261006T1400Z", 80, 100, 1))
        missing = ctx.staged("matalog_fields", keys.field_key(CS[0], CS[1], "event_simpleName", "ProcessRollup2", "cid"))
        self.assertIsNone(missing["week_prof_run_id"])
        rollup = ctx.staged("matalog_fields", keys.source_field_key(CS[0], CS[1], "aid"))
        self.assertEqual((rollup["week_prof_count"], rollup["week_prof_events"]), (110, 160))
        self.assertAlmostEqual(rollup["week_prof_coverage"], 110.0 / 160)

    def test_no_week_search_runs_when_nothing_was_profiled(self):
        stored = {CS_KEY: {"next_profile_due": float(support.SLOT + 3600)}}
        strata = {CS_KEY: [dict(d, last_profiled_run=keys.run_id_of(support.SLOT)) for d in strata_docs(CS, STRATA)]}
        ctx = run(context(stored=stored, strata=strata))
        self.assertEqual([c for c in ctx.client.calls if c[0] == "search"], [])
        self.assertEqual((ctx.counts["sources_profiled"], ctx.counts["sources_deferred"]), (0, 0))

    def test_a_failed_week_search_leaves_stored_week_columns_alone(self):
        client = fake_client.FakeClient(settings=support.settings())
        client.add_search(WEEK_MATCH, {"results": [], "job": {"status": "failed"}})
        ctx = run(context(client=client))
        doc = ctx.staged("matalog_fields", keys.field_key(CS[0], CS[1], "event_simpleName", "ProcessRollup2", "aid"))
        self.assertNotIn("week_prof_run_id", doc)
        self.assertTrue(any(e["subject"] == "week_baseline" for e in ctx.errors))
        self.assertEqual(ctx.counts["sources_profiled"], 1)


class Candidates(unittest.TestCase):
    def test_stratum_candidates_on_an_unstratified_source_come_from_its_fieldsummary_rows(self):
        ctx = run(context(sources=[source_doc(CS)], strata={}))
        candidates = ctx.staged("matalog_sources", CS_KEY)["stratum_candidates"]
        self.assertIn("event_simpleName", candidates)
        self.assertEqual((len(profile_searches(ctx)), len(week_searches(ctx))), (1, 1))

    def test_the_field_that_selects_splunkd_schemas_is_a_stratum_candidate(self):
        ctx = run(context(sources=[source_doc(SPLUNKD)], strata={}))
        self.assertIn("component", ctx.staged("matalog_sources", SPLUNKD_KEY)["stratum_candidates"])

    def test_a_stratified_source_gets_no_stratum_candidates(self):
        ctx = run(context())
        self.assertEqual(ctx.staged("matalog_sources", CS_KEY)["stratum_candidates"], [])

    def test_candidates_need_bounded_distinct_and_five_partitioned_fields(self):
        def fs(field, count, distinct, values):
            return {"field": field, "count": str(count), "distinct_count": str(distinct), "is_exact": "1", "numeric_count": "0",
                    "values": json.dumps([{"value": v, "count": c} for v, c in values])}
        events = 100
        base = [fs("matalog_n", events, 1, [("1", events)]), fs("kind", 100, 2, [("a", 60), ("b", 40)]),
                fs("one", 100, 1, [("x", 100)])]
        partitioned = [fs("a%d" % i, 60, 5, [("v", 60)]) for i in range(4)]
        self.assertEqual(s4_profile.stratum_candidates(base + partitioned, events), [])
        self.assertEqual(s4_profile.stratum_candidates(base + partitioned + [fs("b0", 41, 3, [("w", 41)])], events), ["kind"])



def fs_row(field, count, distinct, values, exact=1, numeric_count=0, mean=None, low=None, high=None):
    row = {"field": field, "count": str(count), "distinct_count": str(distinct), "is_exact": str(exact),
           "numeric_count": str(numeric_count), "values": json.dumps([{"value": v, "count": c} for v, c in values])}
    if mean is not None:
        row.update(mean=str(mean), min=str(low), max=str(high), stdev="0")
    return row


def counter_rows(events, oldest=support.SLOT - 3000):
    return [fs_row("matalog_n", events, 1, [("1", events)], numeric_count=events, mean=1, low=1, high=1),
            fs_row("matalog_t", events, events, [], numeric_count=events, mean=oldest, low=oldest, high=oldest)]


def serve_stratum(client, value, events, fields, field_name="event_simpleName"):
    client.add_results([r'%s="%s"' % (field_name, value), r"matalog_t=_time"], counter_rows(events) + fields)


def serve_source(client, sourcetype, events, fields):
    client.add_results([r'sourcetype="%s" \| head' % sourcetype, r"matalog_t=_time"], counter_rows(events) + fields)


SYN = ("SynA", "SynB")


def synthetic_client(**overrides):
    client = fake_client.FakeClient(settings=support.settings(**overrides))
    serve_stratum(client, "SynA", 100, [
        fs_row("f", 50, 3, [("x", 5), ("y", 4), ("z", 1)]),
        fs_row("n", 40, 2, [("10", 1)], exact=0, numeric_count=1, mean=10, low=10, high=10),
        fs_row("t", 30, 2, [("1", 20), ("2", 10)], numeric_count=30, mean=1.3, low=1, high=2),
        fs_row("id", 100, 1000, [("u1", 1), ("u2", 1)]),
    ])
    serve_stratum(client, "SynB", 80, [
        fs_row("f", 30, 7, [("x", 7), ("w", 6)]),
        fs_row("n", 20, 4, [("1", 1), ("2", 1), ("3", 1)], numeric_count=3, mean=2, low=1, high=3),
        fs_row("t", 30, 1, [("a", 30)]),
        fs_row("id", 80, 5, [("v", 80)]),
    ])
    return client


def synthetic_context(client, **overrides):
    return context(client=client, strata={CS_KEY: strata_docs(CS, SYN)}, **overrides)


def rollup(ctx, name):
    return ctx.staged("matalog_fields", keys.source_field_key(CS[0], CS[1], name))


class Rollups(unittest.TestCase):
    def test_rollups_sum_counts_and_take_max_distinct_inexact_over_children_without_the_probe(self):
        ctx = run(synthetic_context(synthetic_client()))
        f, n = rollup(ctx, "f"), rollup(ctx, "n")
        self.assertEqual((f["cur_prof_count"], f["cur_prof_events"], f["cur_prof_distinct"], f["rollup_strata"]), (80, 180, 7, 2))
        self.assertEqual((f["cur_prof_distinct_exact"], n["cur_prof_distinct_exact"]), (0, 0))

    def test_rollup_numeric_stats_take_min_max_and_the_mean_weighted_by_numeric_count(self):
        ctx = run(synthetic_context(synthetic_client()))
        n = rollup(ctx, "n")
        self.assertEqual((n["numeric_count"], n["num_min"], n["num_max"]), (4, 1.0, 10.0))
        self.assertAlmostEqual(n["num_mean"], (10.0 * 1 + 2.0 * 3) / 4)

    def test_rollup_top_values_merge_children_by_summed_counts(self):
        ctx = run(synthetic_context(synthetic_client()))
        f = rollup(ctx, "f")
        self.assertEqual((f["top_values"], f["top_counts"]), (["x", "w", "y", "z"], ["12", "6", "4", "1"]))
        self.assertEqual(f["values_hash"], rows.values_hash(["x", "w", "y", "z"]))

    def test_rollup_type_guess_is_mixed_without_a_strict_majority(self):
        ctx = run(synthetic_context(synthetic_client()))
        self.assertEqual(rollup(ctx, "t")["type_guess"], "mixed")
        self.assertEqual(rollup(ctx, "f")["type_guess"], "string")

    def test_a_rollup_is_an_identifier_when_any_child_is_and_then_holds_no_top_values(self):
        ctx = run(synthetic_context(synthetic_client()))
        ident = rollup(ctx, "id")
        self.assertEqual((ident["identifier"], ident["top_values"], ident["top_counts"]), (1, [], []))

    def test_a_new_rollup_is_present_and_first_seen_in_this_run(self):
        ctx = run(synthetic_context(synthetic_client()))
        f = rollup(ctx, "f")
        self.assertEqual((f["presence"], f["first_seen_run"], f["observed"], f["last_seen_run"]), ("present", ctx.run_id, 1, ctx.run_id))

    def test_rollup_strata_set_by_discovery_is_kept(self):
        ctx = synthetic_context(synthetic_client())
        ctx.stage_kv("matalog_fields", rows.fields_doc(CS[0], CS[1], keys.ALL, keys.ALL, "f", is_rollup=1, rollup_strata=10, presence="present"))
        run(ctx)
        self.assertEqual(rollup(ctx, "f")["rollup_strata"], 10)
        self.assertEqual(rollup(ctx, "n")["rollup_strata"], 2)

    def test_rollup_ties_break_by_value_and_samples_follow_discovery_count_like_rebuild(self):
        client = fake_client.FakeClient(settings=support.settings(**{"profile.top_values": 1}))
        serve_stratum(client, "SynA", 10, [fs_row("f", 10, 1, [("b", 5)])])
        serve_stratum(client, "SynB", 10, [fs_row("f", 9, 1, [("a", 5)])])
        ctx = synthetic_context(client, **{"profile.top_values": 1})
        for value, disc in (("SynA", 1), ("SynB", 50)):
            ctx.stage_kv("matalog_fields", rows.fields_doc(CS[0], CS[1], "event_simpleName", value, "f", presence="present", cur_disc_count=disc))
        run(ctx)
        self.assertEqual(rollup(ctx, "f")["sample_values"], ["a", "b"])
        client = fake_client.FakeClient(settings=support.settings(**{"profile.top_values": 1}))
        serve_stratum(client, "SynA", 10, [fs_row("f", 10, 1, [("b", 5)])])
        serve_stratum(client, "SynB", 10, [fs_row("f", 9, 1, [("a", 5)])])
        ctx = synthetic_context(client, **{"profile.top_values": 1})
        for value, disc in (("SynA", 50), ("SynB", 1)):
            ctx.stage_kv("matalog_fields", rows.fields_doc(CS[0], CS[1], "event_simpleName", value, "f", presence="present", cur_disc_count=disc))
        run(ctx)
        staged = rollup(ctx, "f")
        self.assertEqual((staged["top_values"], staged["top_counts"]), (["a"], ["5"]))
        self.assertEqual(staged["sample_values"], ["b", "a"])
        self.assertEqual(staged["values_hash"], rows.values_hash(["a", "b"]))

    def test_rollup_week_columns_take_the_newest_run_the_and_of_exactness_and_the_max_ratio(self):
        client = synthetic_client()
        week = []
        for value, run_id, exact, ratio in (("SynA", "20261006T1300Z", "0", "1"), ("SynB", "20261006T1500Z", "1", "10")):
            week.append({"field_key": keys.field_key(CS[0], CS[1], "event_simpleName", value, "f"), "run_id": run_id, "count": "10",
                         "events_in_stratum": "20", "coverage": "0.5", "distinct": "3", "distinct_exact": exact, "sample_ratio": ratio})
        client.add_results(WEEK_MATCH, week)
        ctx = run(synthetic_context(client))
        f = rollup(ctx, "f")
        self.assertEqual((f["week_prof_run_id"], f["week_prof_distinct_exact"], f["week_prof_sample_ratio"]), ("20261006T1500Z", 0, 10))
        self.assertEqual((f["week_prof_count"], f["week_prof_events"]), (20, 40))


class Planning(unittest.TestCase):
    def tight(self, sources, stored=None, strata=None):
        return context(sources=sources, stored=stored, strata=strata if strata is not None else {},
                       **{"budget.max_searches_per_cycle": 12, "write.write_reserve_min": 10})

    def test_sources_equally_due_are_planned_by_priority_descending(self):
        ctx = self.tight([source_doc(SPLUNKD, priority=1.0), source_doc(CS, priority=5.0)])
        self.assertEqual(ctx.budget.plannable(), 2)
        run(ctx)
        self.assertEqual((ctx.state["profiled_sources"], ctx.state["profile_deferred"]), ([CS_KEY], [SPLUNKD_KEY]))

    def test_a_never_profiled_source_enumerated_by_an_earlier_run_is_first_in_line(self):
        low = source_doc(SPLUNKD, priority=1.0)
        low["first_seen_run"] = "20261001T0000Z"
        ctx = run(self.tight([source_doc(CS, priority=5.0), low], stored={CS_KEY: {"next_profile_due": float(support.SLOT)}}))
        self.assertEqual((ctx.state["profiled_sources"], ctx.state["profile_deferred"]), ([SPLUNKD_KEY], [CS_KEY]))

    def test_a_source_first_enumerated_in_this_run_waits_its_priority_turn(self):
        ctx = self.tight([source_doc(CS, priority=5.0), source_doc(SPLUNKD, priority=1.0)], stored={CS_KEY: {"next_profile_due": float(support.SLOT)}})
        ctx.state["sources"][1]["first_seen_run"] = ctx.run_id
        run(ctx)
        self.assertEqual(ctx.state["profiled_sources"], [CS_KEY])

    def test_a_source_at_the_volume_threshold_is_sampled_and_one_below_is_not(self):
        threshold = support.settings().profile.sample_volume_threshold
        for daily, ratio in ((threshold, support.settings().profile.sample_ratio), (threshold - 1, 1)):
            doc = source_doc(CS, stratum_field="event_simpleName", daily_events=daily)
            del doc["profile_mode"]
            ctx = run(context(sources=[doc]))
            self.assertEqual(set(s["sample_ratio"] for s in profile_searches(ctx)), {ratio}, daily)

    def test_duplicate_and_foreign_field_strata_add_no_jobs(self):
        strata = {CS_KEY: strata_docs(CS, STRATA) + strata_docs(CS, STRATA)[1:] +
                  [rows.strata_doc(CS[0], CS[1], "other_field", "X", state="active")]}
        ctx = run(context(strata=strata))
        searches = profile_searches(ctx)
        self.assertEqual(len(searches), 2)
        self.assertFalse([s for s in searches if "other_field" in s["spl"]])

    def test_strata_are_read_from_kv_when_s2_left_none_for_the_source(self):
        client = fake_client.FakeClient(settings=support.settings())
        for doc in strata_docs(CS, ["ProcessRollup2"]):
            client.kv["matalog_strata"][doc["_key"]] = dict(doc)
        ctx = run(context(client=client, strata={}))
        self.assertEqual([s["subject_key"] for s in profile_searches(ctx)], [keys.stratum_key(CS[0], CS[1], "event_simpleName", "ProcessRollup2")])
        self.assertTrue([c for c in client.calls if c[0] == "kv_query" and c[1] == "matalog_strata"])

    def test_the_job_searches_the_search_sourcetype_and_keys_rows_by_the_source_sourcetype(self):
        client = fake_client.FakeClient(settings=support.settings())
        serve_source(client, "cs_alias", 10, [fs_row("aid", 10, 2, [("a", 6), ("b", 4)])])
        doc = source_doc(CS)
        doc["search_sourcetype"] = "cs_alias"
        ctx = run(context(client=client, sources=[doc], strata={}))
        self.assertIn('sourcetype="cs_alias"', profile_searches(ctx)[0]["spl"])
        self.assertEqual([r["src_sourcetype"] for r in field_rows(ctx)], [CS[1]])
        self.assertIsNotNone(ctx.staged("matalog_fields", keys.field_key(CS[0], CS[1], keys.ALL, keys.ALL, "aid")))


class FieldSelection(unittest.TestCase):
    def test_the_fields_kept_under_the_cap_are_the_most_frequent_then_by_name(self):
        client = fake_client.FakeClient(settings=support.settings())
        serve_stratum(client, "SynA", 100, [fs_row("a", 10, 1, [("x", 10)]), fs_row("b", 90, 1, [("x", 90)]),
                                            fs_row("d", 50, 1, [("x", 50)]), fs_row("c", 50, 1, [("x", 50)])])
        ctx = run(context(client=client, strata={CS_KEY: strata_docs(CS, ["SynA"])}, **{"discovery.max_fields_per_stratum": 2}))
        self.assertEqual(sorted(r["field_name"] for r in field_rows(ctx)), ["b", "c"])
        self.assertEqual((ctx.summary["stratum"][0]["fields_found"], ctx.summary["stratum"][0]["fields_truncated"]), (4, 1))

    def test_version_top_is_capped_at_profile_top_values(self):
        client = fake_client.FakeClient(settings=support.settings())
        serve_stratum(client, "SynA", 100, [fs_row("ver", 100, 5, [("v%d" % i, 20) for i in range(5)])])
        doc = source_doc(CS, stratum_field="event_simpleName")
        doc["version_field"] = "ver"
        ctx = run(context(client=client, sources=[doc], strata={CS_KEY: strata_docs(CS, ["SynA"])}, **{"profile.top_values": 3}))
        row = ctx.summary["stratum"][0]
        self.assertEqual((row["version_top"], row["version_top_counts"]), (["v0", "v1", "v2"], ["20", "20", "20"]))


class WeekRead(unittest.TestCase):
    def test_the_week_search_keeps_the_nearest_row_and_the_older_run_on_a_tie(self):
        ctx = run(context())
        self.assertIn("| sort 0 matalog_d run_id | dedup field_key |", week_searches(ctx)[0]["spl"])

    def test_a_rest_error_in_the_week_read_still_stages_rollups_counts_and_state(self):
        client = fake_client.FakeClient(settings=support.settings())

        def broken(spec):
            raise client_mod.ClientError("results read failed", status=500)
        client.add_search(WEEK_MATCH, broken)
        ctx = run(context(client=client))
        self.assertTrue(any(e["subject"] == "week_baseline" for e in ctx.errors))
        self.assertEqual((ctx.counts["sources_profiled"], ctx.state["profiled_sources"]), (1, [CS_KEY]))
        self.assertEqual(rollup(ctx, "aid")["is_rollup"], 1)
        self.assertNotIn("week_prof_run_id", ctx.staged("matalog_fields", keys.field_key(CS[0], CS[1], "event_simpleName", "ProcessRollup2", "aid")))


class Rerun(unittest.TestCase):
    def test_a_rerun_of_an_uncommitted_attempt_stages_the_same_rows_and_kv(self):
        client = fake_client.FakeClient(settings=support.settings())
        first = run(context(client=client))
        second = run(context(client=client))
        self.assertEqual(second.run_id, first.run_id)
        self.assertEqual(second.state["profiled_sources"], first.state["profiled_sources"])
        strip = lambda rs: [dict((k, v) for k, v in r.items() if k not in ("sid", "search_seconds")) for r in rs]
        self.assertEqual(strip(second.summary["stratum"]), strip(first.summary["stratum"]))
        self.assertEqual(len(second.summary["field"]), len(first.summary["field"]))
        for collection in ("matalog_fields", "matalog_strata", "matalog_sources"):
            self.assertEqual(sorted(second.kv[collection]), sorted(first.kv[collection]), collection)
        key = keys.source_field_key(CS[0], CS[1], "aid")
        self.assertEqual(second.staged("matalog_fields", key)["cur_prof_count"], first.staged("matalog_fields", key)["cur_prof_count"])


class CandidateRule(unittest.TestCase):
    def base(self, kind=None):
        events = 100
        kind = kind or fs_row("kind", 100, 2, [("a", 60), ("b", 40)])
        return [kind] + [fs_row("a%d" % i, 60, 5, [("v", 60)]) for i in range(5)], events

    def test_a_field_whose_values_split_five_others_is_a_candidate(self):
        fields, events = self.base()
        self.assertEqual(s4_profile.stratum_candidates(fields, events), ["kind"])

    def test_a_field_carried_by_every_event_is_not_partitioned_by_a_dominant_value(self):
        fields = [fs_row("host", 1000, 2, [("a", 960), ("b", 40)])] + [fs_row("g%d" % i, 1000, 500, [("x", 2)]) for i in range(5)]
        self.assertEqual(s4_profile.stratum_candidates(fields, 1000), [])

    def test_a_candidate_needs_an_exact_value_list(self):
        fields, events = self.base(fs_row("kind", 100, 2, [("a", 60), ("b", 40)], exact=0))
        self.assertEqual(s4_profile.stratum_candidates(fields, events), [])

    def test_a_candidate_needs_coverage_of_at_least_ninety_five_percent(self):
        fields, events = self.base(fs_row("kind", 94, 2, [("a", 60), ("b", 34)]))
        self.assertEqual(s4_profile.stratum_candidates(fields, events), [])

    def test_a_candidate_needs_at_most_fifty_distinct_values(self):
        fields, events = self.base(fs_row("kind", 100, 51, [("a", 60), ("b", 40)]))
        self.assertEqual(s4_profile.stratum_candidates(fields, events), [])
        fields, events = self.base(fs_row("kind", 100, 50, [("a", 60), ("b", 40)]))
        self.assertEqual(s4_profile.stratum_candidates(fields, events), ["kind"])

    def test_a_stratified_source_gets_no_candidates_even_when_its_rows_would_yield_one(self):
        fields, events = self.base()
        client = fake_client.FakeClient(settings=support.settings())
        serve_stratum(client, "SynA", events, fields)
        ctx = run(context(client=client, strata={CS_KEY: strata_docs(CS, ["SynA"])}))
        self.assertEqual(s4_profile.stratum_candidates(counter_rows(events) + fields, events), ["kind"])
        self.assertEqual(ctx.staged("matalog_sources", CS_KEY)["stratum_candidates"], [])

    def test_the_splunkd_corpus_drops_fields_present_in_nearly_every_event(self):
        data = fake_client.load_fixture("s4_splunkd_profile")["results"]
        events = [int(r["count"]) for r in data if r["field"] == "matalog_n"][0]
        self.assertNotIn("source", s4_profile.stratum_candidates(data, events))


if __name__ == "__main__":
    unittest.main()
