import json
import unittest

import support
from matalog import budget as budget_mod
from matalog import client as client_mod
from matalog import keys, rows, runner
from matalog.steps import s3_discover
import fake_client

CS = ("matalog_json", "crowdstrike:events:sensor")
CT = ("matalog_json", "aws:cloudtrail")
SD = ("_internal", "splunkd")
RUN_ID = "20261013T1400Z"
NEXT_RUN_ID = "20261013T1500Z"
PREVIOUS_RUN_ID = "20261013T1300Z"
BUILD = "1007.3.0015406.1"


def source(ident, priority, stratum_field=keys.ALL, version_field=""):
    return rows.sources_doc(*ident, state="active", priority=priority, stratum_field=stratum_field, version_field=version_field, daily_events=1000)


def stratum(ident, field, value, rate):
    return rows.strata_doc(*ident, field, value, state="active", rate_per_hour=rate)


def skey(ident, field, value):
    return keys.stratum_key(*ident, field, value)


def fkey(ident, field, value, name):
    return keys.field_key(*ident, field, value, name)


PHODI = skey(CS, "event_simpleName", "ProcessHandleOpDetectInfo")
DMP = skey(CS, "event_simpleName", "DmpFileWritten")
MISSING = skey(CS, "event_simpleName", keys.MISSING)
PR2 = skey(CS, "event_simpleName", "ProcessRollup2")
LOGIN = skey(CT, "eventName", "ConsoleLogin")
SD_ALL = skey(SD, keys.ALL, keys.ALL)


def default_state(ctx):
    cs = source(CS, 5.0, "event_simpleName", "ConfigBuild")
    ct = source(CT, 4.0, "eventName", "eventVersion")
    sd = source(SD, 3.0)
    ctx.state["sources"] = [cs, ct, sd]
    ctx.state["strata"] = {
        cs["_key"]: [stratum(CS, "event_simpleName", "ProcessHandleOpDetectInfo", 330.0), stratum(CS, "event_simpleName", "DmpFileWritten", 180.0),
                     stratum(CS, "event_simpleName", keys.MISSING, 1.0), rows.strata_doc(*CS, keys.ALL, keys.ALL, state="active")],
        ct["_key"]: [stratum(CT, "eventName", "ConsoleLogin", 600.0)],
        sd["_key"]: [rows.strata_doc(*SD, keys.ALL, keys.ALL, state="active")],
    }
    return ctx


def context(**overrides):
    ctx = support.context(**overrides)
    runner.open_run_record(ctx)
    return default_state(ctx)


def run_step(ctx):
    s3_discover.Discover().run(ctx)
    return ctx


def store(ctx, collection, docs):
    ctx.client.kv_batch_save(collection, [dict(d) for d in docs])


def stratum_rows(ctx):
    return dict((r["stratum_key"], r) for r in ctx.summary["stratum"])


def field_rows(ctx, stratum_key):
    return dict((r["field_name"], r) for r in ctx.summary["field"] if r["stratum_key"] == stratum_key)


def staged_field(ctx, key):
    return ctx.kv["matalog_fields"].get(key)


def rollups_of(ctx, ident):
    return [d for d in ctx.kv["matalog_fields"].values() if d.get("is_rollup") == 1 and d.get("source_key") == keys.source_key(*ident)]


def searches(ctx):
    return [c[1] for c in ctx.client.calls if c[0] == "search"]


def fs(field, count, values=(), distinct=None, numeric_count=0, **extra):
    """One fieldsummary result row."""
    row = {"field": field, "count": str(count), "distinct_count": str(len(values) if distinct is None else distinct), "is_exact": "1",
           "numeric_count": str(numeric_count), "values": json.dumps([{"value": v, "count": c} for v, c in values])}
    row.update((k, str(v)) for k, v in extra.items())
    return row


def serve(ctx, stratum_value, fs_rows, events, scan_count=None, run_duration=0.01):
    """Serve the discovery of one crowdstrike stratum with the given field rows and matalog_n count."""
    head = [fs("matalog_n", events, [("1", events)])] if events else []
    ctx.client.add_results([r'event_simpleName="%s"' % stratum_value], head + list(fs_rows),
                           scan_count=events if scan_count is None else scan_count, run_duration=run_duration)


def field_doc(ident, field, value, name, **values):
    doc = {"_key": fkey(ident, field, value, name), "source_key": keys.source_key(*ident), "stratum_key": skey(ident, field, value),
           "field_name": name, "level": "source" if value == keys.ALL else "stratum"}
    doc.update(values)
    return doc


class Planning(unittest.TestCase):
    def test_due_strata_are_planned_first_then_by_source_priority_and_rate(self):
        ctx = context()
        store(ctx, "matalog_strata", [{"_key": PHODI, "discovery_due_run": NEXT_RUN_ID}, {"_key": DMP, "discovery_due_run": RUN_ID},
                                      {"_key": MISSING, "discovery_due_run": PREVIOUS_RUN_ID}, {"_key": LOGIN, "discovery_due_run": NEXT_RUN_ID}])
        run_step(ctx)
        self.assertEqual(ctx.state["planned"], [DMP, MISSING, SD_ALL, PHODI, LOGIN])

    def test_unplanned_strata_keep_their_due_run_and_are_counted_deferred(self):
        ctx = context(**{"budget.max_searches_per_cycle": 13, "write.write_reserve_min": 10})
        store(ctx, "matalog_strata", [{"_key": PHODI, "discovery_due_run": NEXT_RUN_ID}, {"_key": LOGIN, "discovery_due_run": NEXT_RUN_ID}])
        run_step(ctx)
        self.assertEqual(ctx.state["planned"], [DMP, MISSING, SD_ALL])
        self.assertEqual((ctx.counts["strata_due"], ctx.counts["strata_discovered"], ctx.counts["strata_deferred"]), (3, 3, 2))
        self.assertNotIn(PHODI, ctx.kv["matalog_strata"])
        self.assertNotIn(LOGIN, ctx.kv["matalog_strata"])
        self.assertEqual(ctx.client.kv_get("matalog_strata", PHODI)["discovery_due_run"], NEXT_RUN_ID)
        self.assertEqual(ctx.budget.exhausted, "")

    def test_the_rollup_stratum_of_a_stratified_source_is_never_searched(self):
        ctx = run_step(context())
        self.assertNotIn(skey(CS, keys.ALL, keys.ALL), ctx.state["planned"])
        self.assertEqual(len(ctx.state["planned"]), 5)

    def test_sources_missing_from_the_strata_state_fall_back_to_stored_active_strata(self):
        ctx = context()
        ct_key = keys.source_key(*CT)
        del ctx.state["strata"][ct_key]
        store(ctx, "matalog_strata", [dict(stratum(CT, "eventName", "ConsoleLogin", 1.0)), dict(stratum(CT, "eventName", "Deferred", 1.0), state="deferred"),
                                      dict(stratum(CT, "eventName", "Retired", 1.0), state="retired")])
        run_step(ctx)
        self.assertIn(LOGIN, ctx.state["planned"])
        self.assertNotIn(skey(CT, "eventName", "Deferred"), ctx.state["planned"])
        self.assertNotIn(skey(CT, "eventName", "Retired"), ctx.state["planned"])

    def test_deferred_or_retired_strata_are_never_discovered(self):
        ctx = context()
        cs = ctx.state["strata"][keys.source_key(*CS)]
        cs.append(dict(stratum(CS, "event_simpleName", "ProcessRollup2", 700.0), state="deferred"))
        cs.append(dict(stratum(CS, "event_simpleName", "FileDeleteInfo", 100.0), state="retired"))
        run_step(ctx)
        self.assertIn(PHODI, ctx.state["planned"])
        self.assertNotIn(PR2, ctx.state["planned"])
        self.assertNotIn(skey(CS, "event_simpleName", "FileDeleteInfo"), ctx.state["planned"])
        self.assertEqual(len(ctx.state["planned"]), 5)


class Jobs(unittest.TestCase):
    def test_each_planned_stratum_gets_one_unsampled_job_on_the_discovery_window(self):
        ctx = run_step(context())
        specs = searches(ctx)
        self.assertEqual(len(specs), 5)
        earliest, latest = ctx.windows["discovery"]
        for spec in specs:
            self.assertEqual((spec["earliest"], spec["latest"], spec["sample_ratio"], spec["step"]), (earliest, latest, 1, "S3"))
            self.assertIn("| head 2000 | eval matalog_n=1 | fieldsummary maxvals=100", spec["spl"])
        by_subject = dict((spec["subject_key"], spec["spl"]) for spec in specs)
        self.assertIn('search index="matalog_json" sourcetype="crowdstrike:events:sensor" event_simpleName="DmpFileWritten" | where mvcount(\'event_simpleName\')=1', by_subject[DMP])
        self.assertIn('NOT event_simpleName=* | head', by_subject[MISSING])
        self.assertIn('search index="_internal" sourcetype="splunkd" | head', by_subject[SD_ALL])

    def test_the_search_sourcetype_is_searched_when_a_rename_is_known(self):
        ctx = context()
        ctx.state["sources"][2] = rows.sources_doc("_internal", "splunkd_old", state="active", priority=3.0, stratum_field=keys.ALL, search_sourcetype="splunkd")
        ctx.state["strata"][keys.source_key("_internal", "splunkd_old")] = []
        run_step(ctx)
        spl = dict((s["subject_key"], s["spl"]) for s in searches(ctx))[skey(("_internal", "splunkd_old"), keys.ALL, keys.ALL)]
        self.assertIn('sourcetype="splunkd" |', spl)
        self.assertEqual(stratum_rows(ctx)[skey(("_internal", "splunkd_old"), keys.ALL, keys.ALL)]["src_sourcetype"], "splunkd_old")

    def test_search_cost_rows_come_from_the_pool_one_per_job(self):
        ctx = run_step(context())
        costs = [r for r in ctx.summary["search_cost"] if r["step"] == "S3"]
        self.assertEqual(sorted(r["subject_key"] for r in costs), sorted(ctx.state["planned"]))
        self.assertEqual(ctx.budget.per_step["S3"]["searches"], 5)

    def test_a_failed_job_defers_its_stratum_with_an_error_and_no_rows(self):
        ctx = context()
        ctx.client.add_search([r'event_simpleName="DmpFileWritten"'], lambda spec: client_mod.JobResult(status="failed", messages=[{"type": "ERROR", "text": "boom"}], spl=spec["spl"]))
        run_step(ctx)
        self.assertNotIn(DMP, stratum_rows(ctx))
        self.assertNotIn(DMP, ctx.kv["matalog_strata"])
        self.assertEqual([e["subject"] for e in ctx.errors], [DMP])
        self.assertEqual((ctx.counts["strata_due"], ctx.counts["strata_discovered"], ctx.counts["strata_deferred"]), (5, 4, 1))

    def test_a_budget_ceiling_defers_the_rest_without_failing_the_step(self):
        ctx = context(**{"budget.max_events_scanned_per_cycle": 50, "budget.max_concurrent_searches": 1})
        run_step(ctx)
        self.assertEqual(ctx.budget.exhausted, "scanned")
        self.assertEqual(ctx.counts["strata_discovered"], 1)
        self.assertEqual(ctx.counts["strata_deferred"], 4)
        self.assertEqual(ctx.errors, [])


class StratumRows(unittest.TestCase):
    def test_the_discovery_row_carries_counts_scan_ratio_truncation_and_version_top(self):
        ctx = context()
        ctx.state["strata"][keys.source_key(*CS)].append(stratum(CS, "event_simpleName", "ProcessRollup2", 700.0))
        run_step(ctx)
        row = stratum_rows(ctx)[PHODI]
        self.assertEqual((row["mode"], row["events_seen"], row["events_scanned"], row["scan_ratio"], row["truncated"], row["fields_truncated"]), ("discovery", 63, 63, 1.0, 0, 0))
        self.assertEqual((row["fields_found"], row["sample_ratio"], row["prunable"]), (42, 1, 1))
        self.assertEqual((row["version_top"], row["version_top_counts"]), ([BUILD], ["63"]))
        self.assertEqual((row["earliest"], row["latest"]), (float(ctx.windows["discovery"][0]), float(ctx.windows["discovery"][1])))
        self.assertEqual(row["sid"], ctx.state["discovered"][PHODI]["sid"])
        truncated = stratum_rows(ctx)[PR2]
        self.assertEqual((truncated["events_seen"], truncated["events_scanned"], truncated["scan_ratio"], truncated["truncated"]), (2000, 3000, 1.5, 1))

    def test_an_empty_stratum_writes_a_zero_event_row_and_no_field_rows(self):
        ctx = run_step(context())
        row = stratum_rows(ctx)[MISSING]
        self.assertEqual((row["events_seen"], row["events_scanned"], row["scan_ratio"], row["fields_found"], row["prunable"]), (0, 276, 276.0, 0, 0))
        self.assertEqual(field_rows(ctx, MISSING), {})
        self.assertEqual(ctx.counts["scan_ratio_max"], 276.0)

    def test_fields_over_the_cap_are_counted_and_not_stored(self):
        ctx = context(**{"discovery.max_fields_per_stratum": 10})
        run_step(ctx)
        row = stratum_rows(ctx)[PHODI]
        self.assertEqual((row["fields_found"], row["fields_truncated"]), (42, 1))
        self.assertEqual(len(field_rows(ctx, PHODI)), 10)
        self.assertEqual(ctx.state["discovered"][PHODI]["fields_over_cap"], 32)

    def test_strata_docs_get_the_snapshot_due_run_and_field_count(self):
        ctx = run_step(context())
        doc = ctx.kv["matalog_strata"][PHODI]
        self.assertEqual((doc["last_discovered_run"], doc["discovery_due_run"], doc["cur_run_id"]), (RUN_ID, "20261014T1400Z", RUN_ID))
        self.assertEqual((doc["cur_events_seen"], doc["cur_events_scanned"], doc["cur_scan_ratio"], doc["cur_fields_found"], doc["cur_truncated"], doc["cur_fields_truncated"]), (63, 63, 1.0, 42, 0, 0))
        self.assertEqual((doc["field_count"], doc["version_top"], doc["version_top_counts"]), (42, [BUILD], ["63"]))
        self.assertNotIn("version_changed_run", doc)
        self.assertEqual(ctx.kv["matalog_strata"][MISSING]["field_count"], 0)

    def test_version_changed_run_is_set_only_when_a_value_enters_a_known_version_top(self):
        ctx = context()
        store(ctx, "matalog_strata", [{"_key": PHODI, "version_top": ["1006.0.1"], "version_top_counts": ["5"]}, {"_key": DMP, "version_top": [BUILD], "version_top_counts": ["3"]}])
        store(ctx, "matalog_sources", [{"_key": keys.source_key(*CS), "version_top": ["1006.0.1"], "version_top_counts": ["5"]},
                                       {"_key": keys.source_key(*CT), "version_top": [], "version_top_counts": []}])
        run_step(ctx)
        self.assertEqual(ctx.kv["matalog_strata"][PHODI]["version_changed_run"], RUN_ID)
        self.assertNotIn("version_changed_run", ctx.kv["matalog_strata"][DMP])
        self.assertEqual(ctx.kv["matalog_sources"][keys.source_key(*CS)]["version_changed_run"], RUN_ID)
        self.assertNotIn("version_changed_run", ctx.kv["matalog_sources"][keys.source_key(*CT)])


class FieldRows(unittest.TestCase):
    def test_a_field_new_this_run_gets_a_full_row_and_a_known_field_a_slim_one(self):
        ctx = context()
        store(ctx, "matalog_fields", [{"_key": fkey(CS, "event_simpleName", "DmpFileWritten", "ConfigBuild"), "source_key": keys.source_key(*CS), "stratum_key": DMP,
                                       "field_name": "ConfigBuild", "level": "stratum", "first_seen_run": PREVIOUS_RUN_ID, "origin": "json_auto", "origin_app": "TA-cs"}])
        run_step(ctx)
        new = field_rows(ctx, PHODI)["ConfigBuild"]
        known = field_rows(ctx, DMP)["ConfigBuild"]
        self.assertEqual((new["shape"], new["mode"], new["sample_values"], new["top_values"], new["top_counts"]), ("full", "discovery", [BUILD], [BUILD], ["63"]))
        self.assertIsNone(new["origin"])
        self.assertEqual(known["shape"], "slim")
        self.assertNotIn("sample_values", known)
        self.assertEqual(ctx.counts["fields_new"], 42 + 51 + 48 + 124 - 1)
        self.assertEqual(ctx.counts["fields_present"], len([d for d in ctx.kv["matalog_fields"].values() if d.get("presence") == "present"]))

    def test_a_full_row_for_a_declared_field_carries_its_stored_origin(self):
        ctx = context()
        key = fkey(SD, keys.ALL, keys.ALL, "component")
        store(ctx, "matalog_fields", [{"_key": key, "source_key": keys.source_key(*SD), "stratum_key": SD_ALL, "field_name": "component", "level": "source",
                                       "presence": "declared_only", "observed": 0, "declared": 1, "origin": "regex_extract", "origin_app": "system"}])
        run_step(ctx)
        row = field_rows(ctx, SD_ALL)["component"]
        self.assertEqual((row["shape"], row["origin"], row["origin_app"]), ("full", "regex_extract", "system"))
        doc = staged_field(ctx, key)
        self.assertEqual((doc["presence"], doc["observed"], doc["first_seen_run"], doc["consecutive_unseen"]), ("present", 1, RUN_ID, 0))

    def test_field_docs_carry_the_discovery_snapshot_identity_and_values(self):
        ctx = run_step(context())
        key = fkey(CS, "event_simpleName", "ProcessHandleOpDetectInfo", "event_simpleName")
        doc = staged_field(ctx, key)
        row = field_rows(ctx, PHODI)["event_simpleName"]
        self.assertEqual((doc["level"], doc["is_stratum_field"], doc["is_rollup"], doc["rollup_strata"], doc["presence"], doc["observed"]), ("stratum", 1, 0, 0, "present", 1))
        self.assertEqual((doc["cur_disc_run_id"], doc["cur_disc_count"], doc["cur_disc_events"], doc["cur_disc_coverage"], doc["cur_disc_distinct"]), (RUN_ID, 63, 63, 1.0, 1))
        self.assertEqual((doc["first_seen_run"], doc["last_seen_run"], doc["last_seen_time"], doc["consecutive_unseen"]), (RUN_ID, RUN_ID, float(ctx.windows["discovery"][1]), 0))
        self.assertEqual((doc["type_guess"], doc["identifier"], doc["values_hash"], doc["profile_id"]), (row["type_guess"], row["identifier"], row["values_hash"], row["profile_id"]))
        self.assertEqual((doc["top_values"], doc["sample_values"], doc["numeric_count"]), (["ProcessHandleOpDetectInfo"], ["ProcessHandleOpDetectInfo"], 0))
        self.assertEqual(doc["stratum_label"], "event_simpleName=ProcessHandleOpDetectInfo")
        numeric = staged_field(ctx, fkey(CS, "event_simpleName", "ProcessHandleOpDetectInfo", "date_hour"))
        self.assertGreater(numeric["numeric_count"], 0)
        self.assertIsNotNone(numeric["num_mean"])


class Absence(unittest.TestCase):
    def ghost_docs(self):
        return [
            {"_key": fkey(CS, "event_simpleName", "ProcessHandleOpDetectInfo", "Ghost"), "source_key": keys.source_key(*CS), "stratum_key": PHODI,
             "field_name": "Ghost", "level": "stratum", "presence": "present", "consecutive_unseen": 0, "first_seen_run": PREVIOUS_RUN_ID},
            {"_key": fkey(CS, "event_simpleName", "ProcessHandleOpDetectInfo", "Gone"), "source_key": keys.source_key(*CS), "stratum_key": PHODI,
             "field_name": "Gone", "level": "stratum", "presence": "unobserved", "consecutive_unseen": 2, "first_seen_run": PREVIOUS_RUN_ID},
            {"_key": fkey(CS, "event_simpleName", "ProcessHandleOpDetectInfo", "Old"), "source_key": keys.source_key(*CS), "stratum_key": PHODI,
             "field_name": "Old", "level": "stratum", "presence": "retired", "consecutive_unseen": 1, "first_seen_run": PREVIOUS_RUN_ID},
        ]

    def test_a_field_missing_from_a_qualifying_discovery_is_unobserved_with_consecutive_unseen_up(self):
        ctx = context(**{"discovery.min_events_for_absence": 50})
        store(ctx, "matalog_fields", self.ghost_docs())
        run_step(ctx)
        ghost = staged_field(ctx, fkey(CS, "event_simpleName", "ProcessHandleOpDetectInfo", "Ghost"))
        gone = staged_field(ctx, fkey(CS, "event_simpleName", "ProcessHandleOpDetectInfo", "Gone"))
        self.assertEqual((ghost["presence"], ghost["consecutive_unseen"]), ("unobserved", 1))
        self.assertEqual(gone["consecutive_unseen"], 3)
        self.assertNotIn("presence", gone)
        self.assertIsNone(staged_field(ctx, fkey(CS, "event_simpleName", "ProcessHandleOpDetectInfo", "Old")))

    def test_absence_is_not_judged_below_min_events_or_after_field_truncation(self):
        ctx = context()
        store(ctx, "matalog_fields", self.ghost_docs())
        run_step(ctx)
        self.assertIsNone(staged_field(ctx, fkey(CS, "event_simpleName", "ProcessHandleOpDetectInfo", "Ghost")))
        ctx = context(**{"discovery.min_events_for_absence": 50, "discovery.max_fields_per_stratum": 10})
        store(ctx, "matalog_fields", self.ghost_docs())
        run_step(ctx)
        self.assertIsNone(staged_field(ctx, fkey(CS, "event_simpleName", "ProcessHandleOpDetectInfo", "Ghost")))

    def test_an_observed_field_resets_consecutive_unseen_and_is_present_again(self):
        ctx = context()
        key = fkey(CS, "event_simpleName", "ProcessHandleOpDetectInfo", "ConfigBuild")
        store(ctx, "matalog_fields", [{"_key": key, "presence": "unobserved", "consecutive_unseen": 3, "first_seen_run": PREVIOUS_RUN_ID, "source_key": keys.source_key(*CS), "stratum_key": PHODI, "field_name": "ConfigBuild", "level": "stratum"}])
        run_step(ctx)
        doc = staged_field(ctx, key)
        self.assertEqual((doc["presence"], doc["consecutive_unseen"], doc["observed"]), ("present", 0, 1))
        self.assertEqual(ctx.after_roll("matalog_fields", key)["first_seen_run"], PREVIOUS_RUN_ID)

    def test_a_declared_only_source_row_counts_unseen_qualifying_discoveries(self):
        ctx = context(**{"discovery.min_events_for_absence": 50})
        unseen = fkey(CS, keys.ALL, keys.ALL, "NeverExtracted")
        seen = fkey(CS, keys.ALL, keys.ALL, "ConfigBuild")
        store(ctx, "matalog_fields", [
            {"_key": unseen, "source_key": keys.source_key(*CS), "field_name": "NeverExtracted", "level": "source", "presence": "declared_only", "declared": 1, "observed": 0, "consecutive_unseen": 2},
            {"_key": seen, "source_key": keys.source_key(*CS), "field_name": "ConfigBuild", "level": "source", "presence": "declared_only", "declared": 1, "observed": 0, "consecutive_unseen": 2}])
        run_step(ctx)
        self.assertEqual(staged_field(ctx, unseen)["consecutive_unseen"], 3)
        self.assertNotIn("presence", staged_field(ctx, unseen))
        self.assertEqual(staged_field(ctx, seen)["presence"], "present")


class Rollups(unittest.TestCase):
    def test_rollup_rows_sum_children_and_count_the_strata_included(self):
        ctx = run_step(context())
        doc = staged_field(ctx, fkey(CS, keys.ALL, keys.ALL, "ConfigBuild"))
        self.assertEqual((doc["level"], doc["is_rollup"], doc["rollup_strata"], doc["presence"], doc["observed"]), ("source", 1, 2, "present", 1))
        self.assertEqual((doc["cur_disc_run_id"], doc["cur_disc_count"], doc["cur_disc_events"], doc["cur_disc_coverage"], doc["cur_disc_distinct"]), (RUN_ID, 108, 108, 1.0, 1))
        self.assertEqual((doc["top_values"], doc["top_counts"], doc["sample_values"], doc["type_guess"], doc["identifier"]), ([BUILD], ["108"], [BUILD], "string", 0))
        self.assertEqual((doc["first_seen_run"], doc["last_seen_run"], doc["consecutive_unseen"], doc["is_stratum_field"]), (RUN_ID, RUN_ID, 0, 0))
        self.assertEqual(doc["values_hash"], rows.values_hash([BUILD]))
        stratum_field = staged_field(ctx, fkey(CS, keys.ALL, keys.ALL, "event_simpleName"))
        self.assertEqual((stratum_field["is_stratum_field"], stratum_field["cur_disc_distinct"], stratum_field["top_values"]), (1, 1, ["ProcessHandleOpDetectInfo", "DmpFileWritten"]))
        only_in_dmp = [n for n in field_rows(ctx, DMP) if n not in field_rows(ctx, PHODI)][0]
        self.assertEqual(staged_field(ctx, fkey(CS, keys.ALL, keys.ALL, only_in_dmp))["rollup_strata"], 1)
        self.assertEqual(len(rollups_of(ctx, CS)), len(set(field_rows(ctx, DMP)) | set(field_rows(ctx, PHODI))))

    def test_rollups_include_stored_children_of_active_strata_not_discovered_this_run_and_skip_the_rest(self):
        ctx = context(**{"budget.max_searches_per_cycle": 13, "write.write_reserve_min": 10})
        cs = ctx.state["strata"][keys.source_key(*CS)]
        cs.append(stratum(CS, "event_simpleName", "ProcessRollup2", 700.0))
        cs.append(dict(stratum(CS, "event_simpleName", "FileDeleteInfo", 100.0), state="retired"))
        store(ctx, "matalog_strata", [{"_key": PR2, "discovery_due_run": NEXT_RUN_ID, "last_discovered_run": PREVIOUS_RUN_ID}, {"_key": LOGIN, "discovery_due_run": NEXT_RUN_ID}])
        child = {"source_key": keys.source_key(*CS), "field_name": "ConfigBuild", "level": "stratum", "presence": "present", "observed": 1,
                 "cur_disc_run_id": PREVIOUS_RUN_ID, "cur_disc_count": 10, "cur_disc_events": 100, "cur_disc_coverage": 0.1, "cur_disc_distinct": 2,
                 "top_values": ["old"], "top_counts": ["10"], "sample_values": ["old"], "type_guess": "string", "identifier": 0, "first_seen_run": "20261013T1100Z", "last_seen_run": PREVIOUS_RUN_ID}
        store(ctx, "matalog_fields", [dict(child, _key=fkey(CS, "event_simpleName", "ProcessRollup2", "ConfigBuild"), stratum_key=PR2),
                                      dict(child, _key=fkey(CS, "event_simpleName", "FileDeleteInfo", "ConfigBuild"), stratum_key=skey(CS, "event_simpleName", "FileDeleteInfo"))])
        run_step(ctx)
        self.assertEqual(ctx.state["planned"], [PHODI, DMP, MISSING])
        doc = staged_field(ctx, fkey(CS, keys.ALL, keys.ALL, "ConfigBuild"))
        self.assertEqual((doc["rollup_strata"], doc["cur_disc_count"], doc["cur_disc_events"], doc["cur_disc_distinct"]), (3, 118, 208, 2))
        self.assertEqual((doc["top_values"], doc["top_counts"], doc["sample_values"]), ([BUILD, "old"], ["108", "10"], [BUILD, "old"]))
        self.assertEqual((doc["first_seen_run"], doc["last_seen_run"]), ("20261013T1100Z", RUN_ID))

    def test_a_rollup_whose_children_all_went_unobserved_becomes_unobserved(self):
        ctx = context(**{"discovery.min_events_for_absence": 50})
        rollup = fkey(CS, keys.ALL, keys.ALL, "Ghost")
        store(ctx, "matalog_fields", [
            {"_key": fkey(CS, "event_simpleName", "ProcessHandleOpDetectInfo", "Ghost"), "source_key": keys.source_key(*CS), "stratum_key": PHODI, "field_name": "Ghost", "level": "stratum", "presence": "present", "cur_disc_run_id": PREVIOUS_RUN_ID, "cur_disc_count": 5, "cur_disc_events": 50},
            {"_key": rollup, "source_key": keys.source_key(*CS), "field_name": "Ghost", "level": "source", "is_rollup": 1, "rollup_strata": 1, "presence": "present", "cur_disc_run_id": PREVIOUS_RUN_ID, "cur_disc_count": 5, "cur_disc_events": 50}])
        run_step(ctx)
        doc = staged_field(ctx, rollup)
        self.assertEqual((doc["presence"], doc["rollup_strata"]), ("unobserved", 0))
        self.assertNotIn("cur_disc_count", doc)

    def test_an_unstratified_source_writes_measured_source_rows_not_rollups(self):
        ctx = run_step(context())
        doc = staged_field(ctx, fkey(SD, keys.ALL, keys.ALL, "component"))
        self.assertEqual((doc["level"], doc["is_rollup"], doc["rollup_strata"], doc["stratum_key"], doc["presence"]), ("source", 0, 0, SD_ALL, "present"))
        self.assertEqual(stratum_rows(ctx)[SD_ALL]["stratum_value"], keys.ALL)
        self.assertEqual(ctx.kv["matalog_strata"][SD_ALL]["level"], "source")
        self.assertEqual(ctx.kv["matalog_sources"][keys.source_key(*SD)]["field_count"], 124)


class SourceDocs(unittest.TestCase):
    def test_source_docs_get_last_discovered_run_field_count_and_merged_version_top(self):
        ctx = run_step(context())
        cs = ctx.kv["matalog_sources"][keys.source_key(*CS)]
        self.assertEqual((cs["last_discovered_run"], cs["version_top"], cs["version_top_counts"]), (RUN_ID, [BUILD], ["108"]))
        self.assertEqual(cs["field_count"], len(rollups_of(ctx, CS)))
        self.assertEqual(ctx.kv["matalog_sources"][keys.source_key(*CT)]["field_count"], len(rollups_of(ctx, CT)))
        ct = ctx.kv["matalog_sources"][keys.source_key(*CT)]
        self.assertEqual((ct["last_discovered_run"], ct["version_top"], ct["version_top_counts"]), (RUN_ID, ["1.08"], ["10"]))

    def test_last_discovered_run_waits_until_every_active_stratum_has_a_discovery(self):
        ctx = context(**{"budget.max_searches_per_cycle": 13, "write.write_reserve_min": 10})
        ctx.state["strata"][keys.source_key(*CS)].append(stratum(CS, "event_simpleName", "ProcessRollup2", 700.0))
        store(ctx, "matalog_strata", [{"_key": PR2, "discovery_due_run": NEXT_RUN_ID}, {"_key": LOGIN, "discovery_due_run": NEXT_RUN_ID}])
        run_step(ctx)
        self.assertNotIn("last_discovered_run", ctx.kv["matalog_sources"][keys.source_key(*CS)])
        self.assertNotIn(keys.source_key(*CT), ctx.kv["matalog_sources"])
        ctx = context(**{"budget.max_searches_per_cycle": 13, "write.write_reserve_min": 10})
        ctx.state["strata"][keys.source_key(*CS)].append(stratum(CS, "event_simpleName", "ProcessRollup2", 700.0))
        store(ctx, "matalog_strata", [{"_key": PR2, "discovery_due_run": NEXT_RUN_ID, "last_discovered_run": PREVIOUS_RUN_ID}, {"_key": LOGIN, "discovery_due_run": NEXT_RUN_ID}])
        run_step(ctx)
        self.assertEqual(ctx.kv["matalog_sources"][keys.source_key(*CS)]["last_discovered_run"], RUN_ID)


class Counts(unittest.TestCase):
    def test_counts_cover_due_discovered_deferred_fields_and_scan_ratio_max(self):
        ctx = run_step(context())
        self.assertEqual((ctx.counts["strata_due"], ctx.counts["strata_discovered"], ctx.counts["strata_deferred"]), (5, 5, 0))
        self.assertEqual(ctx.counts["fields_present"], len([d for d in ctx.kv["matalog_fields"].values() if d.get("presence") == "present"]))
        self.assertEqual(ctx.counts["fields_new"], len([r for r in ctx.summary["field"] if r["shape"] == "full"]))
        self.assertEqual(ctx.counts["scan_ratio_max"], 276.0)

    def test_nothing_to_plan_leaves_zero_counts_and_no_jobs(self):
        ctx = support.context()
        ctx.state["sources"] = []
        run_step(ctx)
        self.assertEqual((ctx.counts["strata_due"], ctx.counts["strata_discovered"], ctx.counts["fields_present"], ctx.counts["scan_ratio_max"]), (0, 0, 0, 0.0))
        self.assertEqual(searches(ctx), [])


class TwoRuns(unittest.TestCase):
    def pipeline(self):
        steps = []
        for name in runner.STEP_ORDER:
            if name == "S3":
                steps.append(s3_discover.Discover())
                continue
            step = runner.Step()
            step.name, step.label, step.required = name, name.lower(), name in ("S1", "S10")
            step.run = {"S1": lambda ctx: default_state(ctx), "S10": runner.commit}.get(name, lambda ctx: None)
            steps.append(step)
        return steps

    def test_the_second_run_writes_slim_rows_and_rolls_the_first_snapshot_into_base(self):
        client = fake_client.FakeClient()
        s = support.settings()
        client.settings = s
        first = runner.run_once(s, client, now=support.SLOT + 5, steps=self.pipeline())
        self.assertEqual((first["status"], first["committed"], first["strata_discovered"], first["budget_exhausted"]), ("ok", 1, 5, ""))
        self.assertGreater(first["rows_written"]["field"], 0)
        self.assertEqual(first["rows_written"]["stratum"], 5)
        second = runner.run_once(s, client, now=support.SLOT + 3600, steps=self.pipeline())
        self.assertEqual((second["status"], second["fields_new"]), ("ok", 0))
        shapes = set(r["shape"] for r in client.collected_rows() if r["kind"] == "field" and r["run_id"] == NEXT_RUN_ID)
        self.assertEqual(shapes, {"slim"})
        doc = client.kv_get("matalog_fields", fkey(CS, "event_simpleName", "ProcessHandleOpDetectInfo", "ConfigBuild"))
        self.assertEqual((doc["cur_disc_run_id"], doc["base_disc_run_id"], doc["first_seen_run"], doc["last_seen_run"]), (NEXT_RUN_ID, RUN_ID, RUN_ID, NEXT_RUN_ID))
        self.assertEqual(doc["sample_values"], [BUILD])
        stratum_doc = client.kv_get("matalog_strata", PHODI)
        self.assertEqual((stratum_doc["cur_run_id"], stratum_doc["base_run_id"], stratum_doc["discovery_due_run"]), (NEXT_RUN_ID, RUN_ID, "20261014T1500Z"))
        rollup = client.kv_get("matalog_fields", fkey(CS, keys.ALL, keys.ALL, "ConfigBuild"))
        self.assertEqual((rollup["cur_disc_run_id"], rollup["base_disc_run_id"], rollup["rollup_strata"]), (NEXT_RUN_ID, RUN_ID, 2))


class PlanningSignals(unittest.TestCase):
    def test_due_strata_cut_by_the_search_budget_are_recorded_as_an_error_without_exhausting_the_budget(self):
        ctx = context(**{"budget.max_searches_per_cycle": 12, "write.write_reserve_min": 10})
        run_step(ctx)
        self.assertEqual(len(ctx.state["planned"]), 2)
        self.assertEqual([(e["step"], e["subject"]) for e in ctx.errors], [("S3", "plan")])
        self.assertIn("3 due strata not planned", ctx.errors[0]["message"])
        self.assertEqual(ctx.budget.exhausted, "")

    def test_strata_state_as_a_flat_list_plans_the_same_strata(self):
        ctx = context()
        ctx.state["strata"] = [d for docs in ctx.state["strata"].values() for d in docs]
        run_step(ctx)
        self.assertEqual(len(ctx.state["planned"]), 5)
        self.assertIn(PHODI, ctx.state["planned"])

    def test_strata_state_as_a_dict_of_docs_per_source_plans_the_same_strata(self):
        ctx = context()
        ctx.state["strata"] = dict((k, dict((d["_key"], d) for d in docs)) for k, docs in ctx.state["strata"].items())
        run_step(ctx)
        self.assertEqual(len(ctx.state["planned"]), 5)
        self.assertIn(LOGIN, ctx.state["planned"])


class JobOutcomes(unittest.TestCase):
    def test_a_timed_out_job_is_not_a_discovery_and_its_error_names_the_status(self):
        ctx = context()
        ctx.client.add_search([r'event_simpleName="DmpFileWritten"'], lambda spec: client_mod.JobResult(status="timeout", messages=[], spl=spec["spl"]))
        run_step(ctx)
        self.assertNotIn(DMP, stratum_rows(ctx))
        self.assertNotIn(DMP, ctx.state["discovered"])
        self.assertEqual([(e["subject"], e["message"]) for e in ctx.errors], [(DMP, "discovery timeout with no message")])

    def test_a_field_name_that_fails_identity_is_skipped_with_an_error(self):
        ctx = context()
        serve(ctx, "ProcessHandleOpDetectInfo", [fs("*", 60, [("x", 60)]), fs("Good", 60, [("y", 60)])], 60)
        run_step(ctx)
        self.assertEqual(sorted(field_rows(ctx, PHODI)), ["Good"])
        self.assertEqual([e["subject"] for e in ctx.errors], [PHODI])
        self.assertIn("field skipped", ctx.errors[0]["message"])

    def test_the_search_seconds_ceiling_defers_the_remaining_strata(self):
        ctx = context(**{"budget.max_search_seconds_per_cycle": 1, "budget.max_concurrent_searches": 1})
        serve(ctx, "ProcessHandleOpDetectInfo", [fs("A", 60, [("x", 60)])], 60, run_duration=5.0)
        run_step(ctx)
        self.assertEqual(list(ctx.state["discovered"]), [PHODI])
        self.assertEqual((ctx.budget.exhausted, ctx.counts["strata_discovered"], ctx.counts["strata_deferred"]), ("search_seconds", 1, 4))

    def test_the_wall_seconds_ceiling_defers_every_stratum(self):
        ctx = context(**{"budget.max_wall_seconds_per_cycle": 0})
        run_step(ctx)
        self.assertEqual((ctx.budget.exhausted, ctx.counts["strata_discovered"], ctx.counts["strata_deferred"]), ("wall_seconds", 0, 5))
        self.assertEqual(ctx.summary["stratum"], [])

    def test_the_searches_ceiling_hit_during_dispatch_defers_the_remaining_strata(self):
        ctx = context(**{"budget.max_concurrent_searches": 1})
        fixture = fake_client.load_fixture("s3_fieldsummary_crowdstrike_DmpFileWritten")

        def other_jobs(spec):
            ctx.budget.searches_issued += 10000
            return client_mod.JobResult(status="ok", results=fixture["results"], scan_count=45, spl=spec["spl"])
        ctx.client.add_search([r'event_simpleName="DmpFileWritten"'], other_jobs)
        store(ctx, "matalog_strata", [{"_key": PHODI, "discovery_due_run": NEXT_RUN_ID}, {"_key": MISSING, "discovery_due_run": NEXT_RUN_ID},
                                      {"_key": LOGIN, "discovery_due_run": NEXT_RUN_ID}, {"_key": SD_ALL, "discovery_due_run": NEXT_RUN_ID}])
        run_step(ctx)
        self.assertEqual(ctx.state["planned"][0], DMP)
        self.assertEqual((ctx.budget.exhausted, ctx.counts["strata_discovered"], ctx.counts["strata_deferred"]), ("searches", 1, 4))


class StratumRowLimits(unittest.TestCase):
    def test_long_version_values_are_truncated_and_the_row_fits_max_row_bytes(self):
        ctx = context()
        builds = [("%d" % i + "b" * 900, 10 - i) for i in range(10)]
        serve(ctx, "ProcessHandleOpDetectInfo", [fs("ConfigBuild", 55, builds)], 55)
        run_step(ctx)
        self.assertEqual(len(stratum_rows(ctx)), 5)
        row = stratum_rows(ctx)[PHODI]
        max_chars = ctx.settings.profile.max_value_chars
        self.assertTrue(row["version_top"])
        self.assertTrue(all(len(v) <= max_chars for v in row["version_top"]))
        self.assertEqual(len(row["version_top"]), len(row["version_top_counts"]))
        self.assertLessEqual(rows.row_bytes(row), ctx.settings.profile.max_row_bytes)
        self.assertEqual(ctx.kv["matalog_strata"][PHODI]["version_top"], row["version_top"])
        self.assertTrue(all(len(v) <= max_chars for v in ctx.kv["matalog_sources"][keys.source_key(*CS)]["version_top"]))

    def test_version_top_keeps_the_top_values_most_frequent_builds(self):
        ctx = context(**{"profile.top_values": 2})
        serve(ctx, "ProcessHandleOpDetectInfo", [fs("ConfigBuild", 60, [("b1", 30), ("b2", 20), ("b3", 10)])], 60)
        run_step(ctx)
        row = stratum_rows(ctx)[PHODI]
        self.assertEqual((row["version_top"], row["version_top_counts"]), (["b1", "b2"], ["30", "20"]))

    def test_an_untruncated_stored_build_is_not_taken_for_a_new_one(self):
        ctx = context(**{"profile.max_value_chars": 8})
        store(ctx, "matalog_strata", [{"_key": PHODI, "version_top": [BUILD], "version_top_counts": ["5"]}])
        run_step(ctx)
        self.assertEqual(ctx.kv["matalog_strata"][PHODI]["version_top"], [BUILD[:8]])
        self.assertNotIn("version_changed_run", ctx.kv["matalog_strata"][PHODI])

    def test_a_discovery_without_a_version_value_keeps_the_stored_version_top(self):
        ctx = context()
        store(ctx, "matalog_strata", [{"_key": PHODI, "version_top": [BUILD], "version_top_counts": ["9"]}])
        serve(ctx, "ProcessHandleOpDetectInfo", [], 0, scan_count=100)
        run_step(ctx)
        self.assertNotIn("version_top", ctx.kv["matalog_strata"][PHODI])
        self.assertEqual(ctx.after_roll("matalog_strata", PHODI)["version_top"], [BUILD])

    def test_a_source_whose_discoveries_carry_no_version_keeps_its_stored_version_top(self):
        ctx = context()
        cs_key = keys.source_key(*CS)
        store(ctx, "matalog_sources", [{"_key": cs_key, "version_top": [BUILD], "version_top_counts": ["9"]}])
        serve(ctx, "ProcessHandleOpDetectInfo", [fs("Other", 60, [("x", 60)])], 60)
        serve(ctx, "DmpFileWritten", [fs("Other", 60, [("x", 60)])], 60)
        run_step(ctx)
        self.assertNotIn("version_top", ctx.kv["matalog_sources"][cs_key])
        self.assertEqual(ctx.after_roll("matalog_sources", cs_key)["version_top"], [BUILD])

    def test_the_discovery_row_records_the_job_run_duration(self):
        ctx = context()
        serve(ctx, "ProcessHandleOpDetectInfo", [fs("A", 60, [("x", 60)])], 60, run_duration=2.5)
        run_step(ctx)
        self.assertEqual(stratum_rows(ctx)[PHODI]["search_seconds"], 2.5)

    def test_fields_over_the_cap_keep_the_most_frequent_then_by_name(self):
        ctx = context(**{"discovery.max_fields_per_stratum": 3})
        serve(ctx, "ProcessHandleOpDetectInfo", [fs("low", 5, [("x", 5)]), fs("b", 60, [("x", 60)]), fs("a", 60, [("x", 60)]),
                                                 fs("mid", 30, [("x", 30)]), fs("c", 10, [("x", 10)])], 60)
        run_step(ctx)
        self.assertEqual(sorted(field_rows(ctx, PHODI)), ["a", "b", "mid"])


class S2Staging(unittest.TestCase):
    def test_a_rollup_whose_only_child_was_deleted_this_run_becomes_unobserved_and_leaves_field_count(self):
        ctx = context()
        cs = ctx.state["strata"][keys.source_key(*CS)]
        cs.append(dict(stratum(CS, "event_simpleName", "ProcessRollup2", 700.0), state="deferred"))
        child = field_doc(CS, "event_simpleName", "ProcessRollup2", "OnlyPR2", presence="present", cur_disc_run_id=PREVIOUS_RUN_ID, cur_disc_count=5, cur_disc_events=5)
        rollup = field_doc(CS, keys.ALL, keys.ALL, "OnlyPR2", is_rollup=1, rollup_strata=1, presence="present", cur_disc_run_id=PREVIOUS_RUN_ID)
        store(ctx, "matalog_fields", [child, rollup])
        ctx.delete_kv("matalog_fields", child["_key"])
        run_step(ctx)
        doc = staged_field(ctx, rollup["_key"])
        self.assertEqual((doc["presence"], doc["rollup_strata"]), ("unobserved", 0))
        present = [d for d in rollups_of(ctx, CS) if d.get("presence") == "present"]
        self.assertEqual(ctx.kv["matalog_sources"][keys.source_key(*CS)]["field_count"], len(present))

    def test_a_rollup_that_lost_a_child_outside_the_discovered_strata_is_recomputed(self):
        ctx = context()
        cs = ctx.state["strata"][keys.source_key(*CS)]
        cs.append(dict(stratum(CS, "event_simpleName", "ProcessRollup2", 700.0), state="deferred"))
        child = field_doc(CS, "event_simpleName", "ProcessRollup2", "OnlyPR2", presence="present", cur_disc_run_id=PREVIOUS_RUN_ID, cur_disc_count=5, cur_disc_events=5)
        rollup = field_doc(CS, keys.ALL, keys.ALL, "OnlyPR2", is_rollup=1, rollup_strata=1, presence="present", cur_disc_run_id=PREVIOUS_RUN_ID)
        store(ctx, "matalog_fields", [child, rollup])
        run_step(ctx)
        self.assertEqual(staged_field(ctx, rollup["_key"])["presence"], "unobserved")

    def test_a_rollup_over_profiled_children_without_a_discovery_is_left_to_the_profile_step(self):
        ctx = context()
        child = field_doc(CS, "event_simpleName", "DmpFileWritten", "ProfiledOnly", presence="present", cur_prof_run_id=PREVIOUS_RUN_ID, cur_prof_count=5)
        rollup = field_doc(CS, keys.ALL, keys.ALL, "ProfiledOnly", is_rollup=1, rollup_strata=1, presence="present", cur_prof_run_id=PREVIOUS_RUN_ID)
        store(ctx, "matalog_fields", [child, rollup])
        run_step(ctx)
        self.assertIsNone(staged_field(ctx, rollup["_key"]))

    def test_absence_counts_on_a_reactivated_stratum_whose_fields_were_restaged_unobserved(self):
        ctx = context(**{"discovery.min_events_for_absence": 50})
        key = fkey(CS, "event_simpleName", "ProcessHandleOpDetectInfo", "Ghost")
        store(ctx, "matalog_fields", [field_doc(CS, "event_simpleName", "ProcessHandleOpDetectInfo", "Ghost", presence="retired", consecutive_unseen=1, first_seen_run=PREVIOUS_RUN_ID)])
        ctx.stage_kv("matalog_fields", rows.kv_doc("matalog_fields", key, presence="unobserved", retired_run=None))
        run_step(ctx)
        doc = staged_field(ctx, key)
        self.assertEqual((doc["presence"], doc["consecutive_unseen"]), ("unobserved", 2))

    def test_a_field_deleted_this_run_is_not_judged_absent(self):
        ctx = context(**{"discovery.min_events_for_absence": 50})
        key = fkey(CS, "event_simpleName", "ProcessHandleOpDetectInfo", "Ghost")
        store(ctx, "matalog_fields", [field_doc(CS, "event_simpleName", "ProcessHandleOpDetectInfo", "Ghost", presence="present", consecutive_unseen=0, first_seen_run=PREVIOUS_RUN_ID)])
        ctx.delete_kv("matalog_fields", key)
        run_step(ctx)
        self.assertIsNone(staged_field(ctx, key))
        self.assertIn(key, ctx.kv_deletes["matalog_fields"])


class AbsenceEdges(unittest.TestCase):
    def test_a_discovery_with_exactly_min_events_qualifies_for_absence(self):
        ctx = context(**{"discovery.min_events_for_absence": 63})
        key = fkey(CS, "event_simpleName", "ProcessHandleOpDetectInfo", "Ghost")
        store(ctx, "matalog_fields", [field_doc(CS, "event_simpleName", "ProcessHandleOpDetectInfo", "Ghost", presence="present", consecutive_unseen=0, first_seen_run=PREVIOUS_RUN_ID)])
        run_step(ctx)
        self.assertEqual(staged_field(ctx, key)["consecutive_unseen"], 1)

    def test_a_declared_name_observed_this_run_does_not_count_an_unseen_discovery(self):
        ctx = context(**{"discovery.min_events_for_absence": 50})
        seen = fkey(CS, keys.ALL, keys.ALL, "ConfigBuild")
        store(ctx, "matalog_fields", [field_doc(CS, keys.ALL, keys.ALL, "ConfigBuild", presence="declared_only", declared=1, observed=0, consecutive_unseen=2)])
        run_step(ctx)
        self.assertEqual(ctx.after_roll("matalog_fields", seen)["consecutive_unseen"], 0)

    def test_the_stratum_field_count_leaves_out_unobserved_rows(self):
        ctx = context(**{"discovery.min_events_for_absence": 50})
        store(ctx, "matalog_fields", [field_doc(CS, "event_simpleName", "ProcessHandleOpDetectInfo", "Ghost", presence="present", first_seen_run=PREVIOUS_RUN_ID),
                                      field_doc(CS, "event_simpleName", "ProcessHandleOpDetectInfo", "Gone", presence="unobserved", first_seen_run=PREVIOUS_RUN_ID)])
        run_step(ctx)
        self.assertEqual(ctx.kv["matalog_strata"][PHODI]["field_count"], 42)


class RollupMath(unittest.TestCase):
    def children(self):
        a = {"stratum_key": "a", "cur_disc_count": 10, "cur_disc_events": 100, "cur_disc_distinct": 4, "identifier": 1, "type_guess": "number",
             "numeric_count": 1, "num_min": 5.0, "num_max": 7.0, "num_mean": 6.0, "top_values": ["x"], "top_counts": ["10"], "sample_values": ["x"],
             "first_seen_run": "20261013T1000Z", "last_seen_run": PREVIOUS_RUN_ID, "last_seen_time": 100.0}
        b = {"stratum_key": "b", "cur_disc_count": 30, "cur_disc_events": 300, "cur_disc_distinct": 9, "identifier": 0, "type_guess": "number",
             "numeric_count": 3, "num_min": 1.0, "num_max": 20.0, "num_mean": 10.0, "top_values": ["y", "x"], "top_counts": ["20", "5"], "sample_values": ["y"],
             "first_seen_run": "20261013T1100Z", "last_seen_run": RUN_ID, "last_seen_time": 200.0}
        return a, b

    def rollup(self, children):
        ctx = context()
        src = rows.sources_doc(*CS, stratum_field="event_simpleName")
        return s3_discover.rollup_values(ctx, src, "n", list(children))

    def test_rollup_numbers_are_weighted_and_bounded_over_children(self):
        values = self.rollup(self.children())
        self.assertEqual((values["num_min"], values["num_max"], values["num_mean"], values["numeric_count"]), (1.0, 20.0, 9.0, 4))
        self.assertEqual((values["cur_disc_count"], values["cur_disc_events"], values["cur_disc_distinct"], values["rollup_strata"]), (40, 400, 9, 2))
        self.assertEqual((values["first_seen_run"], values["last_seen_run"], values["last_seen_time"]), ("20261013T1000Z", RUN_ID, 200.0))
        self.assertEqual(values["sample_values"], ["y", "x"])

    def test_an_identifier_child_makes_the_rollup_an_identifier_without_top_values(self):
        values = self.rollup(self.children())
        self.assertEqual((values["identifier"], values["top_values"], values["top_counts"]), (1, [], []))

    def test_rollup_top_values_merge_by_summed_count_without_identifiers(self):
        a, b = self.children()
        a["identifier"] = 0
        values = self.rollup([a, b])
        self.assertEqual((values["identifier"], values["top_values"], values["top_counts"]), (0, ["y", "x"], ["20", "15"]))

    def test_type_guess_needs_a_strict_majority(self):
        self.assertEqual(s3_discover.majority_type(["number", "number", "string", "string"]), "mixed")
        self.assertEqual(s3_discover.majority_type(["number", "number", "string"]), "number")
        self.assertEqual(s3_discover.majority_type([]), "empty")


if __name__ == "__main__":
    unittest.main()
