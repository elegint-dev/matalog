import json
import unittest

import support
from matalog import keys, rows
import fake_client

RUN = {"run_id": "20261013T1400Z", "attempt": 1, "profiled_as": "svc_matalog"}
IDENT = ("matalog_json", "crowdstrike:events:sensor", "event_simpleName", "ProcessRollup2")


def field_values(**extra):
    base = dict(earliest=1.0, latest=2.0, sample_ratio=1, events_in_stratum=100, count=50, distinct=5, distinct_exact=1,
                numeric_count=0, type_guess="string", identifier=0, values_hash="0" * 32, sid="s1")
    base.update(extra)
    return base


class Contract(unittest.TestCase):
    def test_every_collection_has_its_accelerated_fields_among_its_columns(self):
        for collection, fields in rows.ACCELERATED.items():
            for field in fields:
                self.assertIn(field, rows.COLLECTIONS[collection], "%s accelerates unknown %s" % (collection, field))

    def test_key_columns_exist_and_snapshot_groups_name_real_columns(self):
        for collection, column in rows.KEY_COLUMN.items():
            self.assertIn(column, rows.COLLECTIONS[collection])
        for collection, groups in rows.SNAPSHOT_GROUPS.items():
            for cur, base, suffixes in groups:
                for suffix in suffixes:
                    self.assertIn(cur + suffix, rows.COLLECTIONS[collection])
                    self.assertIn(base + suffix, rows.COLLECTIONS[collection])

    def test_week_snapshot_mirrors_the_profile_snapshot(self):
        cols = rows.COLLECTIONS["matalog_fields"]
        for suffix in ("run_id", "count", "events", "coverage", "distinct", "distinct_exact", "sample_ratio"):
            self.assertIn("week_prof_" + suffix, cols)


class Validation(unittest.TestCase):
    def test_unknown_columns_are_rejected_on_rows_and_docs(self):
        row = rows.source_row(RUN, "main", "st", events_last_cycle=1, daily_events=2)
        row["bogus"] = 1
        with self.assertRaises(rows.RowError):
            rows.validate(row)
        with self.assertRaises(rows.RowError):
            rows.sources_doc("main", "st", bogus=1)

    def test_missing_columns_are_rejected_unless_partial(self):
        row = rows.source_row(RUN, "main", "st", events_last_cycle=1, daily_events=2)
        del row["daily_bytes"]
        with self.assertRaises(rows.RowError):
            rows.validate(row)
        self.assertEqual(rows.validate({"_key": "k", "state": "active"}, collection="matalog_sources", partial=True)["state"], "active")
        with self.assertRaises(rows.RowError):
            rows.validate({"state": "active"}, collection="matalog_sources", partial=True)

    def test_values_must_match_the_column_type(self):
        with self.assertRaises(rows.RowError):
            rows.sources_doc("main", "st", daily_events="12")
        with self.assertRaises(rows.RowError):
            rows.sources_doc("main", "st", config_apps="a@1")
        with self.assertRaises(rows.RowError):
            rows.sources_doc("main", "st", state=1)
        with self.assertRaises(rows.RowError):
            rows.sources_doc("main", "st", priority=float("nan"))
        with self.assertRaises(rows.RowError):
            rows.fields_doc(*IDENT, field_name="f", observed=True)
        with self.assertRaises(rows.RowError):
            rows.fields_doc(*IDENT, field_name="f", origin="magic")
        doc = rows.sources_doc("main", "st", daily_events=12, config_apps=["a@1"], state="active", priority=1.5, last_event_time=1.0)
        self.assertEqual(doc["_key"], keys.source_key("main", "st"))
        self.assertEqual(doc["source_key"], doc["_key"])

    def test_enumerations_are_enforced(self):
        with self.assertRaises(rows.RowError):
            rows.field_row(RUN, "discovery", "slim", *IDENT, field_name="f", **field_values(type_guess="number"))
        with self.assertRaises(rows.RowError):
            rows.runs_doc("r", status="done")
        with self.assertRaises(rows.RowError):
            rows.stratum_row(RUN, "weekly", *IDENT, earliest=1.0, latest=2.0, sample_ratio=1, events_seen=1, events_scanned=1, fields_found=1, truncated=0, fields_truncated=0)


class SummaryBuilders(unittest.TestCase):
    def test_source_row_carries_identity_and_every_column(self):
        row = rows.source_row(RUN, "Main", "st", events_last_cycle=1, daily_events=2)
        self.assertEqual(row["kind"], "source")
        self.assertEqual(row["src_index"], "main")
        self.assertEqual(row["source_key"], keys.source_key("main", "st"))
        self.assertEqual(row["row_id"], keys.k("20261013T1400Z", "source", row["source_key"]))
        self.assertEqual(set(row), set(rows.columns_for(kind="source")))
        self.assertEqual(row["config_apps"], [])
        self.assertIsNone(row["daily_bytes"])

    def test_stratum_row_derives_scan_ratio_and_prunable(self):
        row = rows.stratum_row(RUN, "discovery", *IDENT, earliest=1.0, latest=2.0, sample_ratio=1, events_seen=200, events_scanned=3000,
                               fields_found=10, truncated=1, fields_truncated=0, sid="s", search_seconds=0.1)
        self.assertEqual(row["scan_ratio"], 15.0)
        self.assertEqual(row["prunable"], 1)
        self.assertEqual(row["stratum_key"], keys.stratum_key(*IDENT))
        missing = rows.stratum_row(RUN, "profile", "main", "st", "f", keys.MISSING, earliest=1.0, latest=2.0, sample_ratio=100, events_seen=0,
                                   events_scanned=0, fields_found=0, truncated=0, fields_truncated=0)
        self.assertEqual(missing["prunable"], 0)
        self.assertEqual(missing["scan_ratio"], 0.0)

    def test_field_row_shapes_have_their_own_columns(self):
        slim = rows.field_row(RUN, "discovery", "slim", *IDENT, field_name="CommandLine", **field_values())
        self.assertEqual(slim["profile_id"], keys.k("20261013T1400Z", "discovery", slim["field_key"]))
        self.assertNotIn("top_values", slim)
        self.assertEqual(slim["coverage"], 0.5)
        full = rows.field_row(RUN, "profile", "full", *IDENT, field_name="CommandLine", **field_values(top_values=["a"], top_counts=["1"], sample_values=["a"]))
        self.assertEqual(full["samples_truncated"], 0)
        self.assertIsNone(full["origin"])
        with self.assertRaises(rows.RowError):
            rows.field_row(RUN, "discovery", "slim", *IDENT, field_name="x", top_values=["a"], **field_values())

    def test_search_cost_and_commit_rows_are_keyed_by_content(self):
        result = fake_client.client_mod.JobResult(sid="1.2", status="timeout", scan_count=5, event_count=4, result_count=3, run_duration=1.5, spl="search x", earliest=1, latest=2)
        cost = rows.search_cost_row(RUN, result, "S3", "subj")
        self.assertEqual(cost["row_id"], keys.k("20261013T1400Z", "1.2"))
        self.assertEqual(cost["spl_hash"], keys.spl_hash("search x"))
        self.assertEqual((cost["scan_count"], cost["event_count"], cost["result_rows"], cost["run_duration"], cost["status"]), (5, 4, 3, 1.5, "timeout"))
        snap = {"searches_issued": 3, "events_scanned": 10, "search_seconds": 1.0, "wall_seconds": 2.0, "budget_exhausted": ""}
        commit = rows.commit_row(RUN, "normal", 1791900100, "c" * 32, {"field": 2, "source": 1}, snap, 999)
        self.assertEqual(commit["row_id"], keys.k("20261013T1400Z", 1))
        self.assertEqual(commit["rows_kind"], ["field", "source"])
        self.assertEqual(commit["rows_count"], ["2", "1"])


class KVBuilders(unittest.TestCase):
    def test_strata_and_fields_docs_fill_identity_label_and_level(self):
        stratum = rows.strata_doc("main", "st", "f", keys.ALL)
        self.assertEqual((stratum["stratum_value"], stratum["level"], stratum["value_kind"], stratum["stratum_label"]), (keys.ALL, "source", "all", "all events"))
        field = rows.fields_doc(*IDENT, field_name="event_simpleName", observed=1)
        self.assertEqual((field["level"], field["is_stratum_field"], field["stratum_label"]), ("stratum", 1, "event_simpleName=ProcessRollup2"))
        self.assertEqual(field["_key"], keys.field_key(*IDENT, "event_simpleName"))

    def test_every_collection_has_a_builder_that_sets_its_key(self):
        self.assertEqual(rows.stratum_config_doc("*", "st", "f")["_key"], keys.k("*", "st"))
        self.assertEqual(rows.declarations_doc("app", "props", "st", "EXTRACT-x")["_key"], keys.k("app", "props", "st", "EXTRACT-x"))
        self.assertEqual(rows.cim_coverage_doc("A.A", "user", "main", "st")["_key"], keys.k("A.A", "user", "main", "st"))
        self.assertEqual(rows.meanings_doc("fk", 2, text="t")["_key"], keys.k("fk", 2))
        self.assertEqual(rows.objects_doc("alert", "app", "o", "n")["_key"], keys.k("alert", "app", "o", "n"))
        self.assertEqual(rows.usage_doc("ok", "*", "user", "filter")["_key"], keys.k("ok", "*", "user", "filter"))
        self.assertEqual(rows.semantic_types_doc("mt:ipv4")["name"], "ipv4")
        self.assertEqual(rows.field_types_doc("fk", "mt:ipv4")["_key"], keys.k("fk", "mt:ipv4"))
        self.assertEqual(rows.runs_doc("20261013T1400Z", status="running")["run_id"], "20261013T1400Z")


class Encoding(unittest.TestCase):
    def test_values_are_truncated_to_max_value_chars(self):
        s = support.settings(**{"profile.max_value_chars": 4})
        row = rows.field_row(RUN, "profile", "full", *IDENT, field_name="f", **field_values(top_values=["abcdef"], top_counts=["1"], sample_values=["abcdefgh"]))
        trimmed = rows.trim_row(row, s)
        self.assertEqual(trimmed["top_values"], ["abcd"])
        self.assertEqual(trimmed["sample_values"], ["abcd"])
        self.assertEqual(trimmed["values_hash"], "0" * 32)

    def test_sample_values_stop_at_count_or_bytes_whichever_first(self):
        values, truncated = rows.cap_sample_values(["a%02d" % i + "a" * 7 for i in range(50)], 100, 60, 128)
        self.assertLess(len(values), 50)
        self.assertEqual(truncated, 1)
        values, truncated = rows.cap_sample_values([str(i) for i in range(50)], 10, 6144, 128)
        self.assertEqual((len(values), truncated), (10, 0))

    def test_sample_values_stay_distinct_after_truncation(self):
        long_a, long_b = "p" * 128 + "a", "p" * 128 + "b"
        values, truncated = rows.cap_sample_values([long_a, long_b, "q"], 100, 6144, 128)
        self.assertEqual(values, ["p" * 128, "q"])
        self.assertEqual(truncated, 0)

    def test_top_values_are_dropped_from_the_tail_until_the_row_fits(self):
        s = support.settings(**{"profile.max_row_bytes": 960})
        top = ["v%02d" % i for i in range(10)]
        row = rows.field_row(RUN, "profile", "full", *IDENT, field_name="f", **field_values(top_values=top, top_counts=[str(i) for i in range(10)], sample_values=["x%d" % i + "x" * 8 for i in range(3)]))
        self.assertGreater(rows.row_bytes(row), 960)
        trimmed = rows.trim_row(row, s)
        self.assertLessEqual(rows.row_bytes(trimmed), 960)
        self.assertEqual(len(trimmed["sample_values"]), 3)
        self.assertLess(len(trimmed["top_values"]), 10)
        self.assertEqual(trimmed["top_values"], top[:len(trimmed["top_values"])])
        self.assertEqual(len(trimmed["top_counts"]), len(trimmed["top_values"]))

    def test_type_guess_covers_every_outcome(self):
        self.assertEqual(rows.type_guess([]), "empty")
        self.assertEqual(rows.type_guess(["", " "]), "empty")
        self.assertEqual(rows.type_guess(["1", "2"]), "integer")
        self.assertEqual(rows.type_guess(["1", "2.5"]), "float")
        self.assertEqual(rows.type_guess(["true", "FALSE"]), "boolean")
        self.assertEqual(rows.type_guess(["a", "b"]), "string")
        self.assertEqual(rows.type_guess(["a", "1"]), "mixed")

    def test_identifier_gate_uses_distinct_then_ratio_above_min_count(self):
        s = support.settings()
        self.assertEqual(rows.is_identifier(10, 1000, s), 1)
        self.assertEqual(rows.is_identifier(100, 95, s), 1)
        self.assertEqual(rows.is_identifier(40, 40, s), 0)
        self.assertEqual(rows.is_identifier(100, 50, s), 0)

    def test_numeric_stats_are_empty_when_nothing_is_numeric(self):
        self.assertEqual(rows.numeric_stats({"numeric_count": "0", "min": "1"}), {"numeric_count": 0, "num_min": None, "num_max": None, "num_mean": None, "num_stdev": None})
        stats = rows.numeric_stats({"numeric_count": "3", "min": "1", "max": "9", "mean": "4.5", "stdev": "2"})
        self.assertEqual(stats, {"numeric_count": 3, "num_min": 1.0, "num_max": 9.0, "num_mean": 4.5, "num_stdev": 2.0})

    def test_values_hash_ignores_order_and_truncation(self):
        self.assertEqual(rows.values_hash(["b", "a"]), rows.values_hash(["a", "b"]))
        self.assertNotEqual(rows.values_hash(["a"]), rows.values_hash(["a", "b"]))
        self.assertEqual(len(rows.values_hash([])), 32)

    def test_fieldsummary_values_parse_most_frequent_first(self):
        pairs = rows.parse_fieldsummary_values(json.dumps([{"value": "x", "count": 1}, {"value": "y", "count": 5}]))
        self.assertEqual(pairs, [("y", 5), ("x", 1)])
        self.assertEqual(rows.parse_fieldsummary_values(""), [])


class FromFieldsummary(unittest.TestCase):
    def test_fixture_row_becomes_a_full_profile_row_within_the_caps(self):
        s = support.settings()
        fixture = fake_client.load_fixture("fieldsummary_crowdstrike_ProcessRollup2_discovery")
        by_name = dict((r["field"], r) for r in fixture["results"])
        n = int(by_name["matalog_n"]["count"])
        self.assertEqual(n, 2000)
        row = rows.field_row_from_fieldsummary(RUN, s, "discovery", "full", by_name["CommandLine"], *IDENT, events_in_stratum=n,
                                               earliest=1.0, latest=2.0, sample_ratio=1, sid="s", origin="json_auto", origin_app="")
        self.assertEqual(row["kind"], "field")
        self.assertEqual(row["events_in_stratum"], 2000)
        self.assertAlmostEqual(row["coverage"], int(by_name["CommandLine"]["count"]) / 2000.0)
        self.assertLessEqual(rows.row_bytes(row), s.profile.max_row_bytes)
        self.assertLessEqual(len(row["sample_values"]), s.profile.sample_values)
        self.assertEqual(row["origin"], "json_auto")
        numeric = rows.field_row_from_fieldsummary(RUN, s, "discovery", "slim", by_name["AuthenticationId"], *IDENT, events_in_stratum=n, earliest=1.0, latest=2.0, sample_ratio=1, sid="s")
        self.assertGreater(numeric["numeric_count"], 0)
        self.assertIsNotNone(numeric["num_mean"])
        self.assertNotIn("sample_values", numeric)

    def test_identifier_fields_store_no_top_values_but_keep_samples(self):
        s = support.settings(**{"profile.identifier_distinct": 20})
        fixture = fake_client.load_fixture("fieldsummary_crowdstrike_ProcessRollup2_discovery")
        fs = next(r for r in fixture["results"] if int(r["distinct_count"]) >= 20)
        row = rows.field_row_from_fieldsummary(RUN, s, "profile", "full", fs, *IDENT, events_in_stratum=2000, earliest=1.0, latest=2.0, sample_ratio=1, sid="s")
        self.assertEqual(row["identifier"], 1)
        self.assertEqual(row["top_values"], [])
        self.assertTrue(row["sample_values"])


class RebuildMapping(unittest.TestCase):
    def test_summary_rows_map_to_the_documents_the_steps_write(self):
        source = rows.source_row(RUN, "main", "st", events_last_cycle=1, daily_events=2, config_apps=["a@1"])
        collection, doc = rows.kv_from_summary(source)
        self.assertEqual(collection, "matalog_sources")
        self.assertEqual((doc["daily_events"], doc["last_seen_run"], doc["config_apps"]), (2, "20261013T1400Z", ["a@1"]))
        stratum = rows.stratum_row(RUN, "discovery", *IDENT, earliest=1.0, latest=2.0, sample_ratio=1, events_seen=10, events_scanned=20, fields_found=3, truncated=0, fields_truncated=0)
        collection, doc = rows.kv_from_summary(stratum)
        self.assertEqual((collection, doc["cur_run_id"], doc["cur_scan_ratio"], doc["last_discovered_run"]), ("matalog_strata", "20261013T1400Z", 2.0, "20261013T1400Z"))
        field = rows.field_row(RUN, "profile", "full", *IDENT, field_name="f", **field_values(top_values=["a"], top_counts=["1"], sample_values=["a"], origin="json_auto"))
        collection, doc = rows.kv_from_summary(field)
        self.assertEqual((collection, doc["cur_prof_run_id"], doc["cur_prof_count"], doc["presence"], doc["origin"]), ("matalog_fields", "20261013T1400Z", 50, "present", "json_auto"))
        self.assertIsNone(rows.kv_from_summary(rows.search_cost_row(RUN, fake_client.client_mod.JobResult(sid="x"), "S1", "s")))

    def test_mapping_accepts_the_string_values_the_index_returns(self):
        raw = {"kind": "field", "run_id": "20261013T1400Z", "attempt": "1", "profiled_as": "svc", "shape": "slim", "mode": "discovery",
               "src_index": "main", "src_sourcetype": "st", "stratum_field": "__all__", "stratum_value": "__all__", "field_name": "f",
               "count": "5", "events_in_stratum": "10", "coverage": "0.5", "distinct": "2", "latest": "2.0", "identifier": "0", "numeric_count": "0"}
        collection, doc = rows.kv_from_summary(raw)
        self.assertEqual((doc["cur_disc_count"], doc["cur_disc_coverage"], doc["last_seen_time"], doc["level"]), (5, 0.5, 2.0, "source"))


class IdentityIsVerbatim(unittest.TestCase):
    def test_identity_columns_are_never_truncated_so_keys_recompute_from_the_row(self):
        s = support.settings()
        stratum = keys.multi_value(["Value%03d_long_text" % i for i in range(10)])
        fs = {"field": "a" * 150, "count": "5", "distinct_count": "2", "is_exact": "1", "numeric_count": "0",
              "values": '[{"value": "%s", "count": 3}]' % ("v" * 200)}
        row = rows.field_row_from_fieldsummary(RUN, s, "discovery", "full", fs, "main", "st", "f", stratum, 10, 1.0, 2.0, 1, "sid")
        self.assertEqual(row["field_name"], "a" * 150)
        self.assertEqual(row["stratum_value"], stratum)
        self.assertEqual(rows.kv_from_summary(row)[1]["_key"], row["field_key"])
        self.assertEqual(row["field_key"], keys.field_key("main", "st", "f", stratum, "a" * 150))
        self.assertEqual(row["sample_values"], ["v" * 128])


class Enumerations(unittest.TestCase):
    def test_commit_rows_refuse_an_unknown_run_mode(self):
        snapshot = {"searches_issued": 0, "events_scanned": 0, "search_seconds": 0.0, "wall_seconds": 0.0}
        with self.assertRaises(rows.RowError):
            rows.commit_row(RUN, "bogus", 1.0, "h", {}, snapshot, 0)

    def test_summary_rows_refuse_unknown_modes_origins_and_slim_profile_rows(self):
        row = rows.field_row(RUN, "discovery", "slim", *IDENT, field_name="f", **field_values())
        bad = dict(row, mode="listing")
        with self.assertRaises(rows.RowError):
            rows.validate(bad)
        with self.assertRaises(rows.RowError):
            rows.validate(dict(row, mode="profile"))
        full = rows.field_row(RUN, "profile", "full", *IDENT, field_name="f", **field_values())
        with self.assertRaises(rows.RowError):
            rows.validate(dict(full, origin="magic"))
        with self.assertRaises(rows.RowError):
            rows.validate({"_key": "r", "run_mode": "weekly"}, collection="matalog_runs", partial=True)


class StableIds(unittest.TestCase):
    def test_a_cost_row_without_a_sid_is_keyed_by_what_it_searched(self):
        from matalog import client as client_mod
        one = client_mod.JobResult(status="failed", spl="search x", earliest=1, latest=2)
        two = client_mod.JobResult(status="failed", spl="search x", earliest=1, latest=2)
        self.assertEqual(rows.search_cost_row(RUN, one, "S3", "k")["sid"], rows.search_cost_row(RUN, two, "S3", "k")["sid"])


class SummaryToKv(unittest.TestCase):
    def test_a_source_row_without_events_does_not_set_last_seen_run(self):
        quiet = rows.kv_from_summary(rows.source_row(RUN, "main", "st", events_last_cycle=0, daily_events=0))[1]
        self.assertNotIn("last_seen_run", [c for c, v in quiet.items() if v is not None])
        busy = rows.kv_from_summary(rows.source_row(RUN, "main", "st", events_last_cycle=0, daily_events=3))[1]
        self.assertEqual((busy["last_seen_run"], busy["first_seen_run"]), (RUN["run_id"], RUN["run_id"]))

    def test_numeric_stats_reach_kv_from_full_rows_only(self):
        slim = rows.kv_from_summary(rows.field_row(RUN, "discovery", "slim", *IDENT, field_name="f", **field_values(numeric_count=4, num_min=1.0)))[1]
        self.assertNotIn("numeric_count", slim)
        self.assertNotIn("num_min", slim)
        full = rows.kv_from_summary(rows.field_row(RUN, "profile", "full", *IDENT, field_name="f", **field_values(numeric_count=4, num_min=1.0)))[1]
        self.assertEqual((full["numeric_count"], full["num_min"]), (4, 1.0))
        self.assertEqual(full["first_seen_run"], RUN["run_id"])


class RowCap(unittest.TestCase):
    def test_trimming_samples_for_the_row_cap_does_not_claim_the_sample_byte_cap(self):
        s = support.settings(**{"profile.max_row_bytes": 900})
        row = rows.field_row(RUN, "profile", "full", *IDENT, field_name="f", **field_values(sample_values=["s%03d" % i + "x" * 20 for i in range(40)]))
        trimmed = rows.trim_row(row, s)
        self.assertLessEqual(rows.row_bytes(trimmed), 900)
        self.assertEqual(trimmed["samples_truncated"], 0)


class RunCounters(unittest.TestCase):
    def test_run_counters_refuse_names_that_are_not_run_columns(self):
        counts = rows.RunCounts()
        counts["strata_due"] = 3
        with self.assertRaises(rows.RowError):
            counts["strata_planned"] = 1
        with self.assertRaises(rows.RowError):
            counts["strata_due"] = "3"


if __name__ == "__main__":
    unittest.main()
