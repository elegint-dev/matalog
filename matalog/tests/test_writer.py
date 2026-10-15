import json
import unittest

import support
from matalog import keys, rows, writer
import fake_client

RUN = {"run_id": "20261013T1400Z", "attempt": 1, "profiled_as": "svc"}


class Encoding(unittest.TestCase):
    def test_line_starts_with_the_slot_timestamp_and_repeats_names_for_lists(self):
        row = rows.source_row(RUN, "main", "st", events_last_cycle=1, daily_events=2, config_apps=["a@1", "b@2"], daily_bytes=None)
        line = writer.encode_line(row, support.SLOT)
        self.assertTrue(line.startswith('10/13/2026 14:00:00 +0000, kind="source", run_id="20261013T1400Z", attempt="1"'))
        self.assertIn('config_apps="a@1", config_apps="b@2"', line)
        self.assertIn('daily_bytes=""', line)
        self.assertNotIn("version_top=", line)

    def test_quotes_and_backslashes_are_escaped_the_way_collect_does(self):
        self.assertEqual(writer.kv_pair("v", 'say "hi"\\x'), 'v="say \\"hi\\"\\\\x"')
        self.assertEqual(writer.kv_pair("f", 0.5), 'f="0.5"')
        self.assertEqual(writer.kv_pair("f", None), 'f=""')
        back = fake_client.parse_stash_line('10/13/2026 14:00:00 +0000, v="say \\"hi\\"\\\\x", m="1", m="2"')
        self.assertEqual(back["v"], 'say "hi"\\x')
        self.assertEqual(back["m"], ["1", "2"])

    def test_a_collect_job_reads_only_its_own_attempts_buffer_rows_by_seq(self):
        spl = writer.collect_spl("20261013T1400Z", 2, 5, 9)
        self.assertEqual(spl, '| inputlookup matalog_write_buffer where run_id="20261013T1400Z" attempt=2 seq>=5 seq<=9'
                              ' | eval _raw=r | fields _raw | collect index=matalog_profiles sourcetype=stash')


class Batching(unittest.TestCase):
    def test_batches_close_at_rows_or_bytes_whichever_first(self):
        lines = ["x" * 100] * 10
        self.assertEqual([len(b) for b in writer.make_batches(lines, 4, 10 ** 6)], [4, 4, 2])
        per_line = writer.payload_bytes(lines[0])
        self.assertEqual([len(b) for b in writer.make_batches(lines, 100, per_line * 3 + 2)], [3, 3, 3, 1])
        self.assertEqual(writer.make_batches([], 4, 100), [])

    def test_a_line_larger_than_the_byte_cap_still_goes_alone(self):
        self.assertEqual([len(b) for b in writer.make_batches(["y" * 500, "z"], 10, 100)], [1, 1])


class SummaryWrites(unittest.TestCase):
    def test_rows_are_written_in_batches_and_bytes_are_counted(self):
        ctx = support.context(**{"write.write_batch_rows": 2})
        rws = [rows.source_row(RUN, "main", "st%d" % i, events_last_cycle=i, daily_events=i) for i in range(5)]
        report = ctx.summary_writer.write(rws, step="S10")
        self.assertEqual((report.rows, report.write_searches, report.rows_by_kind), (5, 3, {"source": 5}))
        lines = [writer.encode_line(r, support.SLOT) for r in rws]
        self.assertEqual(report.write_bytes, sum(len(writer.batch_payload(b).encode()) for b in writer.make_batches(lines, 2, 10 ** 9)))
        back = ctx.client.collected_rows()
        self.assertEqual([r["src_sourcetype"] for r in back], ["st0", "st1", "st2", "st3", "st4"])
        self.assertEqual(back[0]["_stamp"], "10/13/2026 14:00:00 +0000")
        self.assertEqual(ctx.budget.write_searches, 3)
        self.assertEqual(ctx.budget.per_step["S10"]["rows_written"], 5)
        self.assertEqual(len(ctx.summary["search_cost"]), 3)
        self.assertEqual(ctx.summary["search_cost"][0]["subject_key"], "write")

    def test_the_first_failed_batch_stops_the_write_and_raises_with_the_report(self):
        ctx = support.context(**{"write.write_batch_rows": 1})
        ctx.client.collect_failures = 1
        rws = [rows.source_row(RUN, "main", "st%d" % i, events_last_cycle=i, daily_events=i) for i in range(2)]
        with self.assertRaises(writer.WriteError) as caught:
            ctx.summary_writer.write(rws)
        report = caught.exception.report
        self.assertEqual((report.rows, len(report.failed), report.write_searches), (0, 1, 1))
        self.assertEqual(ctx.client.collected, [])

    def test_invalid_rows_are_refused_before_any_write(self):
        ctx = support.context()
        with self.assertRaises(rows.RowError):
            ctx.summary_writer.write([{"kind": "source", "bogus": 1}])
        self.assertEqual(ctx.client.collected, [])


class RollRule(unittest.TestCase):
    def existing(self):
        return {"_key": "k", "cur_disc_run_id": "20261013T1300Z", "cur_disc_count": 10, "cur_disc_events": 20, "cur_disc_coverage": 0.5, "cur_disc_distinct": 3,
                "base_disc_run_id": "20261013T1200Z", "base_disc_count": 1, "base_disc_events": 2, "base_disc_coverage": 0.5, "base_disc_distinct": 1,
                "cur_prof_run_id": "20261013T0000Z", "cur_prof_count": 7, "usage_count": 4}

    def test_a_newer_run_moves_cur_to_base_then_overwrites_cur(self):
        new = {"_key": "k", "cur_disc_run_id": "20261013T1400Z", "cur_disc_count": 11, "cur_disc_events": 22, "cur_disc_coverage": 0.5, "cur_disc_distinct": 4}
        merged = writer.apply_roll("matalog_fields", new, self.existing())
        self.assertEqual((merged["base_disc_run_id"], merged["base_disc_count"], merged["base_disc_distinct"]), ("20261013T1300Z", 10, 3))
        self.assertEqual((merged["cur_disc_run_id"], merged["cur_disc_count"]), ("20261013T1400Z", 11))
        self.assertEqual((merged["cur_prof_run_id"], merged["cur_prof_count"], merged["usage_count"]), ("20261013T0000Z", 7, 4))

    def test_a_rerun_overwrites_cur_only_and_never_moves_the_baseline(self):
        new = {"_key": "k", "cur_disc_run_id": "20261013T1300Z", "cur_disc_count": 99}
        merged = writer.apply_roll("matalog_fields", new, self.existing())
        self.assertEqual((merged["base_disc_run_id"], merged["base_disc_count"], merged["cur_disc_count"]), ("20261013T1200Z", 1, 99))

    def test_an_older_snapshot_never_replaces_the_current_one(self):
        new = {"_key": "k", "cur_disc_run_id": "20261013T1000Z", "cur_disc_count": 5, "presence": "present"}
        merged = writer.apply_roll("matalog_fields", new, self.existing())
        self.assertEqual((merged["cur_disc_run_id"], merged["cur_disc_count"], merged["presence"]), ("20261013T1300Z", 10, "present"))

    def test_each_snapshot_group_rolls_on_its_own(self):
        new = {"_key": "k", "cur_prof_run_id": "20261013T1400Z", "cur_prof_count": 8}
        merged = writer.apply_roll("matalog_fields", new, self.existing())
        self.assertEqual((merged["base_prof_run_id"], merged["base_prof_count"]), ("20261013T0000Z", 7))
        self.assertEqual(merged["base_disc_run_id"], "20261013T1200Z")
        self.assertEqual(merged["cur_disc_run_id"], "20261013T1300Z")

    def test_a_first_write_has_no_baseline(self):
        merged = writer.apply_roll("matalog_strata", {"_key": "k", "cur_run_id": "20261013T1400Z", "cur_events_seen": 1}, None)
        self.assertNotIn("base_run_id", merged)
        self.assertEqual(merged["cur_events_seen"], 1)

    def test_reclassify_snapshots_are_never_rolled_into_base(self):
        stored = {"_key": "e", "cur_run_id": "20261013T1300Z", "cur_match_rate": 0.9, "cur_tested": 10, "source": "reclassify",
                  "base_run_id": "20261013T1100Z", "base_match_rate": 0.7, "base_tested": 9}
        new = {"_key": "e", "cur_run_id": "20261013T1400Z", "cur_match_rate": 0.8, "cur_tested": 12, "source": "profile"}
        merged = writer.apply_roll("matalog_field_types", new, stored)
        self.assertEqual((merged["base_run_id"], merged["base_match_rate"], merged["base_tested"]), ("20261013T1100Z", 0.7, 9))
        self.assertEqual((merged["cur_run_id"], merged["source"]), ("20261013T1400Z", "profile"))
        stored["source"] = "profile"
        merged = writer.apply_roll("matalog_field_types", dict(new, source="reclassify"), stored)
        self.assertEqual((merged["base_run_id"], merged["source"]), ("20261013T1300Z", "reclassify"))


class KVWrites(unittest.TestCase):
    def test_staged_documents_merge_onto_stored_ones_and_drop_empty_columns(self):
        ctx = support.context()
        ctx.client.kv_batch_save("matalog_sources", [{"_key": keys.source_key("main", "st"), "usage_count": 3, "state": "active"}])
        doc = rows.sources_doc("main", "st", daily_events=5, daily_bytes=None, priority=1.0)
        self.assertEqual(ctx.kv_writer.write("matalog_sources", [doc]), 1)
        stored = ctx.client.kv_get("matalog_sources", doc["_key"])
        self.assertEqual((stored["usage_count"], stored["daily_events"], stored["state"]), (3, 5, "active"))
        self.assertNotIn("daily_bytes", stored)

    def test_kv_writes_validate_against_the_collection(self):
        ctx = support.context()
        with self.assertRaises(rows.RowError):
            ctx.kv_writer.write("matalog_sources", [{"_key": "k", "bogus": 1}])

    def test_delete_removes_keys(self):
        ctx = support.context()
        ctx.client.kv_batch_save("matalog_runs", [{"_key": "a"}, {"_key": "b"}])
        self.assertEqual(ctx.kv_writer.delete("matalog_runs", ["a"]), 1)
        self.assertEqual([d["_key"] for d in ctx.client.kv_query("matalog_runs")], ["b"])


class ReadingBack(unittest.TestCase):
    def test_committed_rows_spl_filters_by_the_commit_subsearch(self):
        spl = writer.committed_rows_spl(["source", "stratum"])
        self.assertIn("kind IN (source, stratum)", spl)
        self.assertIn("[search index=matalog_profiles kind=commit | stats max(attempt) as attempt by run_id | fields run_id attempt]", spl)
        self.assertIn("| dedup 2 field_key mode | head 50", writer.latest_rows_spl("field", 50))
        self.assertIn("| dedup 2 source_key |", writer.latest_rows_spl("source", 5))
        self.assertEqual(writer.committed_attempt_spl("r1"), "search index=matalog_profiles kind=commit run_id=r1 | stats max(attempt) as attempt")
        self.assertIn("run_id=r1 attempt=2", writer.run_rows_spl("r1", 2, ["field"], 10))

    def test_rows_read_back_keep_contract_columns_and_list_shape(self):
        raw = {"kind": "stratum", "run_id": "r", "attempt": "1", "profiled_as": "s", "mode": "discovery", "version_top": "only", "events_seen": "3",
               "_raw": "...", "_time": "x", "sourcetype": "stash", "prunable": ["1"]}
        row = writer.summary_row_from_result(raw)
        self.assertEqual(row["version_top"], ["only"])
        self.assertEqual(row["prunable"], "1")
        self.assertNotIn("_raw", row)
        self.assertIsNone(writer.summary_row_from_result({"kind": "nope"}))


class BufferedWrites(unittest.TestCase):
    def test_written_rows_leave_the_buffer_empty(self):
        ctx = support.context(**{"write.write_batch_rows": 2})
        rws = [rows.source_row(RUN, "main", "st%d" % i, events_last_cycle=i, daily_events=i) for i in range(3)]
        ctx.summary_writer.write(rws)
        self.assertEqual(len(ctx.client.collected), 3)
        self.assertEqual(ctx.client.kv_query(writer.BUFFER_COLLECTION), [])

    def test_buffer_rows_of_another_attempt_are_never_collected(self):
        ctx = support.context()
        stale = rows.source_row(dict(RUN, attempt=7), "main", "stale", events_last_cycle=1, daily_events=1)
        ctx.client.kv_batch_save(writer.BUFFER_COLLECTION, [{"_key": "old", "run_id": ctx.run_id, "attempt": 7, "seq": 1, "kind": "source",
                                                             "r": writer.encode_line(stale, support.SLOT)}])
        ctx.summary_writer.write([rows.source_row(ctx.run, "main", "fresh", events_last_cycle=1, daily_events=1)])
        self.assertEqual([r["src_sourcetype"] for r in ctx.client.collected_rows()], ["fresh"])

    def test_a_collect_that_copies_fewer_rows_than_the_batch_is_a_failed_write(self):
        ctx = support.context()
        original = ctx.client._collect

        def short(spec, spl, sid):
            result = original(spec, spl, sid)
            result.result_count -= 1
            return result
        ctx.client._collect = short
        with self.assertRaises(writer.WriteError):
            ctx.summary_writer.write([rows.source_row(ctx.run, "main", "st%d" % i, events_last_cycle=1, daily_events=1) for i in range(2)])

    def test_clearing_the_buffer_keeps_rows_of_the_current_and_later_attempts(self):
        client = fake_client.FakeClient(load_all=False)
        client.kv_batch_save(writer.BUFFER_COLLECTION, [{"_key": "a", "run_id": "20261013T1300Z", "attempt": 1, "seq": 1},
                                                        {"_key": "b", "run_id": "20261013T1400Z", "attempt": 1, "seq": 1},
                                                        {"_key": "c", "run_id": "20261013T1400Z", "attempt": 2, "seq": 1}])
        writer.clear_buffer(client, "20261013T1400Z", 2)
        self.assertEqual([d["_key"] for d in client.kv_query(writer.BUFFER_COLLECTION)], ["c"])

    def test_one_collect_job_carries_a_batch_far_larger_than_the_makeresults_inline_limit(self):
        ctx = support.context()
        rws = [rows.source_row(RUN, "main", "st%04d" % i, events_last_cycle=i, daily_events=i, config_apps=["app%d@1.0" % i]) for i in range(400)]
        report = ctx.summary_writer.write(rws)
        self.assertGreater(report.write_bytes, 30000)
        self.assertEqual(report.write_searches, 1)


class RollRuleEdges(unittest.TestCase):
    def test_an_older_snapshot_changes_no_cur_column_and_no_newer_plain_column(self):
        merged = writer.apply_roll("matalog_strata",
                                   {"_key": "x", "cur_run_id": "20261013T1300Z", "cur_latest": 1.0, "last_seen_run": "20261013T1300Z",
                                    "updated_run_id": "20261013T1300Z", "listed_events": 5},
                                   {"_key": "x", "cur_run_id": "20261013T1400Z", "cur_latest": 2.0, "last_seen_run": "20261013T1400Z",
                                    "updated_run_id": "20261013T1400Z", "listed_events": 9})
        self.assertEqual((merged["cur_run_id"], merged["cur_latest"], merged["last_seen_run"], merged["updated_run_id"], merged["listed_events"]),
                         ("20261013T1400Z", 2.0, "20261013T1400Z", "20261013T1400Z", 9))

    def test_an_older_document_still_fills_columns_the_stored_one_lacks(self):
        merged = writer.apply_roll("matalog_fields", {"_key": "x", "updated_run_id": "20261013T1300Z", "origin": "json_auto", "top_values": ["a"]},
                                   {"_key": "x", "updated_run_id": "20261013T1400Z", "top_values": ["b"]})
        self.assertEqual((merged["origin"], merged["top_values"]), ("json_auto", ["b"]))

    def test_a_newer_snapshot_replaces_the_whole_cur_group(self):
        stored = {"_key": "x", "cur_run_id": "20261013T1300Z", "cur_events_seen": 4, "cur_truncated": 1, "cur_latest": 1.0}
        merged = writer.apply_roll("matalog_strata", {"_key": "x", "cur_run_id": "20261013T1400Z", "cur_events_seen": 6}, stored)
        self.assertEqual((merged["cur_events_seen"], merged["base_run_id"], merged["base_events_seen"]), (6, "20261013T1300Z", 4))
        self.assertNotIn("cur_truncated", merged)
        self.assertNotIn("cur_latest", merged)

    def test_first_seen_run_keeps_the_earliest_and_last_seen_run_the_latest(self):
        merged = writer.apply_roll("matalog_fields", {"_key": "x", "first_seen_run": "20261013T1400Z", "last_seen_run": "20261013T1200Z"},
                                   {"_key": "x", "first_seen_run": "20261013T1100Z", "last_seen_run": "20261013T1300Z"})
        self.assertEqual((merged["first_seen_run"], merged["last_seen_run"]), ("20261013T1100Z", "20261013T1300Z"))

    def test_merging_snapshots_oldest_first_gives_cur_from_the_newest_and_base_from_the_one_before(self):
        docs = [{"_key": "x", "cur_disc_run_id": "20261013T1200Z", "cur_disc_count": 3},
                {"_key": "x", "cur_disc_run_id": "20261013T1300Z", "cur_disc_count": 7}]
        merged = writer.merge_snapshots("matalog_fields", docs)
        self.assertEqual((merged["cur_disc_count"], merged["base_disc_run_id"], merged["base_disc_count"]), (7, "20261013T1200Z", 3))


if __name__ == "__main__":
    unittest.main()
