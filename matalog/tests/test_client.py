import json
import unittest

import support
from matalog import client as client_mod
from matalog import budget as budget_mod
from matalog import rows
import fake_client


class Tagging(unittest.TestCase):
    def test_every_search_carries_the_run_comment(self):
        self.assertEqual(client_mod.tag_spl("search index=a | head 1 ", "20261013T1400Z", "S3"),
                         'search index=a | head 1 `comment("matalog run_id=20261013T1400Z step=S3")`')
        client = fake_client.FakeClient(settings=support.settings())
        client.run_id = "20261013T1400Z"
        client.search("| metadata type=sourcetypes index=matalog_json", step="S1")
        self.assertIn('`comment("matalog run_id=20261013T1400Z step=S1")`', client.calls[-1][1]["spl"])

    def test_job_result_hashes_its_spl_and_reports_ok(self):
        result = client_mod.JobResult(sid="1", spl="search x", scan_count="5", run_duration="0.5")
        self.assertEqual(result.spl_hash, rows.keys.spl_hash("search x"))
        self.assertTrue(result.ok)
        self.assertEqual((result.scan_count, result.run_duration), (5, 0.5))
        self.assertFalse(client_mod.JobResult(status="timeout").ok)


class Polling(client_mod.SplunkClient):
    """A client whose REST layer is scripted: the job finishes after a number of polls."""

    def __init__(self, polls_until_done, fail=False, clock=None):
        client_mod.SplunkClient.__init__(self, "https://x", username="u", password="p")
        self.polls_until_done = polls_until_done
        self.fail = fail
        self.polls = 0
        self.actions = []

    def request(self, method, path, params=None, data=None, json_body=None, raw=False):
        if method == "POST" and path.endswith("/search/jobs"):
            self.posted = data
            return {"sid": "sid1"}
        if path.endswith("/control"):
            self.actions.append(data["action"])
            self.polls_until_done = self.polls
            return {}
        if path.endswith("/results"):
            return {"results": [{"a": "1"}]}
        self.polls += 1
        done = self.polls >= self.polls_until_done
        return {"entry": [{"content": {"isDone": "1" if done else "0", "isFailed": "1" if (done and self.fail) else "0", "isFinalized": "1" if self.actions else "0",
                                       "scanCount": "9", "eventCount": "8", "resultCount": "1", "runDuration": "0.3", "messages": []}}]}


class SlowFinalize(client_mod.SplunkClient):
    """A job that stays FINALIZING for some polls after finalize, with an empty results body until done."""

    def __init__(self, polls_after_finalize, pages=None, messages=None):
        client_mod.SplunkClient.__init__(self, "https://x", username="u", password="p")
        self.after = polls_after_finalize
        self.finalized = False
        self.pages = pages
        self.messages = messages or []
        self.result_params = []
        self.posted = None

    def request(self, method, path, params=None, data=None, json_body=None, raw=False):
        if method == "POST" and path.endswith("/search/jobs"):
            self.posted = data
            return {"sid": "sid2"}
        if path.endswith("/control"):
            self.finalized = True
            return {}
        if path.endswith("/results"):
            self.result_params.append(dict(params))
            if self.pages is not None:
                offset = int(params.get("offset", 0))
                return {"results": self.pages[offset:offset + int(params["count"])]}
            return "" if self.after > 0 else {"results": [{"a": "1"}]}
        done = self.pages is not None or self.messages or (self.finalized and self.after <= 0)
        if self.finalized:
            self.after -= 1
        total = len(self.pages) if self.pages is not None else 1
        return {"entry": [{"content": {"isDone": "1" if done else "0", "isFailed": "0", "isFinalized": "1" if self.finalized else "0",
                                       "dispatchState": "DONE" if done else "FINALIZING", "scanCount": "9", "eventCount": "8",
                                       "resultCount": str(total), "runDuration": "2.8", "messages": self.messages}}]}


class JobLifecycle(unittest.TestCase):
    def test_blocking_search_passes_window_and_sample_ratio_and_reads_counts(self):
        client = Polling(polls_until_done=2)
        result = client.search("search x", earliest=10, latest=20, sample_ratio=100, timeout=30, step="S4", tag=False)
        self.assertEqual((client.posted["earliest_time"], client.posted["latest_time"], client.posted["sample_ratio"]), ("10", "20", "100"))
        self.assertEqual((result.status, result.scan_count, result.event_count, result.result_count, result.run_duration, result.sid), ("ok", 9, 8, 1, 0.3, "sid1"))
        self.assertEqual(result.results, [{"a": "1"}])
        self.assertNotIn("sample_ratio", Polling(1).__dict__)

    def test_unsampled_search_sends_no_sample_ratio(self):
        client = Polling(polls_until_done=1)
        client.search("search x", sample_ratio=1, tag=False)
        self.assertNotIn("sample_ratio", client.posted)

    def test_a_job_past_its_timeout_is_finalized_and_reported_as_timeout(self):
        client = Polling(polls_until_done=10 ** 6)
        client_mod.JOB_POLL_START = 0.01
        result = client.search("search slow", timeout=0.05, tag=False)
        self.assertEqual(result.status, "timeout")
        self.assertEqual(client.actions, ["finalize"])
        self.assertEqual(result.scan_count, 9)

    def test_a_failed_job_is_reported_as_failed_with_no_results(self):
        client = Polling(polls_until_done=1, fail=True)
        result = client.search("search bad", tag=False)
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.results, [])


class KVStartup(unittest.TestCase):
    def test_requests_wait_while_the_kv_store_initializes(self):
        import urllib.error
        import io
        attempts = {"n": 0}
        slept = []

        class Flaky(client_mod.SplunkClient):
            def _sleep(self, seconds):
                slept.append(seconds)
        client = Flaky("https://x", username="u", password="p")

        def fake_urlopen(req, context=None, timeout=None):
            attempts["n"] += 1
            if attempts["n"] < 3:
                raise urllib.error.HTTPError(req.full_url, 503, "busy", {}, io.BytesIO(b'{"messages":[{"type":"ERROR","text":"KV Store is initializing. Please try again later."}]}'))
            return io.BytesIO(b'{"ok": 1}')
        original = client_mod.urllib.request.urlopen
        client_mod.urllib.request.urlopen = fake_urlopen
        try:
            self.assertEqual(client.request("GET", "/x"), {"ok": 1})
        finally:
            client_mod.urllib.request.urlopen = original
        self.assertEqual((attempts["n"], len(slept)), (3, 2))


class ThroughTheBudget(unittest.TestCase):
    def test_fake_searches_are_counted_and_costed_like_real_ones(self):
        ctx = support.context()
        result = ctx.client.search("| metadata type=sourcetypes index=matalog_json", step="S1", subject_key="matalog_json")
        self.assertTrue(result.ok)
        self.assertEqual(len(result.results), 6)
        self.assertEqual(ctx.budget.searches_issued, 1)
        cost = ctx.summary["search_cost"][0]
        self.assertEqual((cost["step"], cost["subject_key"], cost["status"], cost["run_id"]), ("S1", "matalog_json", "ok", ctx.run_id))

    def test_unmatched_search_names_the_spl(self):
        ctx = support.context()
        with self.assertRaises(fake_client.FakeClientError):
            ctx.client.search("search index=nothing_here", step="S1")

    def test_fixture_registration_serves_step_authors(self):
        client = fake_client.FakeClient(load_all=False)
        client.add_results([r"stats count by x"], [{"x": "a", "count": "2"}], scan_count=20)
        result = client.search("search index=i | stats count by x", tag=False)
        self.assertEqual((result.scan_count, result.results[0]["x"]), (20, "a"))


class KVStore(unittest.TestCase):
    def test_batch_save_splits_at_kv_batch_size(self):
        client = fake_client.FakeClient(settings=support.settings(**{"write.kv_batch_size": 3}), load_all=False)
        docs = [{"_key": "k%d" % i, "v": i} for i in range(7)]
        saved = client.kv_batch_save("matalog_runs", docs)
        self.assertEqual(len(saved), 7)
        batches = [c for c in client.calls if c[0] == "kv_batch_save"]
        self.assertEqual([c[2] for c in batches], [3, 3, 1])

    def test_query_get_many_and_delete_by_keys(self):
        client = fake_client.FakeClient(load_all=False)
        client.kv_batch_save("matalog_runs", [{"_key": "a", "committed": 0, "run_id": "a"}, {"_key": "b", "committed": 1, "run_id": "b"}, {"_key": "c", "committed": 1, "run_id": "c"}])
        self.assertEqual([d["_key"] for d in client.kv_query("matalog_runs", {"committed": 1}, sort="run_id:-1")], ["c", "b"])
        self.assertEqual([d["_key"] for d in client.kv_query("matalog_runs", {"run_id": {"$lt": "c"}, "committed": 1})], ["b"])
        self.assertEqual(set(client.kv_get_many("matalog_runs", ["a", "zz", "c"])), {"a", "c"})
        client.kv_delete_keys("matalog_runs", ["a", "b"])
        self.assertEqual([d["_key"] for d in client.kv_query("matalog_runs")], ["c"])
        self.assertIsNone(client.kv_get("matalog_runs", "a"))

    def test_real_kv_query_pages_until_a_short_page(self):
        pages = [[{"_key": str(i)} for i in range(client_mod.KV_PAGE)], [{"_key": "last"}]]
        calls = []

        class Paged(client_mod.SplunkClient):
            def _get_json(self, path, params=None):
                calls.append(params)
                return pages[len(calls) - 1]
        client = Paged("https://x", username="u", password="p")
        docs = client.kv_query("matalog_fields", query={"level": "source"}, fields=["field_name"])
        self.assertEqual(len(docs), client_mod.KV_PAGE + 1)
        self.assertEqual(calls[0]["skip"], 0)
        self.assertEqual(calls[1]["skip"], client_mod.KV_PAGE)
        self.assertEqual(json.loads(calls[0]["query"]), {"level": "source"})
        self.assertEqual(calls[0]["fields"], "field_name")


class ConfigReads(unittest.TestCase):
    def test_config_entries_keep_name_content_and_acl_in_endpoint_order(self):
        client = fake_client.FakeClient()
        props = client.props()
        self.assertTrue(props)
        names = [e["name"] for e in props]
        self.assertGreater(len(names), len(set(names)), "the -/- namespace lists a stanza once per app")
        entry = next(e for e in props if e["name"] == "crowdstrike:events:sensor")
        self.assertEqual(entry["content"]["KV_MODE"], "json")
        self.assertEqual(set(entry["acl"]), {"app", "owner", "sharing"})
        self.assertTrue(client.transforms() and client.fields_conf() and client.datamodels() and client.apps_local())
        self.assertIn("version", client.apps_local()[0]["content"])

    def test_entry_shape_from_the_rest_payload(self):
        entry = client_mod._entry({"name": "n", "content": {"a": 1}, "acl": {"app": "search", "owner": "nobody", "sharing": "global", "perms": {}}})
        self.assertEqual(entry, {"name": "n", "content": {"a": 1}, "acl": {"app": "search", "owner": "nobody", "sharing": "global"}})


class Helpers(unittest.TestCase):
    def test_metadata_and_licence_helpers_run_through_the_budget(self):
        ctx = support.context()
        meta = ctx.client.metadata_sourcetypes("matalog_json")
        self.assertEqual(sorted(r["sourcetype"] for r in meta.results)[0], "OktaIM2:log")
        usage = ctx.client.licence_usage(0, "now")
        self.assertTrue(all("b" in r and "idx" in r and "st" in r for r in usage.results))
        self.assertEqual(ctx.budget.searches_issued, 2)
        self.assertEqual(ctx.client.licence_pools()[0]["name"], "auto_generated_pool_download-trial")


class TimeoutAndResults(unittest.TestCase):
    def test_a_timed_out_job_waits_for_done_after_finalize_and_returns_status_timeout(self):
        client_mod.JOB_POLL_START = 0.01
        client = SlowFinalize(polls_after_finalize=3)
        result = client.search("search slow", timeout=0.05, tag=False)
        self.assertEqual(result.status, "timeout")
        self.assertEqual(result.results, [{"a": "1"}])

    def test_an_empty_results_body_is_no_results_not_an_error(self):
        client = SlowFinalize(polls_after_finalize=1)
        self.assertEqual(client._job_results("sid2"), [])

    def test_results_are_read_in_pages_until_the_result_count(self):
        rows_back = [{"n": str(i)} for i in range(7)]
        client = SlowFinalize(0, pages=rows_back)
        client_mod.RESULTS_PAGE, saved = 3, client_mod.RESULTS_PAGE
        try:
            result = client.search("search x | head 7", tag=False, max_rows=7)
        finally:
            client_mod.RESULTS_PAGE = saved
        self.assertEqual([r["n"] for r in result.results], [str(i) for i in range(7)])
        self.assertEqual([p["offset"] for p in client.result_params], [0, 3, 6])
        self.assertEqual(client.posted["max_count"], "7")

    def test_a_permission_warning_fails_the_job(self):
        client = SlowFinalize(0, messages=[{"type": "WARN", "text": "This user has insufficient permissions to get metadata"}])
        result = client.search("| metadata type=sourcetypes index=x", tag=False)
        self.assertEqual((result.status, result.results), ("failed", []))


class SplText(unittest.TestCase):
    def test_spl_without_a_leading_pipe_gets_the_search_command(self):
        self.assertEqual(client_mod.normalize_spl("index=a | stats count"), "search index=a | stats count")
        self.assertEqual(client_mod.normalize_spl("| tstats count"), "| tstats count")
        self.assertEqual(client_mod.normalize_spl("search index=a"), "search index=a")

    def test_spl_hash_is_the_same_whatever_run_or_step_tags_the_search(self):
        client = fake_client.FakeClient(settings=support.settings())
        client.add_results(r"index=probe", [])
        hashes = []
        for run_id, step in (("20261013T1400Z", "S3"), ("20261013T1500Z", "S4")):
            client.run_id = run_id
            hashes.append(client.search("search index=probe", step=step).spl_hash)
        self.assertEqual(hashes[0], hashes[1])
        self.assertEqual(hashes[0], rows.keys.spl_hash("search index=probe"))


if __name__ == "__main__":
    unittest.main()
