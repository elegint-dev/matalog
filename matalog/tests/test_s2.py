import unittest

import support
from matalog import keys, rows, runner, writer
from matalog.steps import s2_enumerate_strata as s2
import fake_client

CS = ("matalog_json", "crowdstrike:events:sensor")
SPLUNKD = ("_internal", "splunkd")
SENT = ("s2_sentinels", "s2:sentinels")
OKTA = ("matalog_json", "OktaIM2:log")
HOUR = 3600
DAY = 86400


def source(index, sourcetype, priority=1.0):
    ident = rows.source_identity(index, sourcetype)
    ident.update(priority=priority, daily_events=1000)
    return dict(ident)


def config(client, index_pattern, sourcetype, stratum_field, version_field="", origin="seed", enabled=1, key=None):
    doc = rows.stratum_config_doc(index_pattern, sourcetype, stratum_field, version_field, origin=origin, enabled=enabled, set_at=1.0)
    if key:
        doc["_key"] = key
    client.kv["matalog_stratum_config"][doc["_key"]] = writer.kv_encode(doc)


def serve(client, name):
    fixture = fake_client.load_fixture(name)
    client.add_search(fixture["match"], fixture, name=name)
    return fixture


def new_client():
    client = fake_client.FakeClient(settings=support.settings())
    config(client, "*", CS[1], "event_simpleName", "ConfigBuild")
    config(client, "*", SPLUNKD[1], "component")
    config(client, "*", SENT[1], "f")
    for name in ("s2_listing_crowdstrike", "s2_listing_splunkd", "s2_listing_sentinels"):
        serve(client, name)
    return client


def context(client, slot=support.SLOT, sources=None, **overrides):
    ctx = support.context(client=client, now=slot + 10, **overrides)
    ctx.state["sources"] = sources if sources is not None else [source(*CS)]
    return ctx


def run_s2(ctx):
    s2.EnumerateStrata().run(ctx)
    return ctx


def commit(ctx):
    runner.open_run_record(ctx)
    runner.commit(ctx)
    return ctx


def listing_searches(ctx):
    return [c[1] for c in ctx.client.calls if c[0] == "search" and "stats count by matalog_sv" in c[1]["spl"]]


def skey(ident, field, value):
    return keys.stratum_key(ident[0], ident[1], field, value)


def stored_field_row(client, ident, field, value, name, presence="present"):
    doc = rows.fields_doc(ident[0], ident[1], field, value, name, presence=presence, observed=1, first_seen_run="20261001T0000Z")
    client.kv["matalog_fields"][doc["_key"]] = writer.kv_encode(doc)
    return doc["_key"]


class ListingSearch(unittest.TestCase):
    def test_listing_spl_is_the_search_captured_from_the_sandbox(self):
        for name, ident, field in (("s2_listing_crowdstrike", CS, "event_simpleName"), ("s2_listing_splunkd", SPLUNKD, "component")):
            fixture = fake_client.load_fixture(name)
            self.assertEqual(s2.listing_spl(ident[0], ident[1], field), fixture["spl"])

    def test_listing_eval_quotes_dotted_field_names(self):
        spl = s2.listing_spl("matalog_json", "gws:reports:login", "event.name")
        self.assertIn("isnull('event.name')", spl)
        self.assertIn("mvjoin(mvsort(mvdedup('event.name')), urldecode(\"%1F\"))", spl)

    def test_listing_runs_sampled_over_the_stratum_list_window(self):
        ctx = run_s2(context(new_client()))
        calls = listing_searches(ctx)
        self.assertEqual(len(calls), 1)
        spec = calls[0]
        self.assertEqual((spec["earliest"], spec["latest"]), ctx.windows["stratum_list"])
        self.assertEqual(spec["sample_ratio"], 100)
        self.assertEqual((spec["step"], spec["subject_key"]), ("S2", keys.source_key(*CS)))
        self.assertIn('`comment("matalog run_id=%s step=S2")`' % ctx.run_id, spec["spl"])
        cost = [r for r in ctx.summary["search_cost"] if r["step"] == "S2"]
        self.assertEqual(len(cost), 1)


class StratumConfig(unittest.TestCase):
    def test_exact_index_pattern_beats_wildcard(self):
        rows_ = [{"_key": "a", "index_pattern": "*", "src_sourcetype": "st", "stratum_field": "wild", "origin": "seed", "enabled": 1},
                 {"_key": "b", "index_pattern": "main", "src_sourcetype": "st", "stratum_field": "exact", "origin": "seed", "enabled": 1}]
        self.assertEqual(s2.resolve_config(rows_, "main", "st")["stratum_field"], "exact")
        self.assertEqual(s2.resolve_config(rows_, "other", "st")["stratum_field"], "wild")

    def test_disabled_config_rows_are_ignored(self):
        rows_ = [{"_key": "a", "index_pattern": "*", "src_sourcetype": "st", "stratum_field": "wild", "origin": "seed", "enabled": 1},
                 {"_key": "b", "index_pattern": "main", "src_sourcetype": "st", "stratum_field": "exact", "origin": "user", "enabled": 0}]
        self.assertEqual(s2.resolve_config(rows_, "main", "st")["stratum_field"], "wild")
        self.assertIsNone(s2.resolve_config([dict(rows_[1])], "main", "st"))

    def test_enabled_strings_0_and_false_disable_a_config_row(self):
        for value in ("0", "false", False):
            rows_ = [{"_key": "a", "index_pattern": "*", "src_sourcetype": "st", "stratum_field": "f", "origin": "seed", "enabled": value}]
            self.assertIsNone(s2.resolve_config(rows_, "main", "st"), value)
        self.assertIsNotNone(s2.resolve_config([{"_key": "a", "index_pattern": "*", "src_sourcetype": "st", "stratum_field": "f"}], "main", "st"))

    def test_more_literal_characters_win_among_wildcard_patterns(self):
        rows_ = [{"_key": "a", "index_pattern": "ma*", "src_sourcetype": "st", "stratum_field": "short", "origin": "user", "enabled": 1},
                 {"_key": "b", "index_pattern": "matalog_*", "src_sourcetype": "st", "stratum_field": "long", "origin": "seed", "enabled": 1}]
        self.assertEqual(s2.resolve_config(rows_, "matalog_json", "st")["stratum_field"], "long")

    def test_user_row_beats_seed_row_on_the_same_pattern(self):
        rows_ = [{"_key": "s", "index_pattern": "*", "src_sourcetype": "st", "stratum_field": "seeded", "origin": "seed", "enabled": 1},
                 {"_key": "u", "index_pattern": "*", "src_sourcetype": "st", "stratum_field": "chosen", "origin": "user", "enabled": 1}]
        self.assertEqual(s2.resolve_config(rows_, "main", "st")["stratum_field"], "chosen")

    def test_source_carries_the_stratum_and_version_field_in_force(self):
        client = new_client()
        ctx = run_s2(context(client, sources=[source(*CS), source(*OKTA)]))
        cs = ctx.staged("matalog_sources", keys.source_key(*CS))
        okta = ctx.staged("matalog_sources", keys.source_key(*OKTA))
        self.assertEqual((cs["stratum_field"], cs["version_field"]), ("event_simpleName", "ConfigBuild"))
        self.assertEqual((okta["stratum_field"], okta["version_field"]), ("__all__", ""))
        self.assertEqual(ctx.state["sources"][0]["stratum_field"], "event_simpleName")


class AllRow(unittest.TestCase):
    def test_every_source_has_an_all_row_at_level_source(self):
        ctx = run_s2(context(new_client(), sources=[source(*CS), source(*OKTA)]))
        for ident in (CS, OKTA):
            doc = ctx.staged("matalog_strata", skey(ident, "__all__", "__all__"))
            self.assertEqual((doc["level"], doc["value_kind"], doc["stratum_label"], doc["state"]), ("source", "all", "all events", "active"))

    def test_unstratified_source_issues_no_listing_and_its_all_row_is_the_target(self):
        ctx = run_s2(context(new_client(), sources=[source(*OKTA)]))
        self.assertEqual(listing_searches(ctx), [])
        all_key = skey(OKTA, "__all__", "__all__")
        self.assertEqual(list(ctx.state["strata_by_key"]), [all_key])
        self.assertEqual(ctx.state["strata_by_key"][all_key]["filter"], "")
        src = ctx.staged("matalog_sources", keys.source_key(*OKTA))
        self.assertEqual((src["strata_count"], src["strata_deferred"]), (1, 0))

    def test_all_row_of_a_stratified_source_is_never_a_target(self):
        ctx = run_s2(context(new_client()))
        self.assertNotIn(skey(CS, "__all__", "__all__"), ctx.state["strata_by_key"])
        all_doc = ctx.staged("matalog_strata", skey(CS, "__all__", "__all__"))
        self.assertEqual(all_doc["listed_events"], sum(int(r["count"]) for r in fake_client.load_fixture("s2_listing_crowdstrike")["results"]))


class Listing(unittest.TestCase):
    def test_sentinel_values_become_missing_empty_and_multi_strata(self):
        ctx = run_s2(context(new_client(), sources=[source(*SENT)]))
        multi = keys.multi_value(["a", "b"])
        expected = {multi: ("multi", "f in {a, b}", 0, 2), "__empty__": ("empty", "f is empty", 0, 1),
                    "__missing__": ("missing", "f is missing", 0, 1), "x": ("value", "f=x", 1, 1)}
        for value, (kind, label, prunable, count) in expected.items():
            doc = ctx.staged("matalog_strata", skey(SENT, "f", value))
            self.assertIsNotNone(doc, value)
            self.assertEqual((doc["value_kind"], doc["stratum_label"], doc["prunable"], doc["listed_events"], doc["level"]),
                             (kind, label, prunable, count, "stratum"))

    def test_unusable_listed_rows_are_skipped_and_recorded(self):
        client = new_client()
        client.add_results([r"isnull\('event_simpleName'\)", r"stats count by matalog_sv"], [
            {"matalog_sv": "a", "count": "5"}, {"matalog_sv": "z"}, {"matalog_sv": "y", "count": "abc"}, {"matalog_sv": "w", "count": "0"},
            {"matalog_sv": "*", "count": "3"}, {"matalog_sv": "__all__", "count": "3"}, {"count": "4"}])
        ctx = run_s2(context(client))
        self.assertEqual([e["stratum_value"] for e in ctx.state["strata"][keys.source_key(*CS)]], ["a"])
        self.assertEqual(len([r for r in ctx.summary["stratum"] if r["mode"] == "listing"]), 1)
        self.assertEqual(len([e for e in ctx.errors if e["step"] == "S2" and "listed value skipped" in e["message"]]), 6)

    def test_listing_uses_the_stored_search_sourcetype(self):
        client = new_client()
        src = rows.sources_doc(CS[0], CS[1], search_sourcetype="renamed:sensor")
        client.kv["matalog_sources"][src["_key"]] = writer.kv_encode(src)
        client.add_results([r'sourcetype="renamed:sensor"', r"stats count by matalog_sv"], [{"matalog_sv": "a", "count": "5"}])
        ctx = run_s2(context(client))
        self.assertIn('sourcetype="renamed:sensor"', listing_searches(ctx)[0]["spl"])
        self.assertEqual(ctx.state["strata"][keys.source_key(*CS)][0]["search_sourcetype"], "renamed:sensor")

    def test_sources_given_as_a_dict_are_handled_in_value_order(self):
        sources = {keys.source_key(*OKTA): source(*OKTA), keys.source_key(*CS): source(*CS)}
        ctx = run_s2(context(new_client(), sources=sources))
        self.assertEqual(list(ctx.state["strata"]), [keys.source_key(*OKTA), keys.source_key(*CS)])

    def test_kv_reads_by_key_are_chunked_at_200(self):
        class Client(object):
            def __init__(self):
                self.queries = []

            def kv_query(self, collection, query=None, fields=None):
                self.queries.append(query["source_key"]["$in"])
                return []
        client = Client()
        s2._query_by_keys(client, "matalog_strata", "source_key", ["k%03d" % i for i in range(450)])
        self.assertEqual([len(q) for q in client.queries], [200, 200, 50])

    def test_multi_value_order_from_splunk_does_not_change_the_key(self):
        reordered = keys.MULTI + keys.SEP + "b" + keys.SEP + "a"
        self.assertEqual(s2.parse_listed_value(reordered), keys.multi_value(["a", "b"]))

    def test_first_max_strata_are_active_and_the_rest_deferred_by_listed_events(self):
        ctx = run_s2(context(new_client(), sources=[source(*SPLUNKD)], **{"discovery.max_strata_per_source": 5}))
        results = fake_client.load_fixture("s2_listing_splunkd")["results"]
        ranked = sorted(((-int(r["count"]), r["matalog_sv"]) for r in results))
        active = [v for _, v in ranked[:5]]
        for _, value in ranked:
            doc = ctx.staged("matalog_strata", skey(SPLUNKD, "component", value))
            self.assertEqual(doc["state"], "active" if value in active else "deferred", value)
        targets = [e["stratum_value"] for e in ctx.state["strata"][keys.source_key(*SPLUNKD)]]
        self.assertEqual(targets, active)
        src = ctx.staged("matalog_sources", keys.source_key(*SPLUNKD))
        self.assertEqual((src["strata_count"], src["strata_deferred"]), (5, len(results) - 5))
        self.assertEqual((ctx.counts["strata_total"], ctx.counts["strata_over_cap"]), (len(results), len(results) - 5))

    def test_rate_is_scaled_by_ratio_over_the_window_and_share_sums_to_one(self):
        ctx = run_s2(context(new_client()))
        docs = [ctx.staged("matalog_strata", e["stratum_key"]) for e in ctx.state["strata"][keys.source_key(*CS)]]
        for doc in docs:
            self.assertEqual(doc["listed_sample_ratio"], 100)
            self.assertAlmostEqual(doc["rate_per_hour"], doc["listed_events"] * 100 * 3600.0 / DAY)
        self.assertAlmostEqual(sum(d["share_of_source"] for d in docs), 1.0)
        top = ctx.staged("matalog_strata", skey(CS, "event_simpleName", "ProcessRollup2"))
        self.assertAlmostEqual(top["share_of_source"], top["rate_per_hour"] / sum(d["rate_per_hour"] for d in docs))

    def test_one_listing_summary_row_per_listed_stratum(self):
        ctx = run_s2(context(new_client()))
        listed = [r for r in ctx.summary["stratum"] if r["mode"] == "listing"]
        results = fake_client.load_fixture("s2_listing_crowdstrike")["results"]
        self.assertEqual(len(listed), len(results))
        row = [r for r in listed if r["stratum_value"] == "FileDeleteInfo"][0]
        key = skey(CS, "event_simpleName", "FileDeleteInfo")
        count = [int(r["count"]) for r in results if r["matalog_sv"] == "FileDeleteInfo"][0]
        self.assertEqual((row["stratum_key"], row["row_id"], row["events_seen"], row["sample_ratio"], row["prunable"]),
                         (key, keys.k(ctx.run_id, "listing", key), count, 100, 1))
        self.assertEqual((row["earliest"], row["latest"]), tuple(float(x) for x in ctx.windows["stratum_list"]))
        self.assertIsNone(row["fields_found"])
        rows.validate(row)

    def test_first_and_last_seen_run_are_the_listing_run(self):
        ctx = commit(run_s2(context(new_client())))
        doc = ctx.client.kv["matalog_strata"][skey(CS, "event_simpleName", "DmpFileWritten")]
        self.assertEqual((doc["first_seen_run"], doc["last_seen_run"]), (ctx.run_id, ctx.run_id))

    def test_targets_are_listed_per_source_in_rank_order_and_indexed_by_stratum_key(self):
        src = source(*CS, priority=3.5)
        ctx = run_s2(context(new_client(), sources=[src]))
        key = skey(CS, "event_simpleName", "ProcessRollup2")
        entry = ctx.state["strata_by_key"][key]
        self.assertEqual(entry["stratum_key"], key)
        self.assertEqual(entry["filter"], keys.stratum_filter("event_simpleName", "ProcessRollup2"))
        self.assertEqual((entry["version_field"], entry["priority"], entry["rank"], entry["search_sourcetype"]), ("ConfigBuild", 3.5, 0, CS[1]))
        self.assertEqual(entry["state"], "active")
        listed = ctx.state["strata"][keys.source_key(*CS)]
        self.assertIs(listed[0], entry)
        self.assertEqual([e["rank"] for e in listed], list(range(len(listed))))


class Schedule(unittest.TestCase):
    def committed_client(self):
        client = new_client()
        commit(run_s2(context(client)))
        client.calls[:] = []
        return client

    def test_listing_is_skipped_until_the_interval_has_passed(self):
        client = self.committed_client()
        later = run_s2(context(client, slot=support.SLOT + HOUR))
        self.assertEqual(listing_searches(later), [])
        self.assertEqual(len(later.state["strata_by_key"]), 5)
        self.assertEqual(later.summary["stratum"], [])
        commit(later)
        client.calls[:] = []
        day = run_s2(context(client, slot=support.SLOT + DAY))
        self.assertEqual(len(listing_searches(day)), 1)

    def test_a_rerun_of_the_listing_run_lists_again(self):
        client = self.committed_client()
        again = run_s2(context(client, slot=support.SLOT))
        self.assertEqual(len(listing_searches(again)), 1)

    def test_a_later_listing_keeps_first_seen_run(self):
        client = self.committed_client()
        first = keys.run_id_of(support.SLOT)
        later = commit(run_s2(context(client, slot=support.SLOT + DAY)))
        doc = client.kv["matalog_strata"][skey(CS, "event_simpleName", "ProcessRollup2")]
        self.assertEqual((doc["first_seen_run"], doc["last_seen_run"]), (first, later.run_id))

    def test_budget_exhausted_listing_keeps_the_stored_strata_and_records_an_error(self):
        client = self.committed_client()
        ctx = run_s2(context(client, slot=support.SLOT + DAY, **{"budget.max_searches_per_cycle": 0}))
        self.assertEqual(listing_searches(ctx), [])
        self.assertEqual(len(ctx.state["strata_by_key"]), 5)
        self.assertTrue(any(e["step"] == "S2" and "BudgetExhausted" in e["message"] for e in ctx.errors))
        self.assertIsNone(ctx.staged("matalog_strata", skey(CS, "event_simpleName", "ProcessRollup2")))

    def test_failed_listing_keeps_the_stored_strata(self):
        client = self.committed_client()
        client.add_search([r"stats count by matalog_sv"], {"results": [], "job": {"status": "failed"}})
        ctx = run_s2(context(client, slot=support.SLOT + DAY))
        self.assertEqual(len(ctx.state["strata_by_key"]), 5)
        self.assertTrue(any(e["step"] == "S2" and "listing failed" in e["message"] for e in ctx.errors))
        self.assertEqual(ctx.summary["stratum"], [])
        doc = ctx.staged("matalog_strata", skey(CS, "event_simpleName", "ProcessRollup2"))
        self.assertIsNone(doc)


class Lifecycle(unittest.TestCase):
    def stored_stratum(self, client, value, last_seen_run, state="active", field="event_simpleName", listed=10):
        doc = rows.strata_doc(CS[0], CS[1], field, value, state=state, listed_events=listed, first_seen_run="20260901T0000Z", last_seen_run=last_seen_run)
        client.kv["matalog_strata"][doc["_key"]] = writer.kv_encode(doc)
        return doc["_key"]

    def test_stratum_absent_from_a_listing_keeps_its_listed_events_and_ranks_on_them(self):
        client = new_client()
        recent = keys.run_id_of(support.SLOT - 2 * DAY)
        key = self.stored_stratum(client, "RareEvent", recent, listed=3)
        ctx = run_s2(context(client))
        staged = ctx.staged("matalog_strata", key)
        self.assertEqual(sorted(staged), ["_key", "share_of_source", "state", "stratum_key"])
        self.assertEqual(staged["state"], "active")
        entry = ctx.state["strata_by_key"][key]
        self.assertEqual((entry["listed_events"], entry["last_seen_run"], entry["rank"]), (3, recent, 5))

    def test_active_strata_never_exceed_the_cap_when_stored_strata_are_missed_by_the_listing(self):
        client = new_client()
        recent = keys.run_id_of(support.SLOT - 2 * DAY)
        for value in ("OldA", "OldB", "OldC"):
            self.stored_stratum(client, value, recent, listed=10 ** 6)
        src = rows.sources_doc(CS[0], CS[1], stratum_field="event_simpleName")
        client.kv["matalog_sources"][src["_key"]] = writer.kv_encode(src)
        ctx = run_s2(context(client, **{"discovery.max_strata_per_source": 2}))
        targets = [e["stratum_value"] for e in ctx.state["strata"][keys.source_key(*CS)]]
        self.assertEqual(targets, ["OldA", "OldB"])
        self.assertEqual(ctx.staged("matalog_strata", skey(CS, "event_simpleName", "OldC"))["state"], "deferred")
        self.assertEqual(ctx.staged("matalog_sources", keys.source_key(*CS))["strata_count"], 2)
        self.assertEqual((ctx.counts["strata_total"], ctx.counts["strata_over_cap"]), (8, 6))

    def test_strata_dropped_from_the_cap_by_a_later_listing_are_demoted(self):
        client = new_client()
        commit(run_s2(context(client, **{"discovery.max_strata_per_source": 2})))
        client.add_results([r"isnull\('event_simpleName'\)", r"stats count by matalog_sv"], [{"matalog_sv": "NewOne", "count": "99999"}])
        ctx = run_s2(context(client, slot=support.SLOT + DAY, **{"discovery.max_strata_per_source": 2}))
        targets = ctx.state["strata"][keys.source_key(*CS)]
        self.assertEqual(len(targets), 2)
        self.assertEqual(targets[0]["stratum_value"], "NewOne")
        self.assertEqual(ctx.counts["strata_total"], 6)
        values = ["NewOne"] + [r["matalog_sv"] for r in fake_client.load_fixture("s2_listing_crowdstrike")["results"]]
        shares = [ctx.staged("matalog_strata", skey(CS, "event_simpleName", v))["share_of_source"] for v in values]
        self.assertAlmostEqual(sum(shares), 1.0)

    def test_retired_stratum_relisted_past_the_cap_is_deferred_and_loses_its_field_rows(self):
        client = new_client()
        key = self.stored_stratum(client, "SyntheticProcessRollup2", keys.run_id_of(support.SLOT - 2 * DAY), state="retired")
        field_key = stored_field_row(client, CS, "event_simpleName", "SyntheticProcessRollup2", "aid", presence="retired")
        ctx = run_s2(context(client, **{"discovery.max_strata_per_source": 2}))
        self.assertEqual(ctx.staged("matalog_strata", key)["state"], "deferred")
        self.assertIn(field_key, ctx.kv_deletes["matalog_fields"])
        self.assertIsNone(ctx.staged("matalog_fields", field_key))

    def test_retired_stratum_relisted_within_the_cap_returns_its_field_rows_to_unobserved(self):
        client = new_client()
        key = self.stored_stratum(client, "ProcessRollup2", keys.run_id_of(support.SLOT - 2 * DAY), state="retired")
        field_key = stored_field_row(client, CS, "event_simpleName", "ProcessRollup2", "aid", presence="retired")
        ctx = run_s2(context(client, **{"discovery.max_strata_per_source": 2}))
        self.assertEqual(ctx.staged("matalog_strata", key)["state"], "active")
        self.assertEqual(ctx.staged("matalog_fields", field_key)["presence"], "unobserved")
        self.assertNotIn(field_key, ctx.kv_deletes["matalog_fields"])

    def test_stratum_unlisted_for_retire_days_is_retired_with_its_field_rows(self):
        client = new_client()
        old = keys.run_id_of(support.SLOT - 30 * DAY)
        key = self.stored_stratum(client, "OldEvent", old)
        field_key = stored_field_row(client, CS, "event_simpleName", "OldEvent", "aid")
        ctx = commit(run_s2(context(client)))
        doc = client.kv["matalog_strata"][key]
        self.assertEqual((doc["state"], doc["retired_run"]), ("retired", ctx.run_id))
        self.assertEqual((client.kv["matalog_fields"][field_key]["presence"], client.kv["matalog_fields"][field_key]["retired_run"]), ("retired", ctx.run_id))
        self.assertNotIn(key, ctx.state["strata_by_key"])

    def test_stratum_falling_to_deferred_loses_its_field_rows(self):
        client = new_client()
        key = self.stored_stratum(client, "SyntheticProcessRollup2", keys.run_id_of(support.SLOT - 2 * DAY))
        field_key = stored_field_row(client, CS, "event_simpleName", "SyntheticProcessRollup2", "aid")
        kept = stored_field_row(client, CS, "event_simpleName", "ProcessRollup2", "aid")
        ctx = run_s2(context(client, **{"discovery.max_strata_per_source": 4}))
        self.assertEqual(ctx.staged("matalog_strata", key)["state"], "deferred")
        self.assertIn(field_key, ctx.kv_deletes["matalog_fields"])
        self.assertNotIn(kept, ctx.kv_deletes["matalog_fields"])

    def test_no_counts_without_sources(self):
        ctx = support.context(client=new_client())
        run_s2(ctx)
        self.assertEqual((ctx.counts["strata_total"], ctx.counts["strata_over_cap"]), (0, 0))
        self.assertEqual(ctx.state["strata_by_key"], {})


class Rekey(unittest.TestCase):
    def first_run(self):
        client = new_client()
        ctx = commit(run_s2(context(client)))
        field_key = stored_field_row(client, CS, "event_simpleName", "ProcessRollup2", "aid")
        client.calls[:] = []
        return client, ctx, field_key

    def rekey_to(self, client, field):
        config(client, "*", CS[1], field, "ConfigBuild")

    def test_key_change_retires_old_strata_and_field_rows_and_marks_the_source_rekeyed(self):
        client, first, field_key = self.first_run()
        self.rekey_to(client, "aid")
        client.add_results([r"isnull\('aid'\)", r"stats count by matalog_sv"], [{"matalog_sv": "host1", "count": "9"}, {"matalog_sv": "host2", "count": "4"}])
        ctx = commit(run_s2(context(client, slot=support.SLOT + HOUR)))
        old = client.kv["matalog_strata"][skey(CS, "event_simpleName", "ProcessRollup2")]
        self.assertEqual((old["state"], old["retired_run"]), ("retired", ctx.run_id))
        self.assertEqual(client.kv["matalog_fields"][field_key]["presence"], "retired")
        new = client.kv["matalog_strata"][skey(CS, "aid", "host1")]
        self.assertEqual((new["state"], new["first_seen_run"]), ("active", ctx.run_id))
        self.assertEqual(ctx.state["rekeyed_sources"], {keys.source_key(*CS): {"previous_stratum_field": "event_simpleName", "stratum_field": "aid"}})
        self.assertEqual(client.kv["matalog_sources"][keys.source_key(*CS)]["stratum_field"], "aid")
        self.assertEqual(sorted(e["stratum_value"] for e in ctx.state["strata_by_key"].values()), ["host1", "host2"])
        all_doc = client.kv["matalog_strata"][skey(CS, "__all__", "__all__")]
        self.assertEqual((all_doc["first_seen_run"], all_doc["state"]), (first.run_id, "active"))

    def test_reverting_the_key_reactivates_the_retired_rows_under_their_old_keys(self):
        client, first, field_key = self.first_run()
        self.rekey_to(client, "aid")
        client.add_results([r"isnull\('aid'\)", r"stats count by matalog_sv"], [{"matalog_sv": "host1", "count": "9"}])
        commit(run_s2(context(client, slot=support.SLOT + HOUR)))
        self.rekey_to(client, "event_simpleName")
        before = len(client.kv["matalog_strata"])
        ctx = commit(run_s2(context(client, slot=support.SLOT + 2 * HOUR)))
        self.assertEqual(len(client.kv["matalog_strata"]), before)
        doc = client.kv["matalog_strata"][skey(CS, "event_simpleName", "ProcessRollup2")]
        self.assertEqual(doc["state"], "active")
        self.assertNotIn("retired_run", doc)
        self.assertEqual(doc["first_seen_run"], first.run_id)
        self.assertEqual(client.kv["matalog_fields"][field_key]["presence"], "unobserved")
        self.assertNotIn("retired_run", client.kv["matalog_fields"][field_key])
        self.assertEqual(client.kv["matalog_strata"][skey(CS, "aid", "host1")]["state"], "retired")
        self.assertEqual(ctx.state["rekeyed_sources"][keys.source_key(*CS)]["previous_stratum_field"], "aid")

    def test_key_change_waits_for_a_successful_listing_under_the_new_key(self):
        client, first, field_key = self.first_run()
        self.rekey_to(client, "aid")
        client.add_search([r"isnull\('aid'\)", r"stats count by matalog_sv"], {"results": [], "job": {"status": "failed"}})
        ctx = run_s2(context(client, slot=support.SLOT + HOUR))
        self.assertEqual(ctx.state["rekeyed_sources"], {})
        self.assertEqual(ctx.staged("matalog_sources", keys.source_key(*CS))["stratum_field"], "event_simpleName")
        self.assertIsNone(ctx.staged("matalog_strata", skey(CS, "event_simpleName", "ProcessRollup2")))
        self.assertEqual(len(ctx.state["strata_by_key"]), 5)

    def test_removing_the_key_retires_the_strata_and_targets_the_all_row(self):
        client, first, field_key = self.first_run()
        client.kv["matalog_stratum_config"].clear()
        ctx = run_s2(context(client, slot=support.SLOT + HOUR))
        self.assertEqual(listing_searches(ctx), [])
        self.assertEqual(ctx.staged("matalog_strata", skey(CS, "event_simpleName", "ProcessRollup2"))["state"], "retired")
        self.assertEqual(list(ctx.state["strata_by_key"]), [skey(CS, "__all__", "__all__")])
        self.assertEqual(ctx.state["rekeyed_sources"][keys.source_key(*CS)]["stratum_field"], "__all__")

    def test_key_change_with_an_empty_listing_keeps_the_old_key_and_records_an_error(self):
        client, first, field_key = self.first_run()
        self.rekey_to(client, "ConfigBuild")
        client.add_results([r"isnull\('ConfigBuild'\)", r"stats count by matalog_sv"], [])
        ctx = run_s2(context(client, slot=support.SLOT + DAY))
        self.assertEqual(ctx.state["rekeyed_sources"], {})
        self.assertEqual(ctx.staged("matalog_sources", keys.source_key(*CS))["stratum_field"], "event_simpleName")
        self.assertEqual(len(ctx.state["strata_by_key"]), 5)
        self.assertIsNone(ctx.staged("matalog_strata", skey(CS, "event_simpleName", "ProcessRollup2")))
        self.assertTrue(any(e["step"] == "S2" and "key change not applied" in e["message"] for e in ctx.errors))

    def test_removing_the_key_stages_a_listing_row_for_the_all_stratum(self):
        client, first, field_key = self.first_run()
        client.kv["matalog_stratum_config"].clear()
        ctx = run_s2(context(client, slot=support.SLOT + HOUR))
        listed = [r for r in ctx.summary["stratum"] if r["mode"] == "listing"]
        self.assertEqual(len(listed), 1)
        row = listed[0]
        all_key = skey(CS, "__all__", "__all__")
        self.assertEqual((row["stratum_key"], row["stratum_field"], row["stratum_value"], row["events_seen"], row["sample_ratio"], row["row_id"]),
                         (all_key, "__all__", "__all__", 0, 1, keys.k(ctx.run_id, "listing", all_key)))
        rows.validate(row)

    def test_rerun_of_the_rekey_run_still_marks_the_source_rekeyed(self):
        client, first, field_key = self.first_run()
        self.rekey_to(client, "aid")
        client.add_results([r"isnull\('aid'\)", r"stats count by matalog_sv"], [{"matalog_sv": "host1", "count": "9"}])
        commit(run_s2(context(client, slot=support.SLOT + HOUR)))
        again = run_s2(context(client, slot=support.SLOT + HOUR))
        self.assertEqual(again.state["rekeyed_sources"][keys.source_key(*CS)]["previous_stratum_field"], "event_simpleName")


if __name__ == "__main__":
    unittest.main()
