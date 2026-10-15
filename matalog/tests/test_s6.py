import re
import unittest
from unittest import mock

import support
from matalog import client as client_mod
from matalog import budget, keys, rows, runner
from matalog.steps import s6_parse_usage as s6
import fake_client

FIXTURE = fake_client.load_fixture("s6_audit_searches")
SLOT = int(FIXTURE["latest"])
NOW = SLOT + 10
LAG = 300
LATEST = float(SLOT - LAG)
LOOKBACK = 30 * 86400
AUDIT_RE = r"stats max\(_time\) as last_time by user app search"

CROWDSTRIKE = ("matalog_json", "crowdstrike:events:sensor")
CLOUDTRAIL = ("matalog_json", "aws:cloudtrail")
SPLUNKD = ("_internal", "splunkd")
PROFILES = ("matalog_profiles", "stash")
IDLE = ("main", "idle:feed")
ALL_SOURCES = (CROWDSTRIKE, CLOUDTRAIL, SPLUNKD, PROFILES, IDLE)


def key_of(source):
    return keys.source_key(*source)


def runs_column(present):
    """Patch matalog_runs to have, or lack, the audit_watermark column."""
    table = rows.COLLECTIONS["matalog_runs"]
    columns = dict((c, t) for c, t in table.items() if c != "audit_watermark")
    if present:
        columns["audit_watermark"] = rows.EPOCH
    return mock.patch.dict(table, columns, clear=True)


def committed_run(client, slot, **values):
    run_id = keys.run_id_of(slot)
    doc = dict({"_key": run_id, "run_id": run_id, "committed": 1, "run_mode": "normal"}, **values)
    client.kv["matalog_runs"][run_id] = doc
    return doc


def context(client=None, now=NOW, sources=ALL_SOURCES, previous_run=None, **overrides):
    client = client or fake_client.FakeClient()
    if previous_run is not None:
        previous_run = committed_run(client, keys.slot_start_of(previous_run["run_id"]),
                                     **dict((k, v) for k, v in previous_run.items() if k not in ("run_id", "committed")))
    ctx = support.context(client=client, now=now, **overrides)
    ctx.state["sources"] = []
    for source in sources:
        known = {"sources_top": ["/opt/splunk/var/log/splunk/license_usage.log"]} if source == SPLUNKD else {}
        doc = rows.sources_doc(*source, state="active", **known)
        ctx.stage_kv("matalog_sources", doc)
        ctx.state["sources"].append(dict(doc))
    ctx.previous_run = previous_run
    return ctx


def audit_calls(ctx):
    return [c[1] for c in ctx.client.calls if c[0] == "search" and re.search(AUDIT_RE, c[1]["spl"])]


def serve(client, results, status="ok"):
    rows_ = [dict(r) for r in results]

    def answer(spec):
        return client_mod.JobResult(status=status, results=[dict(r) for r in rows_] if status == "ok" else [],
                                    result_count=len(rows_), spl=spec["spl"], spl_hash=spec.get("spl_hash"),
                                    earliest=spec["earliest"], latest=spec["latest"])
    client.add_search([r"index=_audit", AUDIT_RE], answer)


def audit_row(when, search, user="analyst", app="search"):
    return {"last_time": "%.6f" % when, "user": user, "app": app, "search": "'%s'" % search}


def run_s6(ctx):
    s6.ParseUsage().run(ctx)
    return ctx


def staged_time(ctx, source):
    return (ctx.staged("matalog_sources", key_of(source)) or {}).get("last_human_search_time")


class Constraints(unittest.TestCase):
    def test_audit_quotes_around_the_search_text_are_removed(self):
        self.assertEqual(s6.spl_text("'search index=main'"), "search index=main")
        self.assertEqual(s6.spl_text('search index=main'), "search index=main")

    def test_bare_and_quoted_values_are_constraints(self):
        idx, st = s6.constraints('search index=matalog_json sourcetype="crowdstrike:events:sensor" x=1')
        self.assertEqual((idx, st), ({"matalog_json"}, {"crowdstrike:events:sensor"}))

    def test_values_are_lowercased(self):
        self.assertEqual(s6.constraints("search INDEX=Main SourceType=WinEventLog"), ({"main"}, {"wineventlog"}))

    def test_simple_wildcards_are_kept_as_patterns(self):
        idx, st = s6.constraints("search index=_int* sourcetype=crowdstrike:*")
        self.assertEqual((idx, st), ({"_int*"}, {"crowdstrike:*"}))
        self.assertTrue(s6.touches(idx, st, "_internal", ["crowdstrike:events:sensor"]))

    def test_a_bare_star_constrains_nothing(self):
        self.assertEqual(s6.constraints("| tstats count where index=* by index sourcetype"), (set(), set()))

    def test_negated_terms_constrain_nothing(self):
        self.assertEqual(s6.constraints("search index!=main NOT sourcetype=foo NOT (index=bar)"), (set(), set()))

    def test_in_lists_are_constraints(self):
        idx, st = s6.constraints('search index IN (main, "matalog_json") sourcetype in ("aws:cloudtrail")')
        self.assertEqual((idx, st), ({"main", "matalog_json"}, {"aws:cloudtrail"}))

    def test_terms_from_every_clause_are_collected(self):
        idx, st = s6.constraints("search (index=a OR index=b) | append [search index=c sourcetype=d]")
        self.assertEqual((idx, st), ({"a", "b", "c"}, {"d"}))

    def test_longer_field_names_are_not_index_terms(self):
        self.assertEqual(s6.constraints("search index=_internal idx=summary orig_index=x sourcetype_x=y st=z"), ({"_internal"}, set()))

    def test_terms_inside_string_literals_are_not_constraints(self):
        self.assertEqual(s6.constraints('search index=main | eval note="index=other sourcetype=x"'), ({"main"}, set()))

    def test_a_search_without_index_or_sourcetype_touches_nothing(self):
        self.assertFalse(s6.touches(set(), set(), "main", ["anything"]))

    def test_a_missing_index_is_unconstrained_and_a_missing_sourcetype_touches_nothing(self):
        self.assertFalse(s6.touches({"matalog_json"}, set(), "matalog_json", ["aws:cloudtrail"]))
        self.assertTrue(s6.touches(set(), {"aws:cloudtrail"}, "other_index", ["aws:cloudtrail"]))
        self.assertFalse(s6.touches({"matalog_json"}, {"splunkd"}, "matalog_json", ["aws:cloudtrail"]))


class AuditSearch(unittest.TestCase):
    def test_one_audit_search_per_run_tagged_with_the_step(self):
        ctx = run_s6(context())
        calls = audit_calls(ctx)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["step"], "S6")
        self.assertIn("step=S6", calls[0]["spl"])
        self.assertIn("(info=granted OR info=completed)", calls[0]["spl"])

    def test_excluded_users_and_apps_are_filtered_in_the_search(self):
        spl = audit_calls(run_s6(context()))[0]["spl"]
        self.assertIn('NOT user IN ("svc_matalog", "splunk-system-user")', spl)
        self.assertIn('NOT app IN ("matalog")', spl)

    def test_empty_exclusion_lists_add_no_clause(self):
        spl = s6.audit_spl([], [])
        self.assertNotIn("NOT user", spl)
        self.assertNotIn("NOT app", spl)

    def test_the_search_is_bounded_in_rows(self):
        call = audit_calls(run_s6(context()))[0]
        self.assertIn("| head %d" % s6.AUDIT_MAX_ROWS, call["spl"])
        self.assertEqual(call["max_rows"], s6.AUDIT_MAX_ROWS)


class Watermark(unittest.TestCase):
    def test_first_run_reads_the_initial_lookback(self):
        call = audit_calls(run_s6(context()))[0]
        self.assertEqual((call["earliest"], call["latest"]), (LATEST - LOOKBACK, LATEST))

    def test_initial_lookback_follows_the_setting(self):
        call = audit_calls(run_s6(context(**{"usage.audit_initial_lookback_days": 2})))[0]
        self.assertEqual(call["earliest"], LATEST - 2 * 86400)

    def test_a_later_run_starts_at_the_previous_committed_watermark(self):
        previous = {"run_id": keys.run_id_of(SLOT - 3600), "committed": 1, "audit_watermark": LATEST - 7200}
        call = audit_calls(run_s6(context(previous_run=previous)))[0]
        self.assertEqual((call["earliest"], call["latest"]), (LATEST - 7200, LATEST))

    def test_a_previous_run_without_a_watermark_starts_at_its_window_end(self):
        previous = {"run_id": keys.run_id_of(SLOT - 3600), "committed": 1}
        call = audit_calls(run_s6(context(previous_run=previous)))[0]
        self.assertEqual(call["earliest"], float(SLOT - 3600 - LAG))

    def test_the_window_never_reaches_past_the_initial_lookback(self):
        previous = {"run_id": keys.run_id_of(SLOT - 3600), "committed": 1, "audit_watermark": LATEST - 90 * 86400}
        call = audit_calls(run_s6(context(previous_run=previous)))[0]
        self.assertEqual(call["earliest"], LATEST - LOOKBACK)

    def test_success_moves_the_watermark_to_the_window_end(self):
        ctx = run_s6(context())
        self.assertEqual(ctx.state["audit_watermark"], LATEST)
        self.assertEqual(ctx.state["audit"]["latest"], LATEST)

    def test_a_failed_read_keeps_the_watermark_at_the_window_start(self):
        client = fake_client.FakeClient()
        serve(client, [], status="failed")
        previous = {"run_id": keys.run_id_of(SLOT - 3600), "committed": 1, "audit_watermark": LATEST - 7200}
        ctx = run_s6(context(client=client, previous_run=previous))
        self.assertEqual(ctx.state["audit_watermark"], LATEST - 7200)
        self.assertEqual([e["subject"] for e in ctx.errors], ["audit"])
        self.assertIsNone(staged_time(ctx, CROWDSTRIKE))

    def test_an_empty_window_issues_no_search(self):
        previous = {"run_id": keys.run_id_of(SLOT), "committed": 1, "audit_watermark": LATEST}
        ctx = run_s6(context(previous_run=previous))
        self.assertEqual(audit_calls(ctx), [])
        self.assertEqual(ctx.state["audit_watermark"], LATEST)

    def test_the_watermark_is_read_past_committed_runs_that_carry_none(self):
        client = fake_client.FakeClient()
        committed_run(client, SLOT - 7200, audit_watermark=LATEST - 9000)
        committed_run(client, SLOT - 3600, run_mode="rebuild")
        committed_run(client, SLOT - 10800, audit_watermark=LATEST - 12600)
        ctx = context(client=client)
        call = audit_calls(run_s6(ctx))[0]
        self.assertEqual(call["earliest"], LATEST - 9000)

    def test_an_uncommitted_run_does_not_carry_its_watermark(self):
        client = fake_client.FakeClient()
        committed_run(client, SLOT - 3600, committed=0, audit_watermark=LATEST - 1000)
        call = audit_calls(run_s6(context(client=client)))[0]
        self.assertEqual(call["earliest"], LATEST - LOOKBACK)

    def test_without_the_runs_column_no_counter_is_set(self):
        with runs_column(False):
            ctx = run_s6(context())
        self.assertNotIn("audit_watermark", ctx.counts)
        self.assertEqual(ctx.state["audit_watermark"], LATEST)

    def test_with_the_runs_column_the_watermark_reaches_the_run_record(self):
        with runs_column(True):
            ctx = context()
            runner.open_run_record(ctx)
            run_s6(ctx)
            self.assertEqual(ctx.counts["audit_watermark"], LATEST)
            doc = runner.finalize_run_record(ctx, "ok")
            self.assertEqual(doc["audit_watermark"], LATEST)
            self.assertEqual(doc["status"], "ok")
            self.assertEqual(ctx.client.kv["matalog_runs"][ctx.run_id]["audit_watermark"], LATEST)


class LastHumanSearch(unittest.TestCase):
    def test_sources_get_the_newest_search_that_constrains_them(self):
        ctx = run_s6(context())
        # `| metadata type=sourcetypes index=matalog_json` names no sourcetype and stamps nothing; the newest
        # search naming each sourcetype wins, and splunkd takes `source=*license_usage.log*` through sources_top.
        self.assertAlmostEqual(staged_time(ctx, CROWDSTRIKE), 1791929536.007695, places=5)
        self.assertAlmostEqual(staged_time(ctx, CLOUDTRAIL), 1791927375.995408, places=5)
        self.assertAlmostEqual(staged_time(ctx, SPLUNKD), 1791932862.465484, places=5)
        self.assertIsNone(staged_time(ctx, PROFILES))
        self.assertEqual(ctx.staged("matalog_sources", key_of(CROWDSTRIKE))["last_human_search_user"], "admin")

    def test_ctx_state_sources_carry_the_same_values(self):
        ctx = run_s6(context())
        by_key = dict((d["source_key"], d) for d in ctx.state["sources"])
        self.assertAlmostEqual(by_key[key_of(SPLUNKD)]["last_human_search_time"], 1791932862.465484, places=5)
        self.assertEqual(by_key[key_of(SPLUNKD)]["last_human_search_user"], "admin")

    def test_a_source_no_search_constrains_is_left_empty(self):
        ctx = run_s6(context())
        self.assertNotIn("last_human_search_time", ctx.staged("matalog_sources", key_of(IDLE)))
        self.assertNotIn("last_human_search_time", [k for d in ctx.state["sources"] if d["source_key"] == key_of(IDLE) for k in d])

    def test_searches_by_excluded_users_or_apps_are_ignored(self):
        client = fake_client.FakeClient()
        serve(client, [audit_row(LATEST - 10, "search index=main sourcetype=idle:feed", user="svc_matalog"),
                       audit_row(LATEST - 20, "search index=main sourcetype=idle:feed", user="Splunk-System-User"),
                       audit_row(LATEST - 30, "search index=main sourcetype=idle:feed", app="matalog")])
        ctx = run_s6(context(client=client))
        self.assertIsNone(staged_time(ctx, IDLE))

    def test_a_search_without_constraints_sets_nothing(self):
        client = fake_client.FakeClient()
        serve(client, [audit_row(LATEST - 10, "| tstats count where index=* by index sourcetype"),
                       audit_row(LATEST - 20, "search error | stats count")])
        ctx = run_s6(context(client=client))
        for source in ALL_SOURCES:
            self.assertIsNone(staged_time(ctx, source))

    def test_a_sourcetype_only_search_touches_that_sourcetype_in_every_index(self):
        client = fake_client.FakeClient()
        serve(client, [audit_row(LATEST - 10, "search sourcetype=idle:*")])
        ctx = run_s6(context(client=client))
        self.assertEqual(staged_time(ctx, IDLE), LATEST - 10)
        self.assertIsNone(staged_time(ctx, CROWDSTRIKE))

    def test_the_search_time_sourcetype_name_also_matches(self):
        client = fake_client.FakeClient()
        serve(client, [audit_row(LATEST - 10, "search sourcetype=renamed:feed")])
        ctx = context(client=client)
        ctx.stage_kv("matalog_sources", rows.sources_doc(*IDLE, search_sourcetype="renamed:feed"))
        run_s6(ctx)
        self.assertEqual(staged_time(ctx, IDLE), LATEST - 10)

    def test_rows_outside_the_window_are_ignored(self):
        client = fake_client.FakeClient()
        serve(client, [audit_row(LATEST, "search index=main sourcetype=idle:feed"), audit_row(LATEST - LOOKBACK - 1, "search index=main sourcetype=idle:feed")])
        ctx = run_s6(context(client=client))
        self.assertIsNone(staged_time(ctx, IDLE))

    def test_a_stored_source_missing_from_this_run_is_updated(self):
        client = fake_client.FakeClient()
        stored = rows.sources_doc("main", "quiet:feed", state="active")
        client.kv["matalog_sources"][stored["_key"]] = dict(stored)
        serve(client, [audit_row(LATEST - 10, "search index=main sourcetype=quiet:feed", user="ana")])
        ctx = run_s6(context(client=client, sources=()))
        doc = ctx.staged("matalog_sources", stored["_key"])
        self.assertEqual((doc["last_human_search_time"], doc["last_human_search_user"]), (LATEST - 10, "ana"))
        self.assertEqual((doc["src_index"], doc["src_sourcetype"]), ("main", "quiet:feed"))

    def test_a_stored_newer_value_is_not_overwritten(self):
        client = fake_client.FakeClient()
        stored = rows.sources_doc(*IDLE, last_human_search_time=LATEST - 5, last_human_search_user="first")
        client.kv["matalog_sources"][stored["_key"]] = dict(stored)
        serve(client, [audit_row(LATEST - 10, "search index=main sourcetype=idle:feed")])
        previous = {"run_id": keys.run_id_of(SLOT - 3600), "committed": 1, "audit_watermark": LATEST - 7200}
        ctx = run_s6(context(client=client, previous_run=previous))
        self.assertIsNone(staged_time(ctx, IDLE))

    def test_a_rerun_over_the_same_window_stages_nothing(self):
        client = fake_client.FakeClient()
        serve(client, [audit_row(LATEST - 10, "search index=main sourcetype=idle:feed")])
        first = run_s6(context(client=client))
        client.kv["matalog_sources"][key_of(IDLE)] = dict(first.staged("matalog_sources", key_of(IDLE)))
        second = run_s6(context(client=client))
        self.assertIsNone(staged_time(second, IDLE))

    def test_staged_columns_are_only_the_two_audit_columns(self):
        client = fake_client.FakeClient()
        stored = rows.sources_doc("main", "quiet:feed", state="active", usage_count=4)
        client.kv["matalog_sources"][stored["_key"]] = dict(stored)
        serve(client, [audit_row(LATEST - 10, "search index=main sourcetype=quiet:feed")])
        ctx = run_s6(context(client=client, sources=()))
        doc = ctx.staged("matalog_sources", stored["_key"])
        self.assertEqual(set(doc), {"_key", "source_key", "src_index", "src_sourcetype", "last_human_search_time", "last_human_search_user"})

    def test_staged_values_reach_kv_at_commit(self):
        client = fake_client.FakeClient()
        serve(client, [audit_row(LATEST - 10, "search index=main sourcetype=idle:feed", user="ana")])
        ctx = context(client=client)
        runner.open_run_record(ctx)
        run_s6(ctx)
        runner.commit(ctx)
        doc = client.kv["matalog_sources"][key_of(IDLE)]
        self.assertEqual((doc["last_human_search_time"], doc["last_human_search_user"]), (LATEST - 10, "ana"))


def groups(spl):
    return sorted((sorted(g[0]), sorted(g[1])) for g in s6.constraint_groups(spl))


class ConstraintGroups(unittest.TestCase):
    def test_equality_comparisons_constrain_nothing(self):
        self.assertEqual(s6.constraints('index=a | where sourcetype=="x"'), ({"a"}, set()))
        self.assertEqual(s6.constraints('index=a | search x=1 | where index=="b"'), ({"a"}, set()))
        self.assertEqual(s6.constraints('| where sourcetype=="x" OR index=="y"'), (set(), set()))

    def test_a_subsearch_is_its_own_alternative(self):
        found = s6.constraint_groups("index=web | join host [search index=os sourcetype=cpu]")
        self.assertFalse(s6.touches_any(found, "web", ["access_combined"]))
        self.assertTrue(s6.touches_any(found, "os", ["cpu"]))
        self.assertFalse(s6.touches_any(found, "os", ["mem"]))

    def test_each_top_level_or_branch_is_its_own_alternative(self):
        found = s6.constraint_groups("index=a OR sourcetype=b")
        self.assertFalse(s6.touches_any(found, "a", ["c"]))
        self.assertTrue(s6.touches_any(found, "z", ["b"]))
        self.assertFalse(s6.touches_any(found, "z", ["c"]))

    def test_or_binds_tighter_than_implicit_and(self):
        self.assertEqual(groups("index=a sourcetype=x OR sourcetype=y"), [(["a"], ["x"]), (["a"], ["y"])])

    def test_parenthesized_pairs_do_not_cross(self):
        found = s6.constraint_groups("(index=a sourcetype=x) OR (index=b sourcetype=y)")
        self.assertTrue(s6.touches_any(found, "a", ["x"]))
        self.assertFalse(s6.touches_any(found, "a", ["y"]))
        self.assertFalse(s6.touches_any(found, "b", ["x"]))

    def test_a_negated_group_negates_every_term_in_it(self):
        found = s6.constraint_groups("index=main NOT (sourcetype=a OR sourcetype=b)")
        self.assertEqual(groups("index=main NOT (sourcetype=a OR sourcetype=b)"), [(["main"], [])])

    def test_later_pipes_narrow_every_alternative(self):
        self.assertEqual(groups('index=a OR index=b | search sourcetype="x"'), [(["a"], ["x"]), (["b"], ["x"])])

    def test_destination_arguments_are_not_constraints(self):
        self.assertEqual(groups("index=a | collect index=summary sourcetype=stash"), [(["a"], [])])
        self.assertEqual(groups('index=a | eval index="b"'), [(["a"], [])])

    def test_a_star_in_a_value_list_leaves_the_dimension_open(self):
        self.assertEqual(groups("index IN (*, main) sourcetype=x"), [([], ["x"])])

    def test_parenthesized_or_values_are_constraints(self):
        self.assertEqual(groups("index=(a OR b) foo"), [(["a", "b"], [])])

    def test_escaped_quotes_and_semicolons_end_a_value(self):
        self.assertEqual(groups('index=\\"main\\"'), [(["main"], [])])
        self.assertEqual(groups("index=a;sourcetype=b"), [(["a"], [])])

    def test_only_star_is_a_wildcard(self):
        self.assertFalse(s6.touches({"a?"}, set(), "ab", ["x"]))
        self.assertFalse(s6.touches({"a[bc]"}, set(), "ab", ["x"]))
        self.assertTrue(s6.touches({"a[b"}, {"x"}, "a[b", ["x"]))
        self.assertTrue(s6.touches(set(), {"weird?type*"}, "i", ["weird?type:v2"]))

    def test_alternatives_are_bounded(self):
        spl = " ".join("(index=i%d OR sourcetype=s%d)" % (n, n) for n in range(8))
        self.assertLessEqual(len(s6.constraint_groups(spl)), s6.MAX_GROUPS)


class RowCap(unittest.TestCase):
    def capped(self, kept_times):
        """The AUDIT_MAX_ROWS oldest texts the capped search returns, ending at kept_times[-1]."""
        kept = [audit_row(t, "search index=nomatch") for t in kept_times]
        kept += [audit_row(kept_times[-1], "search index=nomatch")] * (s6.AUDIT_MAX_ROWS - len(kept))
        return kept

    def test_the_search_keeps_the_oldest_texts(self):
        self.assertIn("| sort 0 last_time | head %d" % s6.AUDIT_MAX_ROWS, s6.audit_spl([], []))

    def test_a_truncated_read_holds_the_watermark_at_or_before_every_dropped_text(self):
        client = fake_client.FakeClient()
        # Texts past the cap have latest times no older than the newest kept one.
        dropped = [LATEST - 3000, LATEST - 10]
        serve(client, self.capped([LATEST - 9000, LATEST - 3000]))
        ctx = run_s6(context(client=client))
        self.assertEqual(ctx.state["audit"]["truncated"], 1)
        self.assertLessEqual(ctx.state["audit_watermark"], min(dropped))
        self.assertGreater(ctx.state["audit_watermark"], LATEST - LOOKBACK)
        self.assertEqual([e["subject"] for e in ctx.errors], ["audit"])

    def test_kept_texts_of_a_truncated_read_are_still_matched(self):
        client = fake_client.FakeClient()
        rows_ = self.capped([LATEST - 9000, LATEST - 3000])
        rows_[0] = audit_row(LATEST - 9000, "search index=main sourcetype=idle:feed")
        serve(client, rows_)
        ctx = run_s6(context(client=client))
        self.assertEqual(staged_time(ctx, IDLE), LATEST - 9000)

    def test_a_truncated_read_that_cannot_move_advances_to_the_window_end(self):
        client = fake_client.FakeClient()
        serve(client, self.capped([LATEST - LOOKBACK]))
        ctx = run_s6(context(client=client))
        self.assertEqual(ctx.state["audit_watermark"], LATEST)


class ReplayedRuns(unittest.TestCase):
    def test_a_run_that_finalized_failed_does_not_carry_its_watermark(self):
        client = fake_client.FakeClient()
        committed_run(client, SLOT - 7200, status="ok", audit_watermark=LATEST - 9000)
        committed_run(client, SLOT - 3600, status="failed", committed_attempt=1, audit_watermark=LATEST - 3600)
        call = audit_calls(run_s6(context(client=client)))[0]
        self.assertEqual(call["earliest"], LATEST - 9000)


class CommitStep(runner.Step):
    name = "S10"
    label = "commit"
    required = True

    def run(self, ctx):
        runner.commit(ctx)


class RunOnce(unittest.TestCase):
    def test_a_budget_ceiling_keeps_the_watermark_at_the_window_start(self):
        ctx = context()
        with mock.patch.object(ctx.client, "search", side_effect=budget.BudgetExhausted("searches", "S6", "audit")):
            status = runner.run_steps(ctx, [s6.ParseUsage()])
        self.assertEqual(status, "partial")
        self.assertEqual(ctx.state["audit_watermark"], LATEST - LOOKBACK)
        self.assertEqual([(e["step"], e["subject"]) for e in ctx.errors], [("S6", "audit")])
        self.assertIsNone(staged_time(ctx, IDLE))

    def test_consecutive_runs_read_adjoining_windows_and_store_the_watermark(self):
        settings = support.settings()
        client = fake_client.FakeClient(settings=settings)
        stored = rows.sources_doc(*IDLE, state="active")
        client.kv["matalog_sources"][stored["_key"]] = dict(stored)
        serve(client, [audit_row(LATEST - 10, "search index=main sourcetype=idle:feed", user="ana")])
        with runs_column(True):
            first = runner.run_once(settings, client, now=NOW, steps=[s6.ParseUsage(), CommitStep()])
            second = runner.run_once(settings, client, now=NOW + 3600, steps=[s6.ParseUsage(), CommitStep()])
        calls = [c[1] for c in client.calls if c[0] == "search" and re.search(AUDIT_RE, c[1]["spl"])]
        self.assertEqual([(c["earliest"], c["latest"]) for c in calls], [(LATEST - LOOKBACK, LATEST), (LATEST, LATEST + 3600)])
        self.assertEqual((first["audit_watermark"], second["audit_watermark"]), (LATEST, LATEST + 3600))
        self.assertEqual((first["status"], second["status"]), ("ok", "ok"))
        doc = client.kv["matalog_sources"][stored["_key"]]
        self.assertEqual((doc["last_human_search_time"], doc["last_human_search_user"]), (LATEST - 10, "ana"))


if __name__ == "__main__":
    unittest.main()
