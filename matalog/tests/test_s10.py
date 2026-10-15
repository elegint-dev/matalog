import collections
import io
import sys
import unittest

import support
from matalog import keys, rows, runner, writer
from matalog.steps import s10_commit
from matalog.steps.s10_commit import Commit
import fake_client

sys.path.insert(0, support.BIN)
import matalog_profiler  # noqa: E402

CS = ("matalog_json", "crowdstrike:events:sensor")
STRATUM = CS + ("event_simpleName", "ProcessRollup2")
OTHER = CS + ("event_simpleName", "FileDeleteInfo")
DAY = 86400


def run_id_days_ago(days):
    return keys.run_id_of(support.SLOT - int(days * DAY))


def source_key(name):
    return keys.source_field_key(CS[0], CS[1], name)


def meaning(name, revision, text, status="current", is_current=1, author="ana", created_at=1791000000.0):
    field_key = source_key(name)
    doc = rows.meanings_doc(field_key, revision, src_index=CS[0], src_sourcetype=CS[1], field_name=name, is_current=is_current,
                            text=text, author=author, created_at=created_at, status=status)
    return doc


def field(ident, name, **values):
    values.setdefault("presence", "present")
    return rows.fields_doc(*ident, field_name=name, **values)


def store(client, collection, docs):
    for doc in docs:
        client.kv[collection][doc["_key"]] = writer.kv_encode(doc)


def open_context(client=None, run_mode="normal", **overrides):
    ctx = support.context(client=client, run_mode=run_mode, **overrides)
    runner.open_run_record(ctx)
    return ctx


def commit(ctx):
    Commit().run(ctx)
    return ctx


class HumanMirror(unittest.TestCase):
    def test_staged_field_rows_carry_the_current_meaning_of_their_source_level_key(self):
        ctx = open_context()
        store(ctx.client, "matalog_meanings", [meaning("user", 1, "old text", status="superseded", is_current=0), meaning("user", 2, "the actor")])
        ctx.stage_kv("matalog_fields", field(CS + (keys.ALL, keys.ALL), "user", cur_disc_run_id=ctx.run_id, cur_disc_count=3))
        ctx.stage_kv("matalog_fields", field(STRATUM, "user", cur_disc_run_id=ctx.run_id, cur_disc_count=3))
        commit(ctx)
        for ident in (CS + (keys.ALL, keys.ALL), STRATUM):
            doc = ctx.client.kv_get("matalog_fields", keys.field_key(*ident, "user"))
            self.assertEqual((doc["meaning_human"], doc["meaning_human_author"], doc["meaning_human_revision"], doc["meaning_human_time"]),
                             ("the actor", "ana", 2, 1791000000.0))

    def test_stored_rows_sharing_the_source_level_key_get_the_mirror_without_being_staged_by_a_step(self):
        ctx = open_context()
        store(ctx.client, "matalog_fields", [field(OTHER, "user"), field(STRATUM, "host")])
        store(ctx.client, "matalog_meanings", [meaning("user", 1, "the actor")])
        commit(ctx)
        self.assertEqual(ctx.client.kv_get("matalog_fields", keys.field_key(*OTHER, "user"))["meaning_human"], "the actor")
        self.assertNotIn("meaning_human", ctx.client.kv_get("matalog_fields", keys.field_key(*STRATUM, "host")))
        self.assertNotIn(keys.field_key(*STRATUM, "host"), ctx.kv["matalog_fields"])

    def test_a_row_whose_meaning_is_gone_has_its_mirror_cleared_to_revision_zero(self):
        ctx = open_context()
        store(ctx.client, "matalog_fields", [field(STRATUM, "user", meaning_human="stale", meaning_human_author="bo", meaning_human_revision=3,
                                                   meaning_human_time=5.0)])
        commit(ctx)
        doc = ctx.client.kv_get("matalog_fields", keys.field_key(*STRATUM, "user"))
        self.assertEqual(doc["meaning_human_revision"], 0)
        self.assertNotIn("meaning_human", doc)
        self.assertNotIn("meaning_human_author", doc)

    def test_the_mirror_is_read_after_the_steps_ran_so_a_revision_written_meanwhile_wins(self):
        ctx = open_context()
        store(ctx.client, "matalog_meanings", [meaning("user", 1, "first")])
        ctx.stage_kv("matalog_fields", field(STRATUM, "user", meaning_human="first", meaning_human_revision=1))
        store(ctx.client, "matalog_meanings", [meaning("user", 1, "first", status="superseded", is_current=0), meaning("user", 2, "second")])
        commit(ctx)
        self.assertEqual(ctx.client.kv_get("matalog_fields", keys.field_key(*STRATUM, "user"))["meaning_human_revision"], 2)

    def test_a_revision_saved_during_the_commit_row_write_reaches_the_staged_rows_in_the_kv_batch(self):
        ctx = open_context()
        store(ctx.client, "matalog_meanings", [meaning("user", 1, "first")])
        ctx.stage_kv("matalog_fields", field(STRATUM, "user", cur_disc_run_id=ctx.run_id, cur_disc_count=3))
        original = ctx.summary_writer.write

        def write_then_revise(rows_in, **kwargs):
            report = original(rows_in, **kwargs)
            store(ctx.client, "matalog_meanings", [meaning("user", 1, "first", status="superseded", is_current=0), meaning("user", 2, "second")])
            return report
        ctx.summary_writer.write = write_then_revise
        commit(ctx)
        doc = ctx.client.kv_get("matalog_fields", keys.field_key(*STRATUM, "user"))
        self.assertEqual((doc["meaning_human"], doc["meaning_human_revision"]), ("second", 2))
        self.assertIsInstance(ctx.kv_writer, writer.KVWriter)

    def test_a_failed_meanings_read_still_commits_and_leaves_stored_mirrors_alone(self):
        ctx = open_context()
        store(ctx.client, "matalog_fields", [field(STRATUM, "user", meaning_human="kept", meaning_human_revision=1)])
        original = ctx.client.kv_query

        def failing(collection, *args, **kwargs):
            if collection == "matalog_meanings":
                raise fake_client.client_mod.ClientError("KV unavailable", status=503)
            return original(collection, *args, **kwargs)
        ctx.client.kv_query = failing
        commit(ctx)
        self.assertTrue(ctx.committed)
        self.assertEqual(ctx.client.kv_get("matalog_fields", keys.field_key(*STRATUM, "user"))["meaning_human"], "kept")
        self.assertTrue(any(e["step"] == "S10" and "KV unavailable" in e["message"] for e in ctx.errors))


class MeaningStatus(unittest.TestCase):
    def test_a_meaning_whose_source_level_field_row_is_absent_is_orphaned(self):
        ctx = open_context()
        store(ctx.client, "matalog_meanings", [meaning("gone", 1, "x", status="superseded", is_current=0), meaning("gone", 2, "y")])
        commit(ctx)
        self.assertEqual(ctx.client.kv_get("matalog_meanings", keys.k(source_key("gone"), 2))["status"], "orphaned")
        self.assertEqual(ctx.client.kv_get("matalog_meanings", keys.k(source_key("gone"), 1))["status"], "superseded")

    def test_an_orphaned_meaning_whose_field_row_returns_is_current_again_and_its_text_is_untouched(self):
        ctx = open_context()
        store(ctx.client, "matalog_meanings", [meaning("back", 1, "words", status="orphaned")])
        ctx.stage_kv("matalog_fields", field(CS + (keys.ALL, keys.ALL), "back", cur_disc_run_id=ctx.run_id))
        commit(ctx)
        doc = ctx.client.kv_get("matalog_meanings", keys.k(source_key("back"), 1))
        self.assertEqual((doc["status"], doc["text"], doc["author"], doc["revision"], doc["created_at"]), ("current", "words", "ana", 1, 1791000000.0))

    def test_a_meaning_whose_field_row_this_run_deletes_is_orphaned(self):
        ctx = open_context()
        key = keys.field_key(*CS, keys.ALL, keys.ALL, "f")
        store(ctx.client, "matalog_fields", [field(CS + (keys.ALL, keys.ALL), "f")])
        store(ctx.client, "matalog_meanings", [meaning("f", 1, "t")])
        ctx.delete_kv("matalog_fields", key)
        commit(ctx)
        self.assertEqual(ctx.client.kv_get("matalog_meanings", keys.k(source_key("f"), 1))["status"], "orphaned")

    def test_meaning_revisions_beyond_the_retention_are_deleted_oldest_first(self):
        ctx = open_context(**{"retention.meaning_revisions": 2})
        store(ctx.client, "matalog_fields", [field(CS + (keys.ALL, keys.ALL), "f")])
        store(ctx.client, "matalog_meanings", [meaning("f", r, "t%d" % r, status="superseded", is_current=0) for r in (1, 2, 3)] + [meaning("f", 4, "t4")])
        commit(ctx)
        left = sorted(d["revision"] for d in ctx.client.kv_query("matalog_meanings"))
        self.assertEqual(left, [3, 4])

    def test_a_rebuild_never_writes_matalog_meanings(self):
        ctx = open_context(run_mode="rebuild", **{"retention.meaning_revisions": 1})
        store(ctx.client, "matalog_meanings", [meaning("gone", 1, "x", status="superseded", is_current=0), meaning("gone", 2, "y")])
        before = ctx.client.kv_query("matalog_meanings")
        commit(ctx)
        self.assertEqual(ctx.client.kv_query("matalog_meanings"), before)
        self.assertFalse([c for c in ctx.client.calls if c[0] in ("kv_batch_save", "kv_delete") and c[1] == "matalog_meanings"])


class Retention(unittest.TestCase):
    def test_run_records_beyond_the_retention_count_are_deleted_oldest_first_and_this_run_is_kept(self):
        ctx = open_context(**{"retention.run_retention_count": 3})
        store(ctx.client, "matalog_runs", [rows.runs_doc(run_id_days_ago(h / 24.0), committed=1) for h in (1, 2, 3, 4)])
        commit(ctx)
        self.assertEqual(sorted(d["_key"] for d in ctx.client.kv_query("matalog_runs")), sorted([ctx.run_id, run_id_days_ago(1 / 24.0), run_id_days_ago(2 / 24.0)]))

    def test_unobserved_field_rows_past_the_retention_are_deleted_unless_they_have_meaning_or_usage(self):
        ctx = open_context(**{"retention.unobserved_field_days": 30})
        old, recent = run_id_days_ago(31), run_id_days_ago(5)
        store(ctx.client, "matalog_fields", [
            field(STRATUM, "old_unobserved", presence="unobserved", last_seen_run=old),
            field(STRATUM, "recent", presence="unobserved", last_seen_run=recent),
            field(STRATUM, "present", presence="present", last_seen_run=old),
            field(STRATUM, "used", presence="unobserved", last_seen_run=old, usage_count=2),
            field(STRATUM, "meant", presence="unobserved", last_seen_run=old),
            field(CS + (keys.ALL, keys.ALL), "declared", presence="declared_only", updated_run_id=old),
            field(CS + (keys.ALL, keys.ALL), "still_declared", presence="declared_only", updated_run_id=recent),
        ])
        store(ctx.client, "matalog_meanings", [meaning("meant", 1, "kept by its meaning")])
        commit(ctx)
        left = sorted(d["field_name"] for d in ctx.client.kv_query("matalog_fields"))
        self.assertEqual(left, ["meant", "present", "recent", "still_declared", "used"])

    def test_a_field_row_observed_again_this_run_is_judged_as_written_and_kept(self):
        ctx = open_context()
        store(ctx.client, "matalog_fields", [field(STRATUM, "back", presence="unobserved", last_seen_run=run_id_days_ago(40))])
        ctx.stage_kv("matalog_fields", field(STRATUM, "back", presence="present", last_seen_run=ctx.run_id, cur_disc_run_id=ctx.run_id, cur_disc_count=4))
        commit(ctx)
        doc = ctx.client.kv_get("matalog_fields", keys.field_key(*STRATUM, "back"))
        self.assertEqual((doc["presence"], doc["cur_disc_count"]), ("present", 4))

    def test_retired_strata_past_the_retention_are_deleted_with_their_field_rows(self):
        ctx = open_context(**{"retention.stratum_retire_days": 30})
        store(ctx.client, "matalog_strata", [
            rows.strata_doc(*STRATUM, state="retired", retired_run=run_id_days_ago(31)),
            rows.strata_doc(*OTHER, state="retired", retired_run=run_id_days_ago(3)),
            rows.strata_doc(*CS, keys.ALL, keys.ALL, state="retired", retired_run=run_id_days_ago(60)),
        ])
        store(ctx.client, "matalog_fields", [field(STRATUM, "a", presence="retired"), field(STRATUM, "b", presence="retired"), field(OTHER, "a", presence="retired")])
        commit(ctx)
        self.assertEqual(sorted(d["stratum_value"] for d in ctx.client.kv_query("matalog_strata")), ["FileDeleteInfo", keys.ALL])
        self.assertEqual([d["stratum_value"] for d in ctx.client.kv_query("matalog_fields")], ["FileDeleteInfo"])
        self.assertEqual((ctx.state["retention"]["matalog_strata"], ctx.state["retention"]["matalog_fields"]), (1, 2))

    def test_a_retired_stratum_reactivated_this_run_is_kept(self):
        ctx = open_context()
        store(ctx.client, "matalog_strata", [rows.strata_doc(*STRATUM, state="retired", retired_run=run_id_days_ago(45))])
        ctx.stage_kv("matalog_strata", rows.strata_doc(*STRATUM, state="active", retired_run=None, last_seen_run=ctx.run_id))
        commit(ctx)
        self.assertEqual(ctx.client.kv_get("matalog_strata", keys.stratum_key(*STRATUM))["state"], "active")


    def test_a_declared_only_row_restaged_this_run_is_kept_although_its_stored_update_is_old(self):
        ctx = open_context(**{"retention.unobserved_field_days": 30})
        ident = CS + (keys.ALL, keys.ALL)
        store(ctx.client, "matalog_fields", [field(ident, "decl", presence="declared_only", declared=1, updated_run_id=run_id_days_ago(40))])
        ctx.stage_kv("matalog_fields", rows.kv_doc("matalog_fields", keys.field_key(*ident, "decl"), presence="declared_only", declared=1,
                                                   origin="regex_extract"))
        commit(ctx)
        self.assertEqual(ctx.state["retention"]["matalog_fields"], 0)
        self.assertEqual(ctx.client.kv_get("matalog_fields", keys.field_key(*ident, "decl"))["updated_run_id"], ctx.run_id)

    def test_field_rows_of_a_stratum_reactivated_this_run_are_kept(self):
        ctx = open_context(**{"retention.stratum_retire_days": 30, "retention.unobserved_field_days": 30})
        store(ctx.client, "matalog_strata", [rows.strata_doc(*STRATUM, state="retired", retired_run=run_id_days_ago(20), last_seen_run=run_id_days_ago(20))])
        store(ctx.client, "matalog_fields", [field(STRATUM, "a", presence="retired", retired_run=run_id_days_ago(20), last_seen_run=run_id_days_ago(35))])
        ctx.stage_kv("matalog_strata", rows.strata_doc(*STRATUM, state="active", retired_run=None, last_seen_run=ctx.run_id))
        ctx.stage_kv("matalog_fields", rows.kv_doc("matalog_fields", keys.field_key(*STRATUM, "a"), presence="unobserved", retired_run=None))
        commit(ctx)
        self.assertEqual(ctx.state["retention"]["matalog_fields"], 0)
        self.assertEqual(ctx.client.kv_get("matalog_fields", keys.field_key(*STRATUM, "a"))["presence"], "unobserved")

    def test_unobserved_rows_without_last_seen_run_age_by_their_last_update(self):
        ctx = open_context(**{"retention.unobserved_field_days": 30})
        store(ctx.client, "matalog_fields", [field(STRATUM, "stale", presence="unobserved", updated_run_id=run_id_days_ago(31)),
                                             field(STRATUM, "fresh", presence="unobserved", updated_run_id=run_id_days_ago(3))])
        commit(ctx)
        self.assertEqual([d["field_name"] for d in ctx.client.kv_query("matalog_fields")], ["fresh"])

    def test_a_retired_stratum_not_listed_for_the_retire_age_is_deleted_even_when_retired_recently(self):
        ctx = open_context(**{"retention.stratum_retire_days": 30})
        store(ctx.client, "matalog_strata", [rows.strata_doc(*STRATUM, state="retired", retired_run=run_id_days_ago(15), last_seen_run=run_id_days_ago(45)),
                                             rows.strata_doc(*OTHER, state="retired", retired_run=run_id_days_ago(15), last_seen_run=run_id_days_ago(16))])
        commit(ctx)
        self.assertEqual([d["stratum_value"] for d in ctx.client.kv_query("matalog_strata")], ["FileDeleteInfo"])

    def test_a_run_record_awaiting_replay_is_never_deleted_by_retention(self):
        ctx = open_context(**{"retention.run_retention_count": 3})
        waiting = run_id_days_ago(4 / 24.0)
        store(ctx.client, "matalog_runs", [rows.runs_doc(waiting, committed=0, committed_attempt=1, status="ok")] +
              [rows.runs_doc(run_id_days_ago(h / 24.0), committed=1, committed_attempt=1, status="ok") for h in (1, 2, 3)])
        commit(ctx)
        left = set(d["_key"] for d in ctx.client.kv_query("matalog_runs"))
        self.assertEqual(left, set([waiting, run_id_days_ago(1 / 24.0), ctx.run_id]))

class CommitProtocol(unittest.TestCase):
    def test_the_step_writes_the_commit_row_last_then_the_kv_batches_then_committed(self):
        ctx = open_context()
        ctx.stage(rows.source_row(ctx.run, *CS, events_last_cycle=1, daily_events=2))
        ctx.stage_kv("matalog_sources", rows.sources_doc(*CS, state="active"))
        commit(ctx)
        self.assertEqual(ctx.client.collected_rows()[-1]["kind"], "commit")
        self.assertEqual(ctx.client.kv_get("matalog_sources", keys.source_key(*CS))["updated_run_id"], ctx.run_id)
        run = ctx.client.kv_get("matalog_runs", ctx.run_id)
        self.assertEqual((run["committed"], run["committed_attempt"]), (1, 1))

    def test_retention_deletes_are_applied_only_after_the_commit_row(self):
        ctx = open_context(**{"retention.run_retention_count": 1})
        store(ctx.client, "matalog_runs", [rows.runs_doc("20261012T0000Z", committed=1)])
        ctx.client.collect_failures = 1
        with self.assertRaises(writer.WriteError):
            commit(ctx)
        self.assertIsNotNone(ctx.client.kv_get("matalog_runs", "20261012T0000Z"))


class SlotGuard(unittest.TestCase):
    XML = ("<input><server_host>sh</server_host><server_uri>https://127.0.0.1:8089</server_uri><session_key>abc</session_key>"
           "<configuration><stanza name=\"matalog_profiler://default\"><param name=\"run_mode\">normal</param></stanza></configuration></input>")

    def launch(self, client, now):
        calls = []
        original = matalog_profiler.runner.run_once

        def fake_run_once(settings, client_, now=None, run_mode="normal"):
            calls.append((now, run_mode))
            return {"run_id": keys.run_id_for(now, 3600), "attempt": 1, "status": "ok"}
        matalog_profiler.runner.run_once = fake_run_once
        try:
            code = matalog_profiler.run_modular_input(io.StringIO(self.XML), client=client, now=now)
        finally:
            matalog_profiler.runner.run_once = original
        return code, calls

    def test_a_launch_whose_slot_already_has_a_committed_run_exits_without_work(self):
        client = fake_client.FakeClient(load_all=False)
        run_id = keys.run_id_of(support.SLOT)
        client.kv["matalog_runs"][run_id] = {"_key": run_id, "run_id": run_id, "committed": 1, "status": "ok"}
        code, calls = self.launch(client, support.SLOT + 1200)
        self.assertEqual((code, calls), (0, []))

    def test_a_launch_whose_slot_has_no_committed_run_runs_one_attempt_of_that_slot(self):
        client = fake_client.FakeClient(load_all=False)
        run_id = keys.run_id_of(support.SLOT)
        client.kv["matalog_runs"][run_id] = {"_key": run_id, "run_id": run_id, "committed": 0, "status": "failed"}
        previous = keys.run_id_of(support.SLOT - 3600)
        client.kv["matalog_runs"][previous] = {"_key": previous, "run_id": previous, "committed": 1}
        code, calls = self.launch(client, support.SLOT + 1200)
        self.assertEqual((code, calls), (0, [(support.SLOT + 1200.0, "normal")]))

    def test_a_committed_flag_read_back_as_true_counts_as_committed(self):
        client = fake_client.FakeClient(load_all=False)
        run_id = keys.run_id_of(support.SLOT)
        client.kv["matalog_runs"][run_id] = {"_key": run_id, "committed": "true"}
        self.assertTrue(matalog_profiler.slot_committed(client, support.settings(), support.SLOT + 5))
        self.assertFalse(matalog_profiler.slot_committed(client, support.settings(), support.SLOT + 3605))


# Rebuild derivation.

def listing_row(run, ident, events, ratio=100, window=DAY):
    """A committed kind=stratum mode=listing row as S2 writes it."""
    latest = float(keys.slot_start_of(run["run_id"]) - 300)
    ident_cols = rows.stratum_identity(*ident)
    values = dict(ident_cols)
    values.update(kind="stratum", run_id=run["run_id"], attempt=run["attempt"], profiled_as=run["profiled_as"],
                  row_id=keys.k(run["run_id"], "listing", ident_cols["stratum_key"]), mode="listing", earliest=latest - window, latest=latest,
                  sample_ratio=ratio, events_seen=int(events), prunable=keys.prunable(ident_cols["stratum_value"]), version_top=[], version_top_counts=[],
                  sid="s")
    row = collections.OrderedDict((c, values.get(c)) for c in rows.columns_for(kind="stratum"))
    return rows.validate(row, kind="stratum")


def captured_listing(run, sourcetype="crowdstrike:events:sensor"):
    """Listing rows built from the listing captured on the sandbox."""
    data = fake_client.load_fixture("s10_stratum_listings")["sources"][sourcetype]
    out = []
    for result in data["listing"]:
        ident = (data["src_index"], sourcetype, data["stratum_field"], result["matalog_sv"])
        out.append(listing_row(run, ident, int(result["count"]), ratio=data["sample_ratio"], window=data["latest"] - data["earliest"]))
    return out


def as_results(summary_rows):
    return [fake_client.parse_stash_line(writer.encode_line(r, keys.slot_start_of(r["run_id"]))) for r in summary_rows]


def disc_field(run, ident, name, count, events=100, top=None, samples=None, guess="string"):
    top = top or []
    full = bool(top or samples)
    extra = {"top_values": [v for v, _ in top], "top_counts": [str(c) for _, c in top], "sample_values": samples or [v for v, _ in top]} if full else {}
    return rows.field_row(run, "discovery", "full" if full else "slim", *ident, field_name=name, earliest=1.0, latest=2.0, sample_ratio=1,
                          events_in_stratum=events, count=count, distinct=len(top) or 1, distinct_exact=1, numeric_count=0, type_guess=guess,
                          identifier=0, values_hash="0" * 32, sid="s", **extra)


def rebuild(stratum_rows=(), field_rows=(), client=None, **overrides):
    s = support.settings(**overrides)
    client = client or fake_client.FakeClient(settings=s, load_all=False)
    client.settings = s
    client.add_results([r"kind=source", r"dedup 2 source_key"], [])
    client.add_results([r"kind=stratum", r"dedup 2 stratum_key mode"], as_results(stratum_rows))
    client.add_results([r"kind=field", r"dedup 2 field_key mode"], as_results(field_rows))
    steps = [runner.RebuildStep(), Commit()]
    record = runner.run_once(s, client, now=support.SLOT, run_mode="rebuild", steps=steps)
    return record, client


RUN_A = {"run_id": "20261012T1400Z", "attempt": 1, "profiled_as": "svc_matalog"}
RUN_B = {"run_id": "20261013T1300Z", "attempt": 1, "profiled_as": "svc_matalog"}


class RebuildStrata(unittest.TestCase):
    def test_rebuild_derives_state_rate_and_share_from_the_latest_listing(self):
        record, client = rebuild(captured_listing(RUN_B), **{"discovery.max_strata_per_source": 3})
        self.assertEqual(record["status"], "ok")
        strata = dict((d["stratum_value"], d) for d in client.kv_query("matalog_strata"))
        self.assertEqual([strata[v]["state"] for v in ("ProcessRollup2", "ProcessHandleOpDetectInfo", "DmpFileWritten", "FileDeleteInfo", "SyntheticProcessRollup2")],
                         ["active", "active", "active", "deferred", "deferred"])
        top = strata["ProcessRollup2"]
        self.assertEqual((top["listed_events"], top["listed_sample_ratio"], top["last_seen_run"]), (78, 100, RUN_B["run_id"]))
        self.assertAlmostEqual(top["rate_per_hour"], 78 * 100 * 3600.0 / DAY)
        self.assertAlmostEqual(top["share_of_source"], 78.0 / (78 + 32 + 27 + 13 + 4))
        self.assertAlmostEqual(sum(d["share_of_source"] for d in strata.values()), 1.0)

    def test_rate_per_hour_divides_by_the_configured_listing_window_not_the_row_window(self):
        rows_in = [listing_row(RUN_B, STRATUM, 60, ratio=10, window=DAY / 2)]
        derived = s10_commit.listing_strata(support.settings(**{"discovery.stratum_list_window_seconds": DAY}), rows_in)
        self.assertAlmostEqual(derived[keys.stratum_key(*STRATUM)]["rate_per_hour"], 60 * 10 * 3600.0 / DAY)

    def test_a_listing_row_is_never_read_as_a_discovery_snapshot(self):
        record, client = rebuild(captured_listing(RUN_B))
        for doc in client.kv_query("matalog_strata"):
            self.assertNotIn("cur_run_id", doc)
            self.assertNotIn("last_discovered_run", doc)

    def test_a_value_absent_from_the_newest_listing_keeps_its_last_listing_until_the_retire_age_then_is_retired_and_deleted(self):
        newest = {"run_id": "20261013T1300Z", "attempt": 1, "profiled_as": "svc"}
        recent = {"run_id": "20261012T1300Z", "attempt": 1, "profiled_as": "svc"}
        ancient = {"run_id": "20260901T1300Z", "attempt": 1, "profiled_as": "svc"}
        rows_in = [listing_row(newest, STRATUM, 50), listing_row(recent, OTHER, 7), listing_row(ancient, CS + ("event_simpleName", "Old"), 9)]
        record, client = rebuild(rows_in, **{"retention.stratum_retire_days": 30})
        strata = dict((d["stratum_value"], d) for d in client.kv_query("matalog_strata"))
        self.assertEqual((strata["FileDeleteInfo"]["state"], strata["FileDeleteInfo"]["listed_events"], strata["FileDeleteInfo"]["last_seen_run"]),
                         ("active", 7, recent["run_id"]))
        self.assertNotIn("Old", strata)
        derived = s10_commit.listing_strata(support.settings(**{"retention.stratum_retire_days": 30}), rows_in)
        old = derived[keys.stratum_key(*CS + ("event_simpleName", "Old"))]
        self.assertEqual((old["state"], old["retired_run"], old["last_seen_run"]), ("retired", newest["run_id"], ancient["run_id"]))

    def test_strata_of_a_previous_stratum_field_are_retired_and_their_field_rows_follow(self):
        old_key = CS + ("ConfigBuild", "1007")
        rows_in = [listing_row(RUN_A, old_key, 40), listing_row(RUN_B, STRATUM, 50)]
        fields_in = [disc_field(RUN_A, old_key, "a", 5)]
        record, client = rebuild(rows_in, fields_in)
        old = client.kv_get("matalog_strata", keys.stratum_key(*old_key))
        self.assertEqual((old["state"], old["retired_run"]), ("retired", RUN_B["run_id"]))
        self.assertEqual(client.kv_get("matalog_fields", keys.field_key(*old_key, "a"))["presence"], "retired")
        self.assertIsNone(client.kv_get("matalog_fields", keys.source_field_key(CS[0], CS[1], "a")))


class RebuildRollups(unittest.TestCase):
    def test_rollup_rows_are_recomputed_from_the_children_of_active_strata(self):
        third = CS + ("event_simpleName", "DmpFileWritten")
        listing = [listing_row(RUN_B, STRATUM, 50), listing_row(RUN_B, OTHER, 30), listing_row(RUN_B, third, 10)]
        fields_in = [disc_field(RUN_B, STRATUM, "user", 40, events=100, top=[("a", 30), ("b", 10)]),
                     disc_field(RUN_A, OTHER, "user", 10, events=50, top=[("b", 8), ("c", 2)]),
                     disc_field(RUN_B, third, "user", 9, events=9, top=[("z", 9)], guess="integer")]
        record, client = rebuild(listing, fields_in, **{"discovery.max_strata_per_source": 2})
        doc = client.kv_get("matalog_fields", keys.source_field_key(CS[0], CS[1], "user"))
        self.assertEqual((doc["is_rollup"], doc["rollup_strata"], doc["level"], doc["presence"]), (1, 2, "source", "present"))
        self.assertEqual((doc["cur_disc_count"], doc["cur_disc_events"], doc["cur_disc_run_id"]), (50, 150, RUN_B["run_id"]))
        self.assertAlmostEqual(doc["cur_disc_coverage"], 50 / 150.0)
        self.assertEqual((doc["top_values"], doc["top_counts"]), (["a", "b", "c"], ["30", "18", "2"]))
        self.assertEqual((doc["sample_values"], doc["type_guess"], doc["origin"]), (["a", "b", "c"], "string", "unknown"))
        self.assertIsNone(client.kv_get("matalog_fields", keys.field_key(*third, "user")))

    def test_rebuilt_field_rows_get_the_human_mirror(self):
        client = fake_client.FakeClient(load_all=False)
        store(client, "matalog_meanings", [meaning("user", 1, "the actor")])
        record, client = rebuild([listing_row(RUN_B, STRATUM, 50)], [disc_field(RUN_B, STRATUM, "user", 4)], client=client)
        self.assertEqual(client.kv_get("matalog_fields", keys.field_key(*STRATUM, "user"))["meaning_human"], "the actor")
        self.assertEqual(client.kv_get("matalog_fields", keys.source_field_key(CS[0], CS[1], "user"))["meaning_human_revision"], 1)


if __name__ == "__main__":
    unittest.main()
