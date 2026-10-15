import copy
import json
import logging
import unittest

import support
from matalog import keys, rows
from matalog.steps import s5_read_config as s5
import fake_client
from matalog import runner

SD = ("_internal", "splunkd")
SA = ("_internal", "splunkd_access")
SC = ("_internal", "splunkd_conf")
CS = ("matalog_json", "crowdstrike:events:sensor")
RUN_ID = "20261013T1400Z"


def load(name):
    return fake_client.load_fixture(name)


def entry(name, app, sharing="app", **content):
    return {"name": name, "acl": {"app": app, "owner": "nobody", "sharing": sharing}, "content": dict(content)}


def make_ctx(sources=(SD, SA, SC, CS), fields=None, sandbox_view=True, **overrides):
    """A context over the service-account captures, with sources in ctx.state and staged field rows."""
    ctx = support.context(**overrides)
    if sandbox_view:
        ctx.client.conf["props"] = load("s5_conf_props")
        ctx.client.conf["transforms"] = load("s5_conf_transforms")
        ctx.client.conf["fields"] = load("s5_conf_fields")
        ctx.state["apps_local"] = load("s5_apps_local")
    ctx.state["sources"] = [rows.sources_doc(*ident, state="active") for ident in sources]
    for ident, names in (fields or {}).items():
        for name in names:
            stage_field(ctx, ident, name)
    return ctx


def stage_field(ctx, ident, name, stratum_field=keys.ALL, stratum_value=keys.ALL):
    return ctx.stage_kv("matalog_fields", rows.fields_doc(*ident, stratum_field, stratum_value, name, presence="present", observed=1,
                                                         first_seen_run=RUN_ID, last_seen_run=RUN_ID))


def store_field(ctx, ident, name, **values):
    doc = rows.fields_doc(*ident, keys.ALL, keys.ALL, name, presence="present", observed=1, **values)
    ctx.client.kv["matalog_fields"][doc["_key"]] = dict(doc)
    return doc


def run(ctx):
    step = s5.ReadConfig()
    step.run(ctx)
    return step


def field(ctx, ident, name, stratum_field=keys.ALL, stratum_value=keys.ALL):
    return ctx.kv["matalog_fields"].get(keys.field_key(*ident, stratum_field, stratum_value, name))


def decl_key(app, conf_file, stanza, attribute):
    return keys.k(app, conf_file, stanza, attribute)


def decl(ctx, app, conf_file, stanza, attribute):
    return ctx.kv["matalog_declarations"].get(decl_key(app, conf_file, stanza, attribute))


def props_entry(entries, name, app):
    return [e for e in entries if e["name"] == name and e["acl"]["app"] == app][0]


def searches(ctx):
    return [c[1] for c in ctx.client.calls if c[0] == "search"]


class RegexParsing(unittest.TestCase):

    def test_lookbehinds_escaped_parens_and_character_classes_are_not_groups(self):
        names, complete = s5.regex_fields(r"(?<=x)(?<!y)\(?<no>\)[(?<nope>)](?P<yes>a)(?'also'b)", lambda name: None)
        self.assertEqual(names, ["yes", "also"])
        self.assertTrue(complete)

    def test_key_and_value_groups_are_dynamic_and_underscore_groups_internal(self):
        names, complete = s5.regex_fields(r"(?<_KEY_1>\w+)=(?<_VAL_1>\S+) (?<_pre_msg>.+) (?<Message>.+)", lambda name: None)
        self.assertEqual(names, ["Message"])
        self.assertFalse(complete)

    def test_regex_with_possessive_quantifiers_is_scanned_without_compiling(self):
        names, _ = s5.regex_fields(r"^(?<a>\S++)\s*+(?<b>[^\]]*+)", lambda name: None)
        self.assertEqual(names, ["a", "b"])


class Declarations(unittest.TestCase):

    def setUp(self):
        self.ctx = make_ctx(fields={SD: ["log_level"], SA: ["clientip"]})
        self.step = run(self.ctx)

    def test_extract_declares_its_named_groups(self):
        doc = decl(self.ctx, "search", "props", "splunkd", "EXTRACT-fields")
        self.assertEqual(doc["fields_declared"], ["log_level", "component", "thread_id", "thread_name", "event_message"])
        self.assertEqual((doc["origin_class"], doc["parse_status"], doc["stanza_kind"], doc["src_sourcetype"]), ("regex_extract", "parsed", "sourcetype", "splunkd"))

    def test_report_expands_modular_regexes_to_the_names_splunk_extracts(self):
        doc = decl(self.ctx, "system", "props", "splunkd_access", "REPORT-access")
        observed = set(r["field"] for r in load("s5_observed_splunkd_access")["rows"])
        expected = {"clientip", "ident", "user", "req_time", "method", "uri", "uri_domain", "uri_path", "root", "file", "uri_query",
                    "version", "status", "bytes", "referer", "referer_domain", "useragent", "cookie", "other", "spent"}
        self.assertEqual(set(doc["fields_declared"]), expected)
        self.assertTrue(expected <= observed)
        self.assertEqual(doc["parse_status"], "parsed")

    def test_report_with_static_format_is_parsed(self):
        doc = decl(self.ctx, "system", "props", "syslog", "REPORT-syslog")
        self.assertEqual((doc["fields_declared"], doc["parse_status"]), (["process", "pid"], "parsed"))

    def test_report_mixing_static_and_dynamic_format_is_partial(self):
        doc = decl(self.ctx, "system", "props", "snort", "REPORT-tcp")
        self.assertEqual((doc["fields_declared"], doc["parse_status"]), (["src_ip", "src_port", "dest_ip", "dest_port"], "partial"))

    def test_report_with_delims_and_no_fields_is_opaque(self):
        doc = decl(self.ctx, "system", "props", "PerformanceMonitor", "REPORT-MESSAGE")
        self.assertEqual((doc["fields_declared"], doc["parse_status"]), ([], "opaque"))

    def test_report_with_delims_and_fields_declares_the_fields(self):
        names, complete = s5.transform_fields({"DELIMS": '"|"', "FIELDS": '"user", "action",status'}, lambda name: None)
        self.assertEqual((names, complete), (["user", "action", "status"], True))

    def test_index_time_transforms_with_meta_declare_indexed_fields(self):
        doc = decl(self.ctx, "system", "props", "novell_groupwise", "TRANSFORMS-nov")
        self.assertEqual(doc["origin_class"], "indexed")
        self.assertEqual(doc["fields_declared"][:3], ["msgtype", "originuserid", "messageid"])
        self.assertEqual(doc["parse_status"], "parsed")
        dynamic = decl(self.ctx, "splunk_internal_metrics", "props", "splunk_metrics_log", "TRANSFORMS-metricslog")
        self.assertEqual((dynamic["origin_class"], dynamic["parse_status"]), ("indexed", "opaque"))

    def test_transforms_that_write_no_field_are_not_declarations(self):
        stanza = "source::.../var/log/splunk/metrics.log(.\\d+)?"
        self.assertIsNone(decl(self.ctx, "splunk_internal_metrics", "props", stanza, "TRANSFORMS-metricslogclone"))
        self.assertIsNone(decl(self.ctx, "system", "props", "splunk_help", "TRANSFORMS-help"))

    def test_indexed_extractions_without_field_names_are_opaque_and_with_them_parsed(self):
        doc = decl(self.ctx, "system", "props", "splunkd_conf", "INDEXED_EXTRACTIONS")
        self.assertEqual((doc["origin_class"], doc["fields_declared"], doc["parse_status"]), ("indexed", [], "opaque"))
        parsed = s5.parse_props_attribute("INDEXED_EXTRACTIONS", "csv", {"FIELD_NAMES": "a,b, c"}, lambda name: None)
        self.assertEqual(parsed, ("INDEXED_EXTRACTIONS", "indexed", ["a", "b", "c"], "parsed"))

    def test_fieldalias_declares_the_new_names(self):
        self.assertEqual(s5.fieldalias_fields("src AS src_ip \"dst host\" ASNEW dest"), (["src_ip", "dest"], True))

    def test_eval_declares_its_target(self):
        stanza = "source::.../var/log/splunk/etcd*.log*"
        doc = decl(self.ctx, "system", "props", stanza, "EVAL-log_level")
        self.assertEqual((doc["fields_declared"], doc["origin_class"], doc["stanza_kind"]), (["log_level"], "eval", "source"))

    def test_lookup_declares_output_names_with_aliases(self):
        self.assertEqual(s5.lookup_fields("dmc_assets host AS h OUTPUTNEW machine AS m, search_group", None), (["m", "search_group"], True))

    def test_lookup_without_output_declares_the_lookup_fields_less_its_inputs(self):
        self.assertEqual(s5.lookup_fields("assets host", {"fields_list": "host, machine, search_group"}), (["machine", "search_group"], True))
        self.assertEqual(s5.lookup_fields("assets host", {"filename": "assets.csv"}), ([], False))

    def test_kv_mode_rows_name_no_fields(self):
        doc = decl(self.ctx, "system", "props", "crowdstrike:events:sensor", "KV_MODE")
        self.assertEqual((doc["origin_class"], doc["fields_declared"], doc["parse_status"]), ("json_auto", [], "opaque"))

    def test_fields_conf_indexed_declares_the_stanza_as_an_indexed_field_for_every_source(self):
        doc = decl(self.ctx, "system", "fields", "host", "INDEXED")
        self.assertEqual((doc["origin_class"], doc["fields_declared"], doc["stanza_kind"]), ("indexed", ["host"], "default"))
        self.assertEqual(len(doc["applies_to_source_keys"]), 4)

    def test_declaration_rows_carry_identity_version_and_bookkeeping(self):
        doc = decl(self.ctx, "search", "props", "splunkd", "EXTRACT-fields")
        self.assertEqual(doc["_key"], decl_key("search", "props", "splunkd", "EXTRACT-fields"))
        self.assertEqual(doc["decl_key"], doc["_key"])
        self.assertEqual((doc["owner"], doc["sharing"], doc["app_version"]), ("nobody", "global", "10.4.3"))
        self.assertEqual((doc["first_seen_run"], doc["last_seen_run"]), (RUN_ID, RUN_ID))
        self.assertEqual(doc["applies_to_source_keys"], [keys.source_key(*SD)])
        rows.validate(doc, collection="matalog_declarations", partial=True)

    def test_raw_value_is_truncated_to_4096_characters(self):
        ctx = make_ctx(sources=(SD,))
        ctx.client.conf["props"].append(entry("splunkd", "zeta", **{"EVAL-long": "x" * 5000}))
        run(ctx)
        self.assertEqual(len(decl(ctx, "zeta", "props", "splunkd", "EVAL-long")["raw_value"]), 4096)

    def test_datamodel_calculations_are_declarations_that_apply_to_no_source(self):
        ctx = make_ctx(sources=(SD,), fields={SD: ["actor_roles"]})
        run(ctx)
        found = [d for d in ctx.kv["matalog_declarations"].values() if d["conf_file"] == "datamodels"]
        self.assertTrue(found)
        self.assertTrue(all(d["origin_class"] == "datamodel" and d["applies_to_source_keys"] == [] for d in found))
        self.assertNotEqual(field(ctx, SD, "actor_roles")["origin"], "datamodel")


class StanzaMatching(unittest.TestCase):

    def test_source_patterns_match_whole_paths_with_splunk_wildcards(self):
        pattern = s5.pattern_regex("source::.../splunkd.log(.\\d+)?")
        self.assertTrue(pattern.match("/opt/splunk/var/log/splunk/splunkd.log"))
        self.assertTrue(pattern.match("/opt/splunk/var/log/splunk/splunkd.log.1"))
        self.assertFalse(pattern.match("/opt/splunk/var/log/splunk/splunkd_access.log"))
        self.assertTrue(s5.pattern_regex("(?i)source::.../SPLUNKD.LOG").match("/x/splunkd.log"))
        self.assertFalse(s5.pattern_regex("source::/opt/*.log").match("/opt/a/b.log"))

    def test_source_stanzas_apply_to_sources_whose_paths_match(self):
        ctx = make_ctx(sources=(SD, SA), fields={SD: ["mine"], SA: ["mine"]})
        props = ctx.client.conf["props"]
        props_entry(props, "source::.../splunkd.log(.\\d+)?", "system")["content"]["EVAL-mine"] = "1"
        run(ctx)
        doc = decl(ctx, "system", "props", "source::.../splunkd.log(.\\d+)?", "EVAL-mine")
        self.assertEqual((doc["stanza_kind"], doc["applies_to_source_keys"]), ("source", [keys.source_key(*SD)]))
        self.assertEqual(field(ctx, SD, "mine")["origin"], "eval")
        self.assertEqual(field(ctx, SA, "mine")["origin"], "kv_auto")

    def test_host_stanzas_apply_to_sources_with_a_matching_host(self):
        ctx = make_ctx(sources=(SD, CS), fields={SD: ["mine"], CS: ["mine"]})
        ctx.client.conf["props"].append(entry("host::3ccd20e3a5*", "zeta", **{"EVAL-mine": "1"}))
        ctx.client.conf["props"].append(entry("host::elsewhere", "zeta", **{"EVAL-other": "1"}))
        run(ctx)
        self.assertEqual(decl(ctx, "zeta", "props", "host::3ccd20e3a5*", "EVAL-mine")["applies_to_source_keys"],
                         [keys.source_key(*SD), keys.source_key(*CS)])
        self.assertEqual(decl(ctx, "zeta", "props", "host::elsewhere", "EVAL-other")["applies_to_source_keys"], [])

    def test_sourcetype_stanzas_match_the_sourcetype_exactly(self):
        ctx = make_ctx(sources=(SD, SA))
        ctx.client.conf["props"].append(entry("SPLUNKD", "zeta", **{"EVAL-x": "1"}))
        run(ctx)
        self.assertEqual(decl(ctx, "zeta", "props", "SPLUNKD", "EVAL-x")["applies_to_source_keys"], [])

    def test_rename_sets_search_sourcetype_and_search_time_config_follows_the_new_name(self):
        ctx = make_ctx(sources=(SC,), fields={SC: ["x", "data.task", "foo"]})
        props = ctx.client.conf["props"]
        props_entry(props, "splunkd_conf", "system")["content"]["rename"] = "conf_renamed"
        props.append(entry("conf_renamed", "zeta", **{"EXTRACT-x": "(?<x>\\d+)"}))
        run(ctx)
        self.assertEqual(ctx.kv["matalog_sources"][keys.source_key(*SC)]["search_sourcetype"], "conf_renamed")
        self.assertEqual(field(ctx, SC, "x")["origin"], "regex_extract")
        self.assertIn(keys.source_key(*SC), decl(ctx, "system", "props", "splunkd_conf", "INDEXED_EXTRACTIONS")["applies_to_source_keys"])
        self.assertEqual(decl(ctx, "system", "props", "splunkd_conf", "KV_MODE")["applies_to_source_keys"], [])
        self.assertEqual(field(ctx, SC, "foo")["origin"], "kv_auto")

    def test_search_sourcetype_equals_the_sourcetype_without_rename(self):
        ctx = make_ctx(sources=(SD,))
        run(ctx)
        self.assertEqual(ctx.kv["matalog_sources"][keys.source_key(*SD)]["search_sourcetype"], "splunkd")


class Inheritance(unittest.TestCase):
    """The admin capture shows each app's stanza merged with what it inherits."""

    def setUp(self):
        self.ctx = make_ctx(sources=(SD, SA), fields={SD: ["log_level", "machine"], SA: ["clientip", "machine"]}, sandbox_view=False)
        self.ctx.state["apps_local"] = load("apps_local")
        run(self.ctx)

    def test_an_attribute_repeated_by_inheritance_is_one_declaration_of_its_owner(self):
        self.assertIsNotNone(decl(self.ctx, "system", "props", "splunkd_access", "REPORT-access"))
        self.assertIsNone(decl(self.ctx, "splunk_monitoring_console", "props", "splunkd_access", "REPORT-access"))
        self.assertIsNotNone(decl(self.ctx, "search", "props", "splunkd", "EXTRACT-fields"))
        self.assertIsNone(decl(self.ctx, "splunk_monitoring_console", "props", "splunkd", "EXTRACT-fields"))

    def test_inherited_repeats_raise_no_conflict(self):
        self.assertEqual(field(self.ctx, SA, "clientip")["origin_conflict"], 0)
        self.assertEqual(field(self.ctx, SD, "log_level")["origin_app"], "search")

    def test_an_app_scoped_declaration_is_kept_for_its_app(self):
        doc = field(self.ctx, SA, "machine")
        self.assertEqual((doc["origin"], doc["origin_app"]), ("lookup", "splunk_monitoring_console"))


class Origins(unittest.TestCase):

    def test_the_first_candidate_in_endpoint_order_wins_and_candidates_keep_that_order(self):
        ctx = make_ctx(sources=(SD,), fields={SD: ["log_level"]})
        props = ctx.client.conf["props"]
        index = props.index(props_entry(props, "splunkd", "search"))
        props.insert(index, entry("splunkd", "zeta", **{"EXTRACT-mine": "(?<log_level>\\w+)"}))
        run(ctx)
        doc = field(ctx, SD, "log_level")
        first = decl_key("zeta", "props", "splunkd", "EXTRACT-mine")
        second = decl_key("search", "props", "splunkd", "EXTRACT-fields")
        self.assertEqual(doc["origin_candidates"][:2], [first, second])
        self.assertEqual((doc["origin_decl_key"], doc["origin_app"], doc["origin_stanza"]), (first, "zeta", "props:splunkd:EXTRACT-mine"))

    def test_conflict_is_set_only_when_more_than_one_app_names_the_field(self):
        ctx = make_ctx(sources=(SD,), fields={SD: ["log_level", "component"]})
        props = ctx.client.conf["props"]
        props_entry(props, "splunkd", "search")["content"]["EXTRACT-again"] = "(?<component>\\w+)"
        props.append(entry("splunkd", "zeta", **{"EVAL-log_level": "lower(log_level)"}))
        run(ctx)
        self.assertEqual(len(field(ctx, SD, "component")["origin_candidates"]), 2)
        self.assertEqual(field(ctx, SD, "component")["origin_conflict"], 0)
        self.assertEqual(field(ctx, SD, "log_level")["origin_conflict"], 1)
        self.assertEqual(field(ctx, SD, "log_level")["origin"], "eval")

    def test_json_kv_mode_gives_json_auto_and_absent_kv_mode_gives_kv_auto(self):
        ctx = make_ctx(sources=(SD, CS), fields={SD: ["foo"], CS: ["aid"]})
        run(ctx)
        self.assertEqual(field(ctx, CS, "aid")["origin"], "json_auto")
        self.assertEqual(field(ctx, SD, "foo")["origin"], "kv_auto")
        self.assertEqual((field(ctx, SD, "foo")["declared"], field(ctx, SD, "foo")["origin_decl_key"]), (0, ""))

    def test_fields_conf_makes_default_fields_indexed_without_declared_only_rows(self):
        ctx = make_ctx(sources=(SD,), fields={SD: ["host", "date_hour"]})
        run(ctx)
        self.assertEqual(field(ctx, SD, "host")["origin"], "indexed")
        self.assertEqual(field(ctx, SD, "host")["origin_stanza"], "fields:host:INDEXED")
        self.assertIsNone(field(ctx, SD, "evtlog_account"))

    def test_a_field_walklex_lists_and_the_probe_confirms_is_indexed(self):
        ctx = make_ctx(sources=(SC,), fields={SC: ["data.task", "component"]})
        run(ctx)
        self.assertEqual(field(ctx, SC, "data.task")["origin"], "indexed")
        self.assertEqual(field(ctx, SC, "component")["origin"], "indexed")

    def test_a_field_with_no_declaration_no_auto_kv_and_no_index_entry_is_unknown(self):
        ctx = make_ctx(sources=(SC,), fields={SC: ["foo"]})
        run(ctx)
        self.assertEqual(field(ctx, SC, "foo")["origin"], "unknown")

    def test_stratum_rows_get_the_origin_of_the_source(self):
        ctx = make_ctx(sources=(SD,))
        stage_field(ctx, SD, "log_level", "component", "Metrics")
        run(ctx)
        self.assertEqual(field(ctx, SD, "log_level", "component", "Metrics")["origin"], "regex_extract")

    def test_every_present_row_gets_an_origin(self):
        names = [r["field"] for r in load("fieldsummary_splunkd_discovery")["results"]]
        ctx = make_ctx(sources=(SD,), fields={SD: names})
        run(ctx)
        staged = [d for d in ctx.kv["matalog_fields"].values() if d.get("presence") == "present"]
        self.assertEqual(len(staged), len(set(names)))
        self.assertTrue(all(d["origin"] in rows.ORIGINS for d in staged))

    def test_a_declared_field_no_discovery_saw_becomes_a_declared_only_source_row(self):
        ctx = make_ctx(sources=(SD,), fields={SD: ["log_level", "component"]})
        run(ctx)
        doc = field(ctx, SD, "thread_name")
        self.assertEqual((doc["presence"], doc["observed"], doc["declared"], doc["level"], doc["is_rollup"]), ("declared_only", 0, 1, "source", 0))
        self.assertEqual(doc["origin"], "regex_extract")
        self.assertIsNone(field(ctx, SD, "evtlog_id"))

    def test_a_field_seen_only_in_a_stratum_gets_no_declared_only_row(self):
        ctx = make_ctx(sources=(SD,))
        stage_field(ctx, SD, "thread_name", "component", "Metrics")
        run(ctx)
        self.assertIsNone(field(ctx, SD, "thread_name"))


class Changes(unittest.TestCase):

    def test_a_different_winner_sets_origin_changed_run(self):
        ctx = make_ctx(sources=(SD,))
        store_field(ctx, SD, "log_level", origin="regex_extract", origin_decl_key="0" * 32, origin_changed_run="20261001T0000Z")
        run(ctx)
        self.assertEqual(field(ctx, SD, "log_level")["origin_changed_run"], RUN_ID)

    def test_a_different_origin_sets_origin_changed_run(self):
        ctx = make_ctx(sources=(SD,))
        store_field(ctx, SD, "foo", origin="unknown", origin_decl_key="")
        run(ctx)
        self.assertEqual(field(ctx, SD, "foo")["origin_changed_run"], RUN_ID)

    def test_a_first_origin_sets_no_origin_changed_run(self):
        ctx = make_ctx(sources=(SD,), fields={SD: ["log_level"]})
        run(ctx)
        self.assertNotIn("origin_changed_run", field(ctx, SD, "log_level"))

    def test_a_stored_row_whose_origin_is_unchanged_is_not_staged(self):
        first = make_ctx(sources=(SD,))
        store_field(first, SD, "log_level")
        run(first)
        resolved = dict(first.client.kv["matalog_fields"][keys.source_field_key(*SD, "log_level")])
        resolved.update(field(first, SD, "log_level"))
        second = make_ctx(sources=(SD,))
        second.client.kv["matalog_fields"][resolved["_key"]] = resolved
        run(second)
        self.assertIsNone(field(second, SD, "log_level"))

    def test_a_staged_row_with_an_unchanged_origin_carries_no_origin_changed_run(self):
        first = make_ctx(sources=(SD,))
        store_field(first, SD, "log_level")
        run(first)
        second = make_ctx(sources=(SD,), fields={SD: ["log_level"]})
        stored = dict(first.client.kv["matalog_fields"][keys.source_field_key(*SD, "log_level")])
        stored.update(field(first, SD, "log_level"))
        second.client.kv["matalog_fields"][stored["_key"]] = stored
        run(second)
        self.assertNotIn("origin_changed_run", field(second, SD, "log_level"))

    def test_config_apps_change_sets_config_apps_changed_run(self):
        ctx = make_ctx(sources=(SD, SA))
        for ident, apps in ((SD, ["search@10.4.3", "system@10.4.3"]), (SA, ["system@10.4.2"])):
            doc = rows.sources_doc(*ident, config_apps=apps, config_apps_changed_run="20261001T0000Z")
            ctx.client.kv["matalog_sources"][doc["_key"]] = dict(doc)
        run(ctx)
        unchanged = ctx.kv["matalog_sources"][keys.source_key(*SD)]
        changed = ctx.kv["matalog_sources"][keys.source_key(*SA)]
        self.assertEqual(unchanged["config_apps"], ["search@10.4.3", "system@10.4.3"])
        self.assertNotIn("config_apps_changed_run", unchanged)
        self.assertEqual((changed["config_apps"], changed["config_apps_changed_run"]), (["system@10.4.3"], RUN_ID))

    def test_a_first_config_read_sets_no_config_apps_changed_run(self):
        ctx = make_ctx(sources=(SD,))
        run(ctx)
        self.assertNotIn("config_apps_changed_run", ctx.kv["matalog_sources"][keys.source_key(*SD)])


class Searches(unittest.TestCase):

    def test_one_walklex_and_one_probe_per_index_counted_under_s5(self):
        ctx = make_ctx(fields={SD: ["log_level"], SC: ["data.task"], CS: ["aid"]})
        run(ctx)
        spls = [s["spl"] for s in searches(ctx)]
        self.assertEqual(len(spls), 4)
        self.assertEqual(sum(1 for s in spls if "| walklex index=" in s), 2)
        self.assertEqual(sum(1 for s in spls if s.startswith("| tstats ")), 2)
        self.assertEqual([r["step"] for r in ctx.summary["search_cost"]], ["S5"] * 4)
        self.assertEqual([s["earliest"] for s in searches(ctx)], [ctx.windows["source_day"][0]] * 4)

    def test_the_probe_carries_only_walklex_listed_row_names_not_declared_in_fields_conf(self):
        ctx = make_ctx(sources=(SD, SC), fields={SD: ["log_level", "host", "date_hour", "foo"], SC: ["data.task"]})
        run(ctx)
        probe = [s["spl"] for s in searches(ctx) if s["spl"].startswith("| tstats ")][0]
        self.assertIn('dc("data.task")', probe)
        self.assertIn('dc("log_level")', probe)
        for name in ("host", "date_hour", "foo", "component"):
            self.assertNotIn('dc("%s")' % name, probe)

    def test_an_exhausted_budget_keeps_stored_origins_and_marks_new_rows_unknown(self):
        ctx = make_ctx(sources=(SC,), fields={SC: ["foo"]}, **{"budget.max_searches_per_cycle": 10})
        store_field(ctx, SC, "data.task", origin="indexed", origin_decl_key="")
        run(ctx)
        self.assertEqual(searches(ctx), [])
        self.assertTrue(any(e["step"] == "S5" for e in ctx.errors))
        self.assertIsNone(field(ctx, SC, "data.task"))
        self.assertEqual(field(ctx, SC, "foo")["origin"], "unknown")


    def test_an_unsearched_index_keeps_source_stanza_matches_origins_and_config_apps(self):
        stanza = "source::.../splunkd.log(.\\d+)?"

        def context(**overrides):
            ctx = make_ctx(sources=(SD,), **overrides)
            props_entry(ctx.client.conf["props"], stanza, "system")["content"]["EVAL-mine"] = "1"
            return ctx
        first = context(fields={SD: ["mine"]})
        run(first)
        second = context(**{"budget.max_searches_per_cycle": 10})
        for collection in ("matalog_fields", "matalog_sources", "matalog_declarations"):
            for key, doc in first.kv[collection].items():
                second.client.kv[collection][key] = copy.deepcopy(dict(doc))
        run(second)
        self.assertEqual(searches(second), [])
        self.assertIsNone(field(second, SD, "mine"))
        source = second.kv["matalog_sources"][keys.source_key(*SD)]
        self.assertEqual(source["config_apps"], first.kv["matalog_sources"][keys.source_key(*SD)]["config_apps"])
        self.assertNotIn("config_apps_changed_run", source)
        self.assertEqual(decl(second, "system", "props", stanza, "EVAL-mine")["applies_to_source_keys"], [keys.source_key(*SD)])

    def test_a_failed_or_raising_search_is_an_error_and_the_step_continues(self):
        ctx = make_ctx(sources=(SC, CS), fields={SC: ["foo"], CS: ["aid"]})
        ctx.client.add_search(r"^\| walklex index=\"?_internal\"?", {"results": [], "job": {"status": "failed"}})
        ctx.client.add_search(r"^\| walklex index=\"?matalog_json\"?", lambda spec: (_ for _ in ()).throw(RuntimeError("down")))
        store_field(ctx, SC, "data.task", origin="indexed", origin_decl_key="")
        run(ctx)
        self.assertEqual(len([e for e in ctx.errors if e["step"] == "S5"]), 2)
        self.assertIsNone(field(ctx, SC, "data.task"))
        self.assertEqual(field(ctx, CS, "aid")["origin"], "json_auto")


class Retention(unittest.TestCase):

    def stored_declaration(self, ctx, attribute, last_seen_run, conf_file="props"):
        doc = rows.declarations_doc("gone_app", conf_file, "splunkd", attribute, last_seen_run=last_seen_run, first_seen_run=last_seen_run)
        ctx.client.kv["matalog_declarations"][doc["_key"]] = dict(doc)
        return doc["_key"]

    def committed_runs(self, ctx, run_ids):
        for run_id in run_ids:
            ctx.client.kv["matalog_runs"][run_id] = {"_key": run_id, "run_id": run_id, "committed": 1, "run_mode": "normal"}

    def test_a_declaration_unseen_for_object_stale_runs_reads_is_deleted(self):
        ctx = make_ctx(sources=(SD,))
        self.committed_runs(ctx, ["20261013T1100Z", "20261013T1200Z", "20261013T1300Z"])
        stale = self.stored_declaration(ctx, "EXTRACT-stale", "20261013T1100Z")
        recent = self.stored_declaration(ctx, "EXTRACT-recent", "20261013T1200Z")
        run(ctx)
        self.assertIn(stale, ctx.kv_deletes["matalog_declarations"])
        self.assertNotIn(recent, ctx.kv_deletes["matalog_declarations"])

    def test_a_failed_config_read_stages_no_declarations_and_deletes_nothing(self):
        ctx = make_ctx(sources=(SD,), fields={SD: ["log_level"]})
        del ctx.client.conf["props"]
        self.committed_runs(ctx, ["20261013T1100Z", "20261013T1200Z", "20261013T1300Z"])
        self.stored_declaration(ctx, "EXTRACT-stale", "20261001T0000Z")
        with self.assertRaises(s5.StepFailed):
            run(ctx)
        self.assertEqual(len(ctx.kv["matalog_declarations"]), 0)
        self.assertEqual(ctx.kv_deletes["matalog_declarations"], set())

    def test_a_failed_config_read_writes_unknown_only_where_no_origin_is_stored(self):
        ctx = make_ctx(sources=(SD,), fields={SD: ["log_level", "component"]})
        store_field(ctx, SD, "component", origin="regex_extract", origin_decl_key="1" * 32)
        del ctx.client.conf["props"]
        with self.assertRaises(s5.StepFailed):
            run(ctx)
        self.assertEqual(field(ctx, SD, "log_level")["origin"], "unknown")
        self.assertNotIn("origin", field(ctx, SD, "component"))

    def test_datamodel_declarations_are_kept_when_the_datamodel_read_fails(self):
        ctx = make_ctx(sources=(SD,))
        self.committed_runs(ctx, ["20261013T1100Z", "20261013T1200Z", "20261013T1300Z"])
        kept = self.stored_declaration(ctx, "Eval:obj:id", "20261001T0000Z", conf_file="datamodels")

        def broken():
            raise RuntimeError("unreadable")
        ctx.client.datamodels = broken
        run(ctx)
        self.assertNotIn(kept, ctx.kv_deletes["matalog_declarations"])


class SummaryRows(unittest.TestCase):

    def test_unwritten_source_and_full_field_rows_get_config_apps_and_origin(self):
        ctx = make_ctx(sources=(SD,), fields={SD: ["log_level"]})
        source_row = ctx.stage(rows.source_row(ctx.run, *SD, events_last_cycle=10, daily_events=100))
        fs_row = [r for r in load("fieldsummary_splunkd_discovery")["results"] if r["field"] == "log_level"][0]
        field_row = ctx.stage(rows.field_row_from_fieldsummary(ctx.run, ctx.settings, "discovery", "full", fs_row, *SD, keys.ALL, keys.ALL,
                                                               2000, 0, 900, 1, "sid1"))
        run(ctx)
        self.assertEqual(source_row["config_apps"], ["search@10.4.3", "system@10.4.3"])
        self.assertEqual((field_row["origin"], field_row["origin_app"]), ("regex_extract", "search"))
        rows.validate(field_row)
        rows.validate(source_row)


def probe(ctx):
    return [s["spl"] for s in searches(ctx) if s["spl"].startswith("| tstats ")][0]


class RestagedColumns(unittest.TestCase):

    def test_a_staged_source_level_row_keeps_the_is_stratum_field_s3_set(self):
        ctx = make_ctx(sources=(CS,))
        ctx.stage_kv("matalog_fields", rows.fields_doc(*CS, keys.ALL, keys.ALL, "event_simpleName", presence="present", observed=1,
                                                       is_rollup=1, is_stratum_field=1, level="source"))
        run(ctx)
        doc = field(ctx, CS, "event_simpleName")
        self.assertEqual((doc["is_stratum_field"], doc["is_rollup"], doc["origin"]), (1, 1, "json_auto"))

    def test_a_restaged_stored_row_carries_no_columns_s5_does_not_own(self):
        ctx = make_ctx(sources=(CS,))
        store_field(ctx, CS, "event_simpleName", is_rollup=1, is_stratum_field=1, origin="unknown")
        run(ctx)
        doc = field(ctx, CS, "event_simpleName")
        self.assertEqual(doc["origin"], "json_auto")
        for column in ("is_stratum_field", "stratum_label", "level", "presence", "is_rollup"):
            self.assertNotIn(column, doc)

    def test_a_failed_config_read_restages_unknown_without_columns_s5_does_not_own(self):
        ctx = make_ctx(sources=(CS,))
        ctx.stage_kv("matalog_fields", rows.fields_doc(*CS, keys.ALL, keys.ALL, "event_simpleName", presence="present", observed=1,
                                                       is_rollup=1, is_stratum_field=1))
        del ctx.client.conf["props"]
        with self.assertRaises(s5.StepFailed):
            run(ctx)
        doc = field(ctx, CS, "event_simpleName")
        self.assertEqual((doc["origin"], doc["is_stratum_field"]), ("unknown", 1))


class IndexedOrigin(unittest.TestCase):

    def test_a_probe_confirmed_field_is_indexed_on_an_auto_kv_sourcetype(self):
        ctx = make_ctx(sources=(CS, SD), fields={CS: ["_subsecond", "aid"], SD: ["datetime", "foo"]})
        run(ctx)
        self.assertEqual(field(ctx, CS, "_subsecond")["origin"], "indexed")
        self.assertEqual(field(ctx, CS, "aid")["origin"], "json_auto")
        self.assertEqual(field(ctx, SD, "foo")["origin"], "kv_auto")

    def test_a_probe_count_of_zero_is_not_indexed(self):
        ctx = make_ctx(sources=(SC,), fields={SC: ["data.task"]})
        ctx.client.add_results(r"^\| tstats ", [{"sourcetype": "splunkd_conf", "matalog_dc:data.task": "0", "matalog_source": "/x", "matalog_host": "h"}])
        run(ctx)
        self.assertEqual(field(ctx, SC, "data.task")["origin"], "unknown")

    def test_an_unsearched_index_keeps_a_stored_indexed_origin_on_an_auto_kv_sourcetype(self):
        ctx = make_ctx(sources=(CS,), fields={CS: ["_subsecond"]}, **{"budget.max_searches_per_cycle": 10})
        store_field(ctx, CS, "_subsecond", origin="indexed", origin_decl_key="")
        run(ctx)
        self.assertEqual(searches(ctx), [])
        doc = field(ctx, CS, "_subsecond")
        self.assertEqual(doc["origin"], "indexed")
        self.assertNotIn("origin_changed_run", doc)

    def test_names_past_the_probe_cap_are_not_probed_and_keep_a_stored_indexed_origin(self):
        ctx = make_ctx(sources=(SC,), fields={SC: ["component", "data.task"]})
        store_field(ctx, SC, "data.task", origin="indexed", origin_decl_key="")
        cap = s5.PROBE_MAX_FIELDS
        s5.PROBE_MAX_FIELDS = 1
        try:
            run(ctx)
        finally:
            s5.PROBE_MAX_FIELDS = cap
        self.assertIn('dc("component")', probe(ctx))
        self.assertNotIn('dc("data.task")', probe(ctx))
        self.assertTrue(any(e["step"] == "S5" and "probing the first 1" in e["message"] for e in ctx.errors))
        doc = field(ctx, SC, "data.task")
        self.assertEqual(doc["origin"], "indexed")
        self.assertNotIn("origin_changed_run", doc)
        self.assertEqual(field(ctx, SC, "component")["origin"], "indexed")

    def test_a_name_unsafe_for_tstats_is_never_probed_or_indexed(self):
        ctx = make_ctx(sources=(CS,), fields={CS: ["arn:aws:iam", 'a"b']})
        run(ctx)
        self.assertNotIn("arn:aws:iam", probe(ctx))
        self.assertNotIn('a"b', probe(ctx))
        self.assertEqual(field(ctx, CS, "arn:aws:iam")["origin"], "json_auto")

    def test_the_probe_caps_source_and_host_values(self):
        ctx = make_ctx(sources=(SD,))
        run(ctx)
        self.assertIn("mvindex(matalog_source, 0, 999), matalog_host=mvindex(matalog_host, 0, 999)", probe(ctx))

    def test_search_cost_rows_of_s5_jobs_name_the_index(self):
        ctx = make_ctx(sources=(SD, CS))
        run(ctx)
        self.assertEqual([r["subject_key"] for r in ctx.summary["search_cost"]], ["_internal", "_internal", "matalog_json", "matalog_json"])


class KvModePrecedence(unittest.TestCase):

    def test_a_source_stanza_kv_mode_overrides_the_sourcetype_kv_mode(self):
        ctx = make_ctx(sources=(CS,), fields={CS: ["aid"]})
        ctx.client.conf["props"].append(entry("source::/tmp/crowdstrike_events_sensor.jsonl.part*", "zeta", KV_MODE="none"))
        run(ctx)
        self.assertEqual(field(ctx, CS, "aid")["origin"], "unknown")

    def test_a_source_stanza_kv_mode_listed_first_still_overrides_the_sourcetype(self):
        ctx = make_ctx(sources=(SC,), fields={SC: ["foo"]})
        ctx.client.conf["props"].insert(0, entry("source::...splunkd_conf...", "zeta", KV_MODE="json"))
        ctx.client.conf["props"].append(entry("source::...", "zeta", KV_MODE="none"))
        ctx.client.add_results(r"^\| tstats ", [{"sourcetype": "splunkd_conf", "matalog_source": "/x/splunkd_conf.log", "matalog_host": "h"}])
        run(ctx)
        self.assertEqual(field(ctx, SC, "foo")["origin"], "json_auto")


class DeclarationDetails(unittest.TestCase):

    def test_declarations_that_yield_no_origin_store_an_empty_origin_class(self):
        ctx = make_ctx(sources=(SC,))
        props_entry(ctx.client.conf["props"], "splunkd_conf", "system")["content"]["rename"] = "conf_renamed"
        run(ctx)
        for attribute in ("KV_MODE", "rename"):
            doc = decl(ctx, "system", "props", "splunkd_conf", attribute)
            self.assertEqual(doc["origin_class"], "")

    def test_disabled_props_stanzas_and_transforms_declare_nothing(self):
        ctx = make_ctx(sources=(SD,))
        ctx.client.conf["props"].append(entry("splunkd", "zeta", disabled="1", **{"EXTRACT-off": "(?<off>\\w+)"}))
        ctx.client.conf["props"].append(entry("splunkd", "eta", **{"REPORT-r": "eta_off"}))
        ctx.client.conf["transforms"].append(entry("eta_off", "eta", REGEX="(?<gone>\\w+)", disabled="true"))
        run(ctx)
        self.assertIsNone(decl(ctx, "zeta", "props", "splunkd", "EXTRACT-off"))
        doc = decl(ctx, "eta", "props", "splunkd", "REPORT-r")
        self.assertEqual((doc["fields_declared"], doc["parse_status"]), ([], "opaque"))

    def test_a_default_stanza_value_repeated_in_a_stanza_is_inherited_not_redeclared(self):
        ctx = make_ctx(sources=(SD,))
        ctx.client.conf["props"].append(entry("default", "zeta", "global", **{"EVAL-dflt": "1"}))
        ctx.client.conf["props"].append(entry("splunkd", "zeta", "global", **{"EVAL-dflt": "1"}))
        run(ctx)
        self.assertIsNotNone(decl(ctx, "zeta", "props", "default", "EVAL-dflt"))
        self.assertIsNone(decl(ctx, "zeta", "props", "splunkd", "EVAL-dflt"))

    def test_fields_conf_declares_only_truthy_indexed_and_scopes_sourcetype_stanzas(self):
        ctx = make_ctx(sources=(SD, SA))
        ctx.client.conf["fields"].append(entry("not_indexed", "zeta", INDEXED="false"))
        ctx.client.conf["fields"].append(entry("sourcetype::splunkd::st_only", "zeta", INDEXED="true"))
        run(ctx)
        self.assertIsNone(decl(ctx, "zeta", "fields", "not_indexed", "INDEXED"))
        doc = decl(ctx, "zeta", "fields", "sourcetype::splunkd::st_only", "INDEXED")
        self.assertEqual((doc["stanza_kind"], doc["src_sourcetype"], doc["applies_to_source_keys"]), ("sourcetype", "splunkd", [keys.source_key(*SD)]))

    def test_datamodel_raw_values_are_truncated_and_apply_to_no_source(self):
        ctx = make_ctx(sources=(SD,), fields={SD: ["dm_out"]})
        model = {"modelName": "M", "objects": [{"objectName": "O", "calculations": [
            {"calculationID": "c1", "calculationType": "Eval", "expression": "x" * 5000, "outputFields": [{"fieldName": "dm_out"}]}]}]}
        ctx.client.conf["datamodels"] = [{"name": "M", "acl": {"app": "zeta", "owner": "nobody", "sharing": "global"},
                                           "content": {"description": json.dumps(model)}}]
        run(ctx)
        doc = decl(ctx, "zeta", "datamodels", "M", "Eval:O:c1")
        self.assertEqual((len(doc["raw_value"]), doc["applies_to_source_keys"]), (4096, []))
        self.assertEqual(field(ctx, SD, "dm_out")["origin_candidates"], [])

    def test_declared_names_starting_with_an_underscore_get_no_declared_only_row(self):
        ctx = make_ctx(sources=(SD,))
        ctx.client.conf["props"].append(entry("splunkd", "zeta", **{"EVAL-_hidden": "1", "EVAL-shown": "1"}))
        run(ctx)
        self.assertIsNone(field(ctx, SD, "_hidden"))
        self.assertEqual(field(ctx, SD, "shown")["presence"], "declared_only")

    def test_stored_matches_of_sources_not_resolved_this_run_are_kept(self):
        ctx = make_ctx(sources=(SA,))
        other = keys.source_key("elsewhere", "splunkd_access")
        doc = rows.declarations_doc("system", "props", "splunkd_access", "REPORT-access", applies_to_source_keys=[other, keys.source_key(*SA)])
        ctx.client.kv["matalog_declarations"][doc["_key"]] = dict(doc)
        run(ctx)
        self.assertEqual(decl(ctx, "system", "props", "splunkd_access", "REPORT-access")["applies_to_source_keys"], [keys.source_key(*SA), other])


class SourcesAndRows(unittest.TestCase):

    def test_sources_of_staged_field_rows_are_resolved_without_a_source_doc(self):
        ctx = make_ctx(sources=(), fields={SD: ["log_level"]})
        run(ctx)
        self.assertEqual(field(ctx, SD, "log_level")["origin"], "regex_extract")
        self.assertIn(keys.source_key(*SD), ctx.kv["matalog_sources"])

    def test_stored_field_rows_are_read_in_chunks(self):
        ctx = make_ctx(sources=(SD, SA, SC))
        chunk = s5.KV_QUERY_CHUNK
        s5.KV_QUERY_CHUNK = 2
        try:
            run(ctx)
        finally:
            s5.KV_QUERY_CHUNK = chunk
        queries = [c for c in ctx.client.calls if c[0] == "kv_query" and c[1] == "matalog_fields"]
        self.assertEqual([len(q[2]["source_key"]["$in"]) for q in queries], [2, 1])

    def test_a_stored_empty_origin_sets_no_origin_changed_run(self):
        ctx = make_ctx(sources=(SD,), fields={SD: ["log_level"]})
        store_field(ctx, SD, "log_level", origin="", origin_decl_key="0" * 32)
        run(ctx)
        self.assertNotIn("origin_changed_run", field(ctx, SD, "log_level"))

    def test_a_stored_row_whose_candidates_differ_is_restaged(self):
        first = make_ctx(sources=(SD,))
        store_field(first, SD, "log_level")
        run(first)
        resolved = dict(first.client.kv["matalog_fields"][keys.source_field_key(*SD, "log_level")])
        resolved.update(field(first, SD, "log_level"))
        resolved["origin_candidates"] = resolved["origin_candidates"][:1] + ["f" * 32]
        second = make_ctx(sources=(SD,))
        second.client.kv["matalog_fields"][resolved["_key"]] = resolved
        run(second)
        doc = field(second, SD, "log_level")
        self.assertEqual(doc["origin_candidates"], field(first, SD, "log_level")["origin_candidates"])
        self.assertNotIn("origin_changed_run", doc)


class StaleCount(unittest.TestCase):

    def setUp(self):
        self.ctx = make_ctx(sources=(SD,), **{"retention.object_stale_runs": 3})
        doc = rows.declarations_doc("gone_app", "props", "splunkd", "EXTRACT-gone", last_seen_run="20261013T1000Z", first_seen_run="20261013T1000Z")
        self.ctx.client.kv["matalog_declarations"][doc["_key"]] = dict(doc)
        self.key = doc["_key"]

    def add_run(self, run_id, run_mode="normal", errors=None):
        self.ctx.client.kv["matalog_runs"][run_id] = {"_key": run_id, "run_id": run_id, "committed": 1, "run_mode": run_mode, "errors": errors or []}

    def test_a_run_whose_config_read_failed_is_not_counted(self):
        self.add_run("20261013T1100Z")
        self.add_run("20261013T1200Z", errors=[{"step": "S5", "subject": "", "message": "StepFailed: conf-props unreadable: down"}])
        run(self.ctx)
        self.assertNotIn(self.key, self.ctx.kv_deletes["matalog_declarations"])

    def test_a_failed_config_read_stored_as_json_text_is_not_counted(self):
        self.add_run("20261013T1100Z")
        self.add_run("20261013T1200Z", errors=json.dumps([{"step": "S5", "subject": "", "message": "StepFailed: apps/local unreadable"}]))
        run(self.ctx)
        self.assertNotIn(self.key, self.ctx.kv_deletes["matalog_declarations"])

    def test_rebuild_runs_are_not_counted(self):
        self.add_run("20261013T1100Z")
        self.add_run("20261013T1200Z", run_mode="rebuild")
        run(self.ctx)
        self.assertNotIn(self.key, self.ctx.kv_deletes["matalog_declarations"])

    def test_runs_with_other_step_errors_are_counted(self):
        self.add_run("20261013T1100Z")
        self.add_run("20261013T1200Z", errors=[{"step": "S5", "subject": "_internal", "message": "search failed: x"}])
        run(self.ctx)
        self.assertIn(self.key, self.ctx.kv_deletes["matalog_declarations"])


class WrittenSummaryRows(unittest.TestCase):

    def test_rows_already_written_are_not_changed(self):
        ctx = make_ctx(sources=(SD,), fields={SD: ["log_level"]})
        source_row = ctx.stage(rows.source_row(ctx.run, *SD, events_last_cycle=10, daily_events=100))
        fs_row = [r for r in load("fieldsummary_splunkd_discovery")["results"] if r["field"] == "log_level"][0]
        field_row = ctx.stage(rows.field_row_from_fieldsummary(ctx.run, ctx.settings, "discovery", "full", fs_row, *SD, keys.ALL, keys.ALL,
                                                               2000, 0, 900, 1, "sid1"))
        before = (copy.deepcopy(source_row), copy.deepcopy(field_row))
        ctx.unwritten[:] = [r for r in ctx.unwritten if r is not source_row and r is not field_row]
        run(ctx)
        self.assertEqual((source_row, field_row), before)

    def test_origin_is_not_added_to_a_row_it_would_push_past_max_row_bytes(self):
        fs_row = [r for r in load("fieldsummary_splunkd_discovery")["results"] if r["field"] == "log_level"][0]
        probe_ctx = make_ctx(sources=(SD,))
        size = rows.row_bytes(rows.field_row_from_fieldsummary(probe_ctx.run, probe_ctx.settings, "discovery", "full", fs_row, *SD,
                                                               keys.ALL, keys.ALL, 2000, 0, 900, 1, "sid1"))
        ctx = make_ctx(sources=(SD,), fields={SD: ["log_level"]}, **{"profile.max_row_bytes": size})
        field_row = ctx.stage(rows.field_row_from_fieldsummary(ctx.run, ctx.settings, "discovery", "full", fs_row, *SD, keys.ALL, keys.ALL,
                                                               2000, 0, 900, 1, "sid1"))
        self.assertLessEqual(rows.row_bytes(field_row), size)
        before = (field_row.get("origin"), field_row.get("origin_app"))
        run(ctx)
        self.assertEqual((field_row.get("origin"), field_row.get("origin_app")), before)
        self.assertLessEqual(rows.row_bytes(field_row), size)


class FullRun(unittest.TestCase):

    def test_a_rerun_of_the_same_slot_restages_identical_declarations_and_changes_no_origin(self):
        logging.disable(logging.CRITICAL)
        try:
            client = fake_client.FakeClient()
            s = support.settings(**{"budget.index_scan_interval_seconds": 3600})
            client.settings = s
            first = runner.run_once(s, client, now=support.SLOT)
            declarations = copy.deepcopy(client.kv["matalog_declarations"])
            second = runner.run_once(s, client, now=support.SLOT)
        finally:
            logging.disable(logging.NOTSET)
        self.assertEqual((first["committed"], second["committed"], second["committed_attempt"]), (1, 1, 2))
        self.assertTrue(declarations)
        self.assertEqual(client.kv["matalog_declarations"], declarations)
        self.assertTrue(all(d["first_seen_run"] == first["run_id"] for d in declarations.values()))
        fields = list(client.kv["matalog_fields"].values())
        self.assertTrue(all(d.get("origin") for d in fields if d.get("presence") == "present"))
        self.assertFalse(any(d.get("origin_changed_run") for d in fields))


if __name__ == "__main__":
    unittest.main()
