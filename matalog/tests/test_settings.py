import os
import unittest

import support
from matalog import settings as settings_mod
import fake_client

CONF = os.path.join(support.APP_ROOT, "default", "matalog.conf")


class Defaults(unittest.TestCase):
    def test_every_contract_setting_has_a_default_of_its_type(self):
        s = settings_mod.Settings.defaults()
        self.assertEqual(len(settings_mod.setting_names()), 60)
        self.assertEqual(s.budget.cycle_seconds, 3600)
        self.assertIsInstance(s.budget.priority_usage_weight, float)
        self.assertEqual(s.usage.service_account, "svc_matalog")
        self.assertEqual(s.get("write.kv_batch_size"), 500)

    def test_unknown_settings_and_bad_values_are_rejected(self):
        with self.assertRaises(settings_mod.SettingError):
            settings_mod.Settings.from_dict({"budget.nope": 1})
        with self.assertRaises(settings_mod.SettingError):
            settings_mod.Settings.from_dict({"budget.cycle_seconds": "soon"})
        with self.assertRaises(AttributeError):
            settings_mod.Settings.defaults().budget.nope

    def test_conf_values_are_coerced_and_overlay_the_defaults(self):
        s = settings_mod.Settings.from_conf_text("[budget]\ncycle_seconds = 600\n# comment\n[profile]\nidentifier_distinct_ratio = 0.5\n[other]\nx = 1\n")
        self.assertEqual(s.budget.cycle_seconds, 600)
        self.assertEqual(s.profile.identifier_distinct_ratio, 0.5)
        self.assertEqual(s.budget.max_searches_per_cycle, 1500)

    def test_with_overrides_returns_a_new_object(self):
        base = settings_mod.Settings.defaults()
        changed = base.with_overrides({"budget.cycle_seconds": 60})
        self.assertEqual(changed.budget.cycle_seconds, 60)
        self.assertEqual(base.budget.cycle_seconds, 3600)


class ShippedConf(unittest.TestCase):
    def test_default_conf_file_states_every_default_exactly(self):
        with open(CONF, encoding="utf-8") as handle:
            stanzas = settings_mod.parse_conf(handle.read())
        for stanza, table in settings_mod.DEFAULTS.items():
            self.assertIn(stanza, stanzas)
            for name, (typ, default) in table.items():
                self.assertIn(name, stanzas[stanza], "%s.%s missing from matalog.conf" % (stanza, name))
                self.assertEqual(settings_mod.coerce(stanza, name, stanzas[stanza][name]), default, "%s.%s" % (stanza, name))
            extra = set(stanzas[stanza]) - set(table)
            self.assertFalse(extra, "matalog.conf has settings outside the contract: %s" % extra)

    def test_seed_stanzas_match_the_contract_table(self):
        s = settings_mod.Settings.from_conf_file(CONF)
        seeds = dict((row["src_sourcetype"], (row["stratum_field"], row["version_field"], row["index_pattern"])) for row in s.stratum_seeds)
        self.assertEqual(seeds["crowdstrike:events:sensor"], ("event_simpleName", "ConfigBuild", "*"))
        self.assertEqual(seeds["aws:cloudtrail"], ("eventName", "eventVersion", "*"))
        self.assertEqual(seeds["OktaIM2:log"], ("eventType", "", "*"))
        self.assertEqual(seeds["gws:reports:login"], ("event.name", "", "*"))
        self.assertEqual(seeds["XmlWinEventLog:Security"], ("EventCode", "", "*"))
        self.assertEqual(len(seeds), 10)


class RunRecordInputs(unittest.TestCase):
    def test_budget_json_carries_every_setting(self):
        s = settings_mod.Settings.from_dict({"budget.cycle_seconds": 60})
        payload = s.budget_json()
        self.assertEqual(set("%s.%s" % (stanza, name) for stanza, table in payload.items() for name in table), set(settings_mod.setting_names()))
        self.assertEqual(payload["budget"]["cycle_seconds"], 60)
        self.assertFalse(any("." in key for stanza in payload.values() for key in stanza), "KV document keys may not contain a dot")

    def test_config_hash_changes_with_settings_stratum_rows_and_declarations(self):
        s = settings_mod.Settings.defaults()
        base = s.config_hash([], [])
        self.assertEqual(len(base), 32)
        self.assertEqual(base, s.config_hash([], []))
        self.assertNotEqual(base, s.with_overrides({"budget.cycle_seconds": 60}).config_hash([], []))
        self.assertNotEqual(base, s.config_hash([{"_key": "k", "stratum_field": "f"}], []))
        self.assertNotEqual(base, s.config_hash([], ["d1"]))
        self.assertEqual(s.config_hash([], ["b", "a"]), s.config_hash([], ["a", "b"]))

    def test_from_client_falls_back_to_defaults_when_the_conf_is_unreadable(self):
        client = fake_client.FakeClient(load_all=False)
        s = settings_mod.Settings.from_client(client)
        self.assertEqual(s.budget.cycle_seconds, 3600)
        client.conf["matalog"] = [{"name": "budget", "content": {"cycle_seconds": "900", "eai:appName": "matalog"}, "acl": {}},
                                  {"name": "stratum:x:y", "content": {"stratum_field": "f", "version_field": "", "index_pattern": "*"}, "acl": {}}]
        s = settings_mod.Settings.from_client(client)
        self.assertEqual(s.budget.cycle_seconds, 900)
        self.assertEqual(s.stratum_seeds[0]["src_sourcetype"], "x:y")

    def test_exclude_lists_split_on_commas(self):
        s = settings_mod.Settings.from_dict({"usage.exclude_users": "svc_matalog, bot"})
        self.assertEqual(s.exclude_users(), ["svc_matalog", "bot"])
        self.assertEqual(s.exclude_apps(), ["matalog"])


if __name__ == "__main__":
    unittest.main()
