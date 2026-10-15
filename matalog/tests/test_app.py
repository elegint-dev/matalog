import ast
import os
import re
import unittest

import support
from matalog import rows
from matalog import settings as settings_mod

ROOT = os.path.abspath(support.APP_ROOT)
DEFAULT = os.path.join(ROOT, "default")


def read(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def stanzas(path):
    return settings_mod.parse_conf(read(path))


class Collections(unittest.TestCase):
    def test_collections_conf_declares_every_collection_column_and_accelerated_field(self):
        conf = stanzas(os.path.join(DEFAULT, "collections.conf"))
        every = dict(rows.COLLECTIONS, **rows.INTERNAL_COLLECTIONS)
        every_accelerated = dict(rows.ACCELERATED, **rows.INTERNAL_ACCELERATED)
        self.assertEqual(set(conf), set(every))
        for collection, columns in every.items():
            declared = set(k[6:] for k in conf[collection] if k.startswith("field."))
            typed = set(c for c, t in columns.items() if t not in (rows.JSON, rows.STRING_LIST))
            self.assertEqual(declared, typed, collection)
            accelerated = [re.match(r'\{"(.+)": 1\}', conf[collection][k]).group(1) for k in sorted(conf[collection]) if k.startswith("accelerated_fields.")]
            self.assertEqual(sorted(accelerated), sorted(every_accelerated[collection]), collection)
            for column, typ in columns.items():
                if typ in (rows.INT, rows.FLOAT, rows.EPOCH, rows.BOOL):
                    self.assertEqual(conf[collection]["field." + column], "number")

    def test_transforms_conf_has_a_kvstore_lookup_per_collection_listing_every_column(self):
        conf = stanzas(os.path.join(DEFAULT, "transforms.conf"))
        every = dict(rows.COLLECTIONS, **rows.INTERNAL_COLLECTIONS)
        self.assertEqual(set(name for name, body in conf.items() if "filename" not in body), set(every))
        for collection, columns in every.items():
            self.assertEqual(conf[collection]["external_type"], "kvstore")
            self.assertEqual(conf[collection]["collection"], collection)
            listed = [c.strip() for c in conf[collection]["fields_list"].split(",")]
            self.assertEqual(listed, ["_key"] + list(columns))


class OtherConf(unittest.TestCase):
    def test_index_retention_is_profiles_frozen_days(self):
        conf = stanzas(os.path.join(DEFAULT, "indexes.conf"))
        self.assertEqual(int(conf["matalog_profiles"]["frozenTimePeriodInSecs"]), settings_mod.DEFAULTS["retention"]["profiles_frozen_days"][1] * 86400)

    def test_modular_input_ships_disabled_on_a_slot_aligned_schedule(self):
        conf = stanzas(os.path.join(DEFAULT, "inputs.conf"))
        self.assertEqual(conf["matalog_profiler://default"]["disabled"], "1")
        self.assertEqual(conf["matalog_profiler://default"]["interval"], "0 * * * *")
        self.assertEqual(conf["matalog_profiler"]["python.required"], "3.13")
        self.assertEqual(conf["matalog_profiler://default"]["python.required"], "3.13")

    def test_modular_input_scheme_has_its_spec_file(self):
        spec = read(os.path.join(ROOT, "README", "inputs.conf.spec"))
        self.assertIn("[matalog_profiler://<name>]", spec)
        self.assertIn("run_mode", spec)

    def test_run_comment_macro_ships_with_the_app(self):
        conf = stanzas(os.path.join(DEFAULT, "macros.conf"))
        self.assertEqual(conf["comment(1)"]["definition"], '""')
        self.assertEqual(conf["comment(1)"]["iseval"], "1")

    def test_app_conf_names_the_app(self):
        conf = stanzas(os.path.join(DEFAULT, "app.conf"))
        self.assertEqual(conf["package"]["id"], "matalog")
        self.assertEqual(conf["ui"]["is_visible"], "true")
        self.assertTrue(os.path.exists(os.path.join(ROOT, "app.manifest")))
        self.assertTrue(os.path.exists(os.path.join(ROOT, "metadata", "default.meta")))

    def test_readme_says_how_to_run_tests_on_host_and_under_splunks_interpreter(self):
        text = read(os.path.join(ROOT, "README.md"))
        self.assertIn("python3 -m unittest discover -s matalog/tests", text)
        self.assertIn("$SPLUNK_HOME/bin/splunk", text)
        self.assertIn("splunk cmd python3", text)


class Register(unittest.TestCase):
    def files(self):
        for base, dirs, names in os.walk(ROOT):
            dirs[:] = [d for d in dirs if d not in ("__pycache__", "fixtures", "local", "node_modules")]
            for name in names:
                if name.endswith((".py", ".conf", ".md", ".meta", ".manifest", ".spec")):
                    yield os.path.join(base, name)

    def test_no_em_dashes_in_code_conf_or_docs(self):
        dash = chr(0x2014)
        for path in self.files():
            self.assertNotIn(dash, read(path), path)

    def test_python_parses_under_the_3_9_grammar(self):
        for path in self.files():
            if path.endswith(".py"):
                ast.parse(read(path), path, feature_version=(3, 9))


if __name__ == "__main__":
    unittest.main()
