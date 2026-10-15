import hashlib
import unittest

import support  # noqa: F401
from matalog import keys


class KeyFunction(unittest.TestCase):
    def test_key_is_first_32_hex_of_sha256_over_unit_separator_join(self):
        expected = hashlib.sha256("a\u001fb\u001fc".encode("utf-8")).hexdigest()[:32]
        self.assertEqual(keys.k("a", "b", "c"), expected)
        self.assertEqual(len(keys.k("x")), 32)

    def test_unit_separator_inside_a_part_is_replaced_before_hashing(self):
        self.assertEqual(keys.k("a\u001fb"), keys.k("a�b"))
        self.assertNotEqual(keys.k("a\u001fb"), keys.k("a", "b"))

    def test_parts_are_stringified_and_none_is_rejected(self):
        self.assertEqual(keys.k("r", 1), keys.k("r", "1"))
        with self.assertRaises(keys.IdentityError):
            keys.k("a", None)
        with self.assertRaises(keys.IdentityError):
            keys.k()

    def test_same_content_gives_same_key_so_rewrites_overwrite(self):
        self.assertEqual(keys.field_key("MAIN", "st", "f", "v", "user"), keys.field_key("main", "st", "f", "v", "user"))


class Sentinels(unittest.TestCase):
    def test_stratum_value_of_maps_absent_empty_single_and_multi(self):
        self.assertEqual(keys.stratum_value_of(None), keys.MISSING)
        self.assertEqual(keys.stratum_value_of(""), keys.EMPTY)
        self.assertEqual(keys.stratum_value_of("ProcessRollup2"), "ProcessRollup2")
        self.assertEqual(keys.stratum_value_of(["only"]), "only")
        self.assertEqual(keys.stratum_value_of([]), keys.MISSING)

    def test_multi_form_sorts_distinct_values_joined_by_unit_separator(self):
        value = keys.stratum_value_of(["b", "a", "b"])
        self.assertEqual(value, "__multi__\u001fa\u001fb")
        self.assertEqual(keys.multi_values(value), ["a", "b"])
        self.assertEqual(keys.value_kind(value), "multi")

    def test_value_kind_and_label_cover_every_sentinel(self):
        self.assertEqual(keys.value_kind(keys.ALL), "all")
        self.assertEqual(keys.value_kind(keys.EMPTY), "empty")
        self.assertEqual(keys.value_kind(keys.MISSING), "missing")
        self.assertEqual(keys.value_kind("x"), "value")
        self.assertEqual(keys.stratum_label("event_simpleName", "ProcessRollup2"), "event_simpleName=ProcessRollup2")
        self.assertEqual(keys.stratum_label("event_simpleName", keys.MISSING), "event_simpleName is missing")
        self.assertEqual(keys.stratum_label("event_simpleName", keys.EMPTY), "event_simpleName is empty")
        self.assertEqual(keys.stratum_label("event_simpleName", keys.multi_value(["b", "a"])), "event_simpleName in {a, b}")
        self.assertEqual(keys.stratum_label(keys.ALL, keys.ALL), "all events")

    def test_only_plain_values_are_prunable_and_filters_match_the_contract(self):
        self.assertEqual(keys.prunable("x"), 1)
        self.assertEqual(keys.prunable(keys.MISSING), 0)
        self.assertEqual(keys.stratum_filter("f", 'a"b'), 'f="a\\"b" | where mvcount(\'f\')=1 AND \'f\'=="a\\"b"')
        self.assertEqual(keys.stratum_filter("f", keys.MISSING), "NOT f=*")
        self.assertEqual(keys.stratum_filter("f", keys.EMPTY), 'f="" | where mvcount(\'f\')=1 AND \'f\'==""')
        self.assertEqual(keys.stratum_filter("f", keys.multi_value(["a", "b"])),
                         'f="a" f="b" | where mvcount(\'f\')>1 AND mvcount(mvdedup(\'f\'))=2 AND isnotnull(mvfilter(\'f\'=="a")) AND isnotnull(mvfilter(\'f\'=="b"))')
        self.assertEqual(keys.stratum_filter(keys.ALL, keys.ALL), "")

    def test_a_value_filter_matches_case_and_wildcards_exactly_and_keeps_the_prunable_term(self):
        spl = keys.stratum_filter("EventCode", "4624*")
        self.assertTrue(spl.startswith('EventCode="4624*" | where '))
        self.assertIn("'EventCode'==\"4624*\"", spl)
        self.assertIn("'event.name'==\"x\"", keys.stratum_filter("event.name", "x"))

    def test_a_repeated_value_is_a_multi_stratum_and_its_filter_counts_distinct_values(self):
        self.assertEqual(keys.stratum_value_of(["a", "a"]), keys.multi_value(["a"]))
        spl = keys.stratum_filter("f", keys.multi_value(["a"]))
        self.assertIn("mvcount('f')>1 AND mvcount(mvdedup('f'))=1", spl)

    def test_numbers_in_keys_hash_the_same_whole_or_float(self):
        self.assertEqual(keys.num_text(1791900000), "1791900000")
        self.assertEqual(keys.num_text(1791900000.0), "1791900000")
        self.assertEqual(keys.num_text(0.25), "0.25")
        self.assertEqual(keys.num_text(None), "")

    def test_identity_values_are_never_empty_or_wildcard(self):
        for bad in ("", "*", None):
            with self.assertRaises(keys.IdentityError):
                keys.value_kind(bad)
            with self.assertRaises(keys.IdentityError):
                keys.norm_sourcetype(bad)


class Identity(unittest.TestCase):
    def test_index_is_lowercased_and_sourcetype_and_field_name_are_verbatim(self):
        self.assertEqual(keys.norm_index("MAIN"), "main")
        self.assertEqual(keys.norm_sourcetype("OktaIM2:log"), "OktaIM2:log")
        self.assertEqual(keys.norm_field_name(" event.parameters{}.name "), " event.parameters{}.name ")
        self.assertEqual(keys.norm_stratum_field(""), keys.ALL)

    def test_source_level_field_key_uses_the_all_stratum(self):
        self.assertEqual(keys.source_field_key("main", "st", "user"), keys.field_key("main", "st", keys.ALL, keys.ALL, "user"))


class RunIdentity(unittest.TestCase):
    def test_run_id_is_the_utc_slot_start_and_round_trips(self):
        self.assertEqual(keys.slot_start(1791900000 + 1234, 3600), 1791900000)
        self.assertEqual(keys.run_id_of(1791900000), "20261013T1400Z")
        self.assertEqual(keys.slot_start_of("20261013T1400Z"), 1791900000)
        self.assertEqual(keys.run_id_for(1791900000 + 3599, 3600), "20261013T1400Z")

    def test_run_ids_sort_as_text_and_slot_arithmetic_is_whole_slots(self):
        later = keys.run_id_add("20261013T1400Z", 24, 3600)
        self.assertEqual(later, "20261014T1400Z")
        self.assertGreater(later, "20261013T1400Z")
        self.assertEqual(keys.slots_between("20261013T1400Z", later, 3600), 24)
        self.assertEqual(keys.run_id_add("20261013T1400Z", -1, 3600), "20261013T1300Z")

    def test_stamp_is_the_stash_timestamp_format(self):
        self.assertEqual(keys.stamp(1791900000), "10/13/2026 14:00:00 +0000")


class Windows(unittest.TestCase):
    def test_every_window_ends_at_slot_minus_lag_and_has_its_contract_length(self):
        s = support.settings()
        w = keys.windows(s, 1791900000)
        latest = 1791900000 - 300
        self.assertEqual(w["discovery"], (latest - 900, latest))
        self.assertEqual(w["profile"], (latest - 86400, latest))
        self.assertEqual(w["stratum_list"], (latest - 86400, latest))
        self.assertEqual(w["source_day"], (latest - 86400, latest))
        self.assertEqual(w["source_cycle"], (latest - 3600, latest))
        self.assertEqual(set(w), set(keys.WINDOW_NAMES))


if __name__ == "__main__":
    unittest.main()
