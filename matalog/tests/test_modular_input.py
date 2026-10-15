import io
import os
import sys
import unittest

import support

sys.path.insert(0, support.BIN)
import matalog_profiler  # noqa: E402

INPUT_XML = """<input><server_host>sh</server_host><server_uri>https://127.0.0.1:8089</server_uri><session_key>abc</session_key>
<configuration><stanza name="matalog_profiler://default"><param name="run_mode">rebuild</param><param name="interval">0 * * * *</param></stanza></configuration></input>"""

VALIDATE_XML = """<items><server_host>sh</server_host><server_uri>https://127.0.0.1:8089</server_uri><session_key>abc</session_key>
<item name="default"><param name="run_mode">%s</param></item></items>"""


class Scheme(unittest.TestCase):
    def test_scheme_is_printed(self):
        out = io.StringIO()
        old = sys.stdout
        sys.stdout = out
        try:
            self.assertEqual(matalog_profiler.main(["--scheme"]), 0)
        finally:
            sys.stdout = old
        self.assertIn("<scheme>", out.getvalue())
        self.assertIn("run_mode", out.getvalue())

    def test_input_xml_yields_session_key_uri_and_params(self):
        data = matalog_profiler.read_input_xml(io.StringIO(INPUT_XML))
        self.assertEqual((data["session_key"], data["server_uri"]), ("abc", "https://127.0.0.1:8089"))
        self.assertEqual(data["params"]["run_mode"], "rebuild")
        self.assertEqual(data["stanzas"], ["matalog_profiler://default"])

    def test_a_launch_without_stanzas_runs_nothing(self):
        empty = "<input><server_host>sh</server_host><server_uri>https://127.0.0.1:8089</server_uri><session_key>abc</session_key><configuration/></input>"
        self.assertEqual(matalog_profiler.run_modular_input(io.StringIO(empty)), 0)

    def test_validate_accepts_known_modes_only(self):
        self.assertEqual(matalog_profiler.validate_arguments(io.StringIO(VALIDATE_XML % "normal")), 0)
        self.assertEqual(matalog_profiler.validate_arguments(io.StringIO(VALIDATE_XML % "weekly")), 1)

    def test_validate_rejects_unparseable_xml_with_a_message_not_a_traceback(self):
        err, old = io.StringIO(), sys.stderr
        sys.stderr = err
        try:
            self.assertEqual(matalog_profiler.validate_arguments(io.StringIO("garbage")), 1)
        finally:
            sys.stderr = old
        self.assertIn("not valid XML", err.getvalue())

    def test_cli_parser_takes_now_and_run_mode(self):
        args = matalog_profiler.build_parser().parse_args(["--url", "https://x", "--user", "u", "--password", "p", "--now", "1791900000", "--run-mode", "rebuild", "--set", "budget.cycle_seconds=60"])
        self.assertEqual((args.now, args.run_mode, args.set), (1791900000.0, "rebuild", ["budget.cycle_seconds=60"]))


if __name__ == "__main__":
    unittest.main()
