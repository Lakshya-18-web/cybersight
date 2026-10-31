"""The EVE sender, against the real handlers over local HTTP (stdlib test double of the web layer). Nothing leaves this machine."""
import os
import tempfile
import unittest
from unittest import mock

from week5 import eve_send

from tests.week5_support import ApiRig, HttpStub, TOKENS

SAMPLE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples", "eve", "eve_mixed.ndjson")


class Sender(unittest.TestCase):
    def run_cli(self, rig, who="bob", extra=(), env=True, sensor="sensor-lab-1", path=SAMPLE):
        lines = []
        with HttpStub(rig.api, max_body=2_000_000) as stub:
            with mock.patch.dict(os.environ, {"WEEK5_SENSOR_TOKEN": TOKENS[who]} if env else {}, clear=False):
                if not env:
                    os.environ.pop("WEEK5_SENSOR_TOKEN", None)
                code = eve_send.main(["--base-url", stub.url, "--sensor", sensor, "--file", path] + list(extra), out=lines.append)
        return code, lines

    def test_sends_the_sample_and_a_second_run_creates_nothing(self):
        rig = ApiRig(sensor=True)
        code, lines = self.run_cli(rig)
        self.assertEqual(code, 0, lines)
        self.assertIn("stored=20", " ".join(lines))
        self.assertEqual(rig.call("list_sensors", "carol").body["events"], 20)
        n_jobs = rig.call("list_jobs", "carol").body["total"]
        self.assertEqual(n_jobs, 4)
        code, lines = self.run_cli(rig)
        self.assertEqual(code, 0)
        self.assertIn("duplicates=20", lines[-1])
        self.assertEqual(rig.call("list_jobs", "carol").body["total"], n_jobs)

    def test_no_analyze_stores_evidence_without_jobs(self):
        rig = ApiRig(sensor=True)
        code, _ = self.run_cli(rig, extra=["--no-analyze"])
        self.assertEqual(code, 0)
        self.assertEqual(rig.call("list_sensors", "carol").body["events"], 20)
        self.assertEqual(rig.call("list_jobs", "carol").body["total"], 0)

    def test_a_viewer_token_is_refused_and_nothing_is_stored(self):
        rig = ApiRig(sensor=True)
        code, lines = self.run_cli(rig, who="carol")
        self.assertEqual(code, 1)
        self.assertIn("403", lines[0])
        self.assertEqual(rig.call("list_sensors", "carol").body["events"], 0)

    def test_the_token_must_come_from_the_environment(self):
        code, lines = self.run_cli(ApiRig(sensor=True), env=False)
        self.assertEqual(code, 2)
        self.assertIn("WEEK5_SENSOR_TOKEN", lines[0])

    def test_bad_sensor_name_and_missing_file_are_refused_before_any_request(self):
        rig = ApiRig(sensor=True)
        self.assertEqual(self.run_cli(rig, sensor="bad name!")[0], 2)
        self.assertEqual(self.run_cli(rig, path="/nonexistent.ndjson")[0], 2)

    def test_large_files_are_batched(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "big.ndjson")
            with open(SAMPLE, "rb") as fh:
                line = fh.readline()
            with open(p, "wb") as fh:
                fh.write((line.rstrip(b"\n") + b"\n") * 1000)
            self.assertEqual(len(list(eve_send.batches(p))), 3)

    def test_a_bad_analyze_flag_is_refused(self):
        rig = ApiRig(sensor=True)
        with open(SAMPLE, "rb") as fh:
            raw = fh.read()
        r = rig.call("ingest_eve", "bob", raw=raw, path={"sensor": "s1"}, query={"analyze": "maybe"}, content_type="application/x-ndjson")
        self.assertEqual(r.status, 422)
        self.assertEqual(rig.call("list_sensors", "carol").body["events"], 0)

    def test_the_token_never_appears_in_the_output(self):
        rig = ApiRig(sensor=True)
        _, lines = self.run_cli(rig)
        self.assertNotIn(TOKENS["bob"], " ".join(lines))


if __name__ == "__main__":
    unittest.main()
