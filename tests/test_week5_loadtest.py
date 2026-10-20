"""Week 5 load tester: statistics, result structure, honesty rules, in-process and HTTP runs (fake model only, offline)."""
import contextlib
import io
import json
import os
import tempfile
import threading
import unittest
import unittest.mock

from tests import week5_support as W5
from week5.loadtest import backend, client, metrics, report, run
from week5.loadtest import __main__ as cli


class PercentileTests(unittest.TestCase):
    def test_nearest_rank_known_values(self):
        v = list(range(1, 101))
        self.assertEqual([metrics.percentile(v, p) for p in (50, 90, 95, 99, 100)], [50, 90, 95, 99, 100])
        self.assertEqual(metrics.percentile([5, 1, 3], 50), 3)
        self.assertEqual(metrics.percentile([7], 99), 7)
        self.assertEqual(metrics.percentile([1, 2, 3, 4], 25), 1)
        self.assertEqual(metrics.percentile([1, 2, 3, 4], 75), 3)
        self.assertEqual(metrics.percentile([1, 2, 3, 4], 76), 4)
        self.assertIsNone(metrics.percentile([], 50))
        for bad in (0, -1, 101):
            with self.assertRaises(ValueError):
                metrics.percentile([1], bad)

    def test_it_returns_only_observed_values(self):
        v = [0.1, 0.2, 0.9]
        for p in (50, 90, 95, 99):
            self.assertIn(metrics.percentile(v, p), v)

    def test_summary_flags_low_sample_percentiles(self):
        s = metrics.summarize([1.0, 2.0, 3.0], "s")
        self.assertEqual((s["n"], s["min"], s["max"], s["p50"], s["p99"]), (3, 1.0, 3.0, 2.0, 3.0))
        self.assertEqual(s["low_sample"], ["p90", "p95", "p99"])
        self.assertEqual(metrics.summarize(range(200), "s")["low_sample"], [])
        empty = metrics.summarize([], "s")
        self.assertEqual((empty["n"], empty["p50"], empty["mean"]), (0, None, None))
        self.assertEqual(metrics.summarize([None, 1.0], "s")["n"], 1)

    def test_rate_and_seconds_between(self):
        self.assertEqual(metrics.rate(10, 4), 2.5)
        self.assertIsNone(metrics.rate(10, 0))
        self.assertIsNone(metrics.seconds_between(None, None))


class UsageTests(unittest.TestCase):
    def test_fake_usage_has_no_tokens_and_no_cost(self):
        u = metrics.usage_summary([{"usage": {"model_calls": 1, "tokens_available": False, "tokens_note": "a fake model reports no token counts", "total_tokens": None}}] * 3)
        self.assertEqual((u["model_calls"], u["tokens_available"], u["total_tokens"], u["cost_usd"]), (3, False, None, None))
        self.assertIn("unavailable", u["cost_note"])

    def test_tokens_are_summed_only_when_every_job_reported_them(self):
        full = {"usage": {"model_calls": 1, "tokens_available": True, "prompt_tokens": 10, "output_tokens": 5, "thinking_tokens": 0, "total_tokens": 15}}
        self.assertEqual(metrics.usage_summary([full, full])["total_tokens"], 30)
        partial = {"usage": {"model_calls": 1, "tokens_available": False, "tokens_note": "x"}}
        mixed = metrics.usage_summary([full, partial])
        self.assertIsNone(mixed["total_tokens"])
        self.assertFalse(mixed["tokens_available"])

    def test_cost_is_never_computed(self):
        full = {"usage": {"model_calls": 1, "tokens_available": True, "prompt_tokens": 10, "output_tokens": 5, "thinking_tokens": 0, "total_tokens": 15}}
        self.assertIsNone(metrics.usage_summary([full])["cost_usd"])

    def test_validator_rejects_invented_tokens_or_cost(self):
        res = _small_results()
        self.assertEqual(metrics.validate_results(res), [])
        bad = json.loads(json.dumps(res))
        bad["usage"].update(total_tokens=100)
        self.assertTrue(metrics.validate_results(bad))
        bad = json.loads(json.dumps(res))
        bad["usage"]["cost_usd"] = 1.5
        self.assertTrue(metrics.validate_results(bad))
        bad = json.loads(json.dumps(res))
        bad["usage"].update(tokens_available=True)
        self.assertTrue(any("fake" in p for p in metrics.validate_results(bad)))
        bad = json.loads(json.dumps(res))
        del bad["latency"]["queue_wait_s"]
        self.assertTrue(metrics.validate_results(bad))
        self.assertTrue(metrics.validate_results({}))


_CACHE = {}


def _small_results(**kw):
    key = tuple(sorted(kw.items()))
    if key not in _CACHE:
        cfg = run.LoadConfig(total=kw.pop("total", 24), concurrency=4, duplicates=kw.pop("duplicates", 0.25), seed=3, drain_timeout=30, **kw)
        b = backend.InProcessBackend(workers=3, model_delay=0.01)
        b.start()
        try:
            _CACHE[key] = run.run_load(cfg, client.InProcessClient(b), b.describe(), True, "FAKE:canned", "inprocess")
        finally:
            b.stop()
    return json.loads(json.dumps(_CACHE[key], default=str))


class InProcessRunTests(unittest.TestCase):
    def test_results_are_complete_and_consistent(self):
        r = _small_results()
        self.assertEqual(metrics.validate_results(r), [])
        c = r["counts"]
        self.assertEqual(c["submissions"], 30)
        self.assertEqual(c["jobs_created"], 24)
        self.assertEqual(c["duplicates_recognised"], 6)
        self.assertEqual(c["succeeded"] + c["failed"] + c["timed_out"] + c["unfinished_at_drain_timeout"], c["jobs_created"])
        self.assertEqual(c["succeeded"], 24)
        self.assertEqual(c["http_status"], {"200": 6, "202": 24})
        self.assertEqual(r["latency"]["end_to_end_s"]["n"], 24)
        self.assertEqual(r["latency"]["api_submit_ms"]["n"], 30)
        self.assertTrue(r["meta"]["fake_model"])

    def test_latency_parts_add_up(self):
        r = _small_results()
        rows = r["_rows"]
        checked = 0
        for row in rows:
            if row.get("end_to_end_s") is not None and row["attempts"] == 1:
                self.assertAlmostEqual(row["queue_wait_s"] + row["processing_s"], row["end_to_end_s"], delta=0.05)
                checked += 1
        self.assertGreater(checked, 10)
        lat = r["latency"]
        self.assertLessEqual(lat["end_to_end_s"]["p50"], lat["end_to_end_s"]["p99"])
        self.assertGreaterEqual(lat["processing_s"]["min"], 0.01 * 0.9, "the simulated model delay must show up in processing time")

    def test_per_node_timing_present_and_labelled(self):
        r = _small_results()
        self.assertIn("verdict_node", r["per_node"])
        self.assertIn("supervisor", r["per_node"])
        self.assertGreater(r["per_node"]["verdict_node"]["seconds_per_job"]["mean"], 0.005)

    def test_no_tokens_and_no_cost_for_a_fake_model(self):
        u = _small_results()["usage"]
        self.assertEqual((u["tokens_available"], u["total_tokens"], u["cost_usd"]), (False, None, None))
        text = report.render(_strip_rows(_small_results()))
        self.assertIn("Tokens: unavailable", text)
        self.assertIn("Cost: unavailable", text)
        self.assertIn("FAKE", text)

    def test_honesty_notes_say_the_model_is_fake_and_simulated(self):
        notes = " ".join(_small_results()["honesty"])
        self.assertIn("FAKE", notes)
        self.assertIn("SIMULATED", notes)
        self.assertIn("nearest-rank", notes)

    def test_failure_injection_shows_up_in_outcomes(self):
        ids = ["LT-%06d" % i for i in range(40)]
        table = backend.scenario_table(ids, backend.parse_mix("permanent=0.25"), 5)
        self.assertTrue(5 <= len(table) <= 15)
        cfg = run.LoadConfig(total=40, concurrency=4, seed=5, drain_timeout=30)
        b = backend.InProcessBackend(workers=3, model_delay=0.0, scenarios=table, seed=5)
        b.start()
        try:
            r = run.run_load(cfg, client.InProcessClient(b), b.describe(), True, "FAKE:canned", "inprocess")
        finally:
            b.stop()
        self.assertEqual(r["counts"]["failed"], len(table))
        self.assertEqual(r["errors"]["by_error_code"], {"model_rejected": len(table)})
        self.assertEqual(r["counts"]["succeeded"], 40 - len(table))

    def test_api_rate_limit_shows_up_as_429s(self):
        cfg = run.LoadConfig(total=20, concurrency=2, seed=1, drain_timeout=20)
        b = backend.InProcessBackend(workers=2, model_delay=0.0, api_rate_per_minute=60, api_burst=5)
        b.start()
        try:
            r = run.run_load(cfg, client.InProcessClient(b), b.describe(), True, "FAKE:canned", "inprocess")
        finally:
            b.stop()
        self.assertGreater(r["counts"]["http_status"].get("429", 0), 0)
        self.assertEqual(r["counts"]["http_status"].get("202", 0), r["counts"]["jobs_created"])
        self.assertEqual(r["errors"]["http_non_success"], {"429": r["counts"]["http_status"]["429"]})

    def test_open_loop_pacing_is_respected(self):
        cfg = run.LoadConfig(total=21, rate=100.0, concurrency=4, seed=1, drain_timeout=20)
        b = backend.InProcessBackend(workers=2, model_delay=0.0)
        b.start()
        try:
            r = run.run_load(cfg, client.InProcessClient(b), b.describe(), True, "FAKE:canned", "inprocess")
        finally:
            b.stop()
        self.assertGreaterEqual(r["throughput"]["submit_window_s"], 0.19)
        self.assertEqual(r["parameters"]["pattern"], "open loop")

    def test_unfinished_jobs_are_counted_not_hidden(self):
        cfg = run.LoadConfig(total=6, concurrency=2, seed=1, drain_timeout=0.3)
        b = backend.InProcessBackend(workers=1, model_delay=0.5)
        b.start()
        try:
            r = run.run_load(cfg, client.InProcessClient(b), b.describe(), True, "FAKE:canned", "inprocess")
        finally:
            b.stop()
        self.assertGreater(r["counts"]["unfinished_at_drain_timeout"], 0)
        self.assertEqual(r["counts"]["succeeded"] + r["counts"]["failed"] + r["counts"]["timed_out"] + r["counts"]["unfinished_at_drain_timeout"], 6)


def _strip_rows(r):
    r = dict(r)
    r.pop("_rows", None)
    return r


class WorkloadTests(unittest.TestCase):
    def test_submissions_are_deterministic_for_a_seed(self):
        a = run.build_submissions(run.LoadConfig(total=30, duplicates=0.2, seed=9))
        b = run.build_submissions(run.LoadConfig(total=30, duplicates=0.2, seed=9))
        c = run.build_submissions(run.LoadConfig(total=30, duplicates=0.2, seed=10))
        self.assertEqual(a, b)
        self.assertNotEqual([x[1]["alert_id"] for x in a], [x[1]["alert_id"] for x in c])
        self.assertEqual(len(a), 36)
        self.assertEqual(len({x[1]["alert_id"] for x in a}), 30)

    def test_config_validation(self):
        for kw in ({"total": 0}, {"rate": -1}, {"concurrency": 0}, {"concurrency": 9999}, {"duplicates": 0.95}):
            with self.assertRaises(ValueError):
                run.LoadConfig(**kw)

    def test_failure_mix_parsing(self):
        self.assertEqual(backend.parse_mix("unavailable=0.1, malformed=0.2"), {"unavailable": 0.1, "malformed": 0.2})
        self.assertEqual(backend.parse_mix(""), {})
        for bad in ("bogus=0.1", "unavailable", "unavailable=2", "unavailable=0.7,malformed=0.5", "ok_benign=0.1"):
            with self.assertRaises(ValueError):
                backend.parse_mix(bad)

    def test_scenario_table_is_deterministic_and_proportional(self):
        ids = ["A-%d" % i for i in range(2000)]
        t = backend.scenario_table(ids, {"unavailable": 0.1, "malformed": 0.2}, 1)
        self.assertEqual(t, backend.scenario_table(ids, {"unavailable": 0.1, "malformed": 0.2}, 1))
        counts = {k: sum(1 for v in t.values() if v == k) for k in ("unavailable", "malformed")}
        self.assertAlmostEqual(counts["unavailable"] / 2000, 0.1, delta=0.03)
        self.assertAlmostEqual(counts["malformed"] / 2000, 0.2, delta=0.03)


class HttpModeTests(unittest.TestCase):
    def test_http_mode_against_a_local_server(self):
        rig = W5.ApiRig()
        token_env = "WEEK5_LT_TEST_TOKEN"
        stop = threading.Event()
        worker_thread = threading.Thread(target=lambda: [rig.worker.run_once() or stop.wait(0.005) for _ in iter(stop.is_set, True)], daemon=True)
        rig.repo.upsert_analyst("loadtester", "analyst")
        from week4.api import auth
        rig.api.auth.token_hashes["loadtester"] = auth.hash_token("L" * 40)
        worker_thread.start()
        try:
            with W5.HttpStub(rig.api) as stub, unittest.mock.patch.dict(os.environ, {token_env: "L" * 40}):
                c = client.HttpClient(stub.url, token_env)
                cfg = run.LoadConfig(total=10, concurrency=3, duplicates=0.2, seed=2, drain_timeout=30)
                r = run.run_load(cfg, c, {"base_url_host": "127.0.0.1"}, None, "reported by the server", "http")
        finally:
            stop.set()
            worker_thread.join(timeout=3)
        self.assertEqual(metrics.validate_results(r), [])
        self.assertEqual(r["meta"]["mode"], "http")
        self.assertIs(r["meta"]["fake_model"], True, "the server's own jobs say they used a fake model")
        self.assertEqual((r["counts"]["jobs_created"], r["counts"]["succeeded"], r["counts"]["duplicates_recognised"]), (10, 10, 2))

    def test_client_refusals(self):
        with unittest.mock.patch.dict(os.environ, {"T": "x" * 40}):
            with self.assertRaises(ValueError):
                client.HttpClient("http://example.com:8000", "T")
            with self.assertRaises(ValueError):
                client.HttpClient("ftp://127.0.0.1", "T")
            client.HttpClient("http://example.com:8000", "T", allow_remote=True)
            client.HttpClient("http://127.0.0.1:8000", "T")
        with unittest.mock.patch.dict(os.environ, {"T": ""}):
            with self.assertRaises(ValueError):
                client.HttpClient("http://127.0.0.1:8000", "T")

    def test_a_dead_server_gives_status_zero_not_an_exception(self):
        with unittest.mock.patch.dict(os.environ, {"T": "x" * 40}):
            c = client.HttpClient("http://127.0.0.1:9", "T", timeout=1)
            self.assertEqual(c.submit({"a": 1})[0], 0)


def read_text(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(list(args))
        return code, out.getvalue()

    def test_run_writes_json_csv_and_report_then_report_command_agrees(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out = self.run_cli("run", "--total", "12", "--workers", "2", "--model-delay", "0", "--out-dir", tmp, "--duplicates", "0.25")
            self.assertEqual(code, 0, out)
            names = sorted(os.listdir(tmp))
            self.assertEqual(names, ["jobs.csv", "report.md", "results.json", "summary.csv"])
            res = json.loads(read_text(os.path.join(tmp, "results.json")))
            self.assertEqual(metrics.validate_results(res), [])
            self.assertNotIn("_rows", res)
            lines = read_text(os.path.join(tmp, "jobs.csv")).strip().splitlines()
            self.assertEqual(len(lines), 1 + 15)
            self.assertEqual(lines[0].split(","), list(run.ROW_COLUMNS))
            summary = read_text(os.path.join(tmp, "summary.csv")).splitlines()
            self.assertEqual(summary[0].split(","), list(metrics.SUMMARY_COLUMNS))
            self.assertTrue(any(l.startswith("end_to_end_s,") for l in summary))
            code, again = self.run_cli("report", "--results", os.path.join(tmp, "results.json"))
            self.assertEqual(code, 0)
            self.assertEqual(again, read_text(os.path.join(tmp, "report.md")))

    def test_bad_arguments_stop_cleanly(self):
        for args in (("run", "--total", "0"), ("run", "--mode", "http"), ("run", "--failure-mix", "bogus=1"), ("run", "--duplicates", "0.99")):
            code, out = self.run_cli(*args)
            self.assertEqual(code, 2, args)
            self.assertIn("STOPPED", out)

    def test_report_refuses_an_invalid_results_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "x.json")
            with open(path, "w") as fh:
                json.dump({"schema": "nope"}, fh)
            code, out = self.run_cli("report", "--results", path)
            self.assertEqual(code, 2)
            self.assertIn("not valid", out)

    def test_there_is_no_live_model_option(self):
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                cli.main(["run", "--model", "gemini"])


class ReportTests(unittest.TestCase):
    def test_report_contains_every_latency_metric_and_the_machine(self):
        text = report.render(_strip_rows(_small_results()))
        for word in ("api_submit_ms", "queue_wait_s", "processing_s", "end_to_end_s", "p95", "p99", "CPU", "Python", "Time per graph node", "How to read this"):
            self.assertIn(word, text)


if __name__ == "__main__":
    unittest.main()
