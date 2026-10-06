import io
import ast
import os
import contextlib
import re
import sys
import json
import shutil
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

import pandas as pd

import config
import llm_config
import verdict_schema
import baseline_prompt
import baseline_store as store
import gemini_client
import run_baseline_dev as runner

PINNED_PROMPT_SHA256 = "0208c856dc1063ef5e249fcffdb28af803bd2899fa87977dde0ac4a23b06f172"

MODULES = ["baseline_prompt.py", "gemini_client.py", "baseline_store.py", "run_baseline_dev.py"]

GOOD_MALICIOUS = {"is_malicious": True, "attack_type": "PortScan", "mitre_technique": "T1046", "severity": "medium",
                  "evidence": "One source sent 800 tiny flows to 790 different destination ports within two minutes."}
GOOD_BENIGN = {"is_malicious": False, "attack_type": "BENIGN", "mitre_technique": "NONE", "severity": "none",
               "evidence": "Single short HTTPS flow with normal packet sizes."}
GOOD = json.dumps(GOOD_MALICIOUS)
FAKE_KEY = "FAKE-KEY-DO-NOT-STORE-12345"


def read_source(name):
    with open(os.path.join(ROOT, "src", name), encoding="utf-8") as f:
        return f.read()


def make_alerts(n):
    rows = []
    for i in range(n):
        row = {name: 1.0 for name in baseline_prompt.ALERT_FIELDS}
        row["alert_id"] = "DEV-%04d" % (i + 1)
        row["flow_row"] = i
        row["timestamp"] = pd.Timestamp("2017-07-05 10:00:00") + pd.Timedelta(minutes=i)
        row["flow_id"] = "10.0.0.%d-10.0.1.1-5000-80-6" % (i + 1)
        row["src_ip"] = "10.0.0.1"
        row["dst_ip"] = "10.0.1.1"
        row["detector_score"] = 0.5
        rows.append(row)
    return pd.DataFrame(rows)


def make_flows(n):
    return pd.DataFrame({
        "flow_row": range(n),
        "timestamp": [pd.Timestamp("2017-07-05 10:00:00") + pd.Timedelta(minutes=i) for i in range(n)],
        "src_ip": ["10.0.0.1"] * n,
        "dst_ip": ["10.0.1.1"] * n,
        "dst_port": [80 + i for i in range(n)],
    })


class FakeTime:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now = self.now + seconds


class FakeClient:
    def __init__(self, script=None, on_call=None):
        self.script = list(script or [])
        self.prompts = []
        self.on_call = on_call

    def generate(self, prompt):
        self.prompts.append(prompt)
        if self.on_call is not None:
            self.on_call(len(self.prompts))
        if len(self.script) > 0:
            item = self.script.pop(0)
        else:
            item = GOOD
        if isinstance(item, Exception):
            raise item
        return gemini_client.CallRecord(text=item, finish_reason="STOP", block_reason=None, prompt_tokens=100, output_tokens=50,
                                        thinking_tokens=None, total_tokens=150)


def transient(code=503):
    return gemini_client.TransientModelError("busy", code)


class CodeError(Exception):
    def __init__(self, code):
        Exception.__init__(self, "error " + str(code))
        self.code = code


class ReadTimeout(Exception):
    pass


class PromptTests(unittest.TestCase):
    def test_prompt_is_pinned(self):
        self.assertEqual(baseline_prompt.PROMPT_VERSION, "baseline_v1")
        self.assertEqual(baseline_prompt.prompt_sha256(), PINNED_PROMPT_SHA256,
                         "the baseline prompt text changed. Baseline v1 is not to be edited; make a new version instead.")

    def test_system_prompt_lists_the_five_fields_and_all_classes(self):
        text = baseline_prompt.SYSTEM_PROMPT
        for field in verdict_schema.FIELDS:
            self.assertIn(field + ":", text)
        for name in verdict_schema.ATTACK_TYPES:
            self.assertIn(name, text)
        for severity in verdict_schema.SEVERITIES:
            self.assertIn(severity, text)
        for dropped in ["Infiltration", "Heartbleed"]:
            self.assertNotIn(dropped, text)

    def test_system_prompt_has_no_answer_key_and_no_tools(self):
        lowered = baseline_prompt.SYSTEM_PROMPT.lower()
        for word in ["ground truth", "answer key", "frozen", "label"]:
            self.assertNotIn(word, lowered)
        ids = set(re.findall(r"T\d{4}(?:\.\d{3})?", baseline_prompt.SYSTEM_PROMPT))
        self.assertEqual(ids, {"T1059", "T1059.001"})
        self.assertIn("no tools", lowered)

    def test_user_prompt_holds_the_alert_as_json(self):
        import triage_inputs
        alerts = make_alerts(3)
        model_input, prompt = baseline_prompt.build_prompt_for_row(alerts.iloc[1], make_flows(3))
        self.assertIn("DEV-0002", prompt)
        body = prompt.split("Alert:\n", 1)[1].rsplit("\n\nReply with", 1)[0]
        parsed = json.loads(body)
        self.assertEqual(parsed["alert"]["alert_id"], "DEV-0002")
        self.assertNotIn("flow_row", parsed["alert"])
        self.assertEqual(sorted(parsed.keys()), ["alert", "context"])
        self.assertEqual(parsed["context"]["window_minutes"], triage_inputs.CONTEXT_WINDOW_MINUTES)

    def test_extra_or_missing_fields_are_refused(self):
        alerts = make_alerts(2)
        flows = make_flows(2)
        import triage_inputs
        good = triage_inputs.build_model_input(alerts.iloc[0], flows)
        baseline_prompt.check_model_input(good)
        for extra in ["label", "is_attack", "source_file", "original_row", "mitre_technique_id", "source_alert_id", "anything_else"]:
            bad = json.loads(json.dumps(good))
            bad["alert"][extra] = "x"
            with self.assertRaises(ValueError, msg=extra):
                baseline_prompt.check_model_input(bad)
        missing = json.loads(json.dumps(good))
        del missing["alert"]["detector_score"]
        with self.assertRaises(ValueError):
            baseline_prompt.check_model_input(missing)
        bad_context = json.loads(json.dumps(good))
        bad_context["context"]["extra"] = 1
        with self.assertRaises(ValueError):
            baseline_prompt.check_model_input(bad_context)

    def test_missing_number_is_refused(self):
        alerts = make_alerts(2)
        alerts.loc[0, "Flow Duration"] = float("nan")
        with self.assertRaises(ValueError):
            baseline_prompt.build_prompt_for_row(alerts.iloc[0], make_flows(2))

    def test_user_prompt_has_no_class_names(self):
        alerts = make_alerts(2)
        model_input, prompt = baseline_prompt.build_prompt_for_row(alerts.iloc[0], make_flows(2))
        for name in verdict_schema.ATTACK_TYPES:
            self.assertNotIn(name, prompt)


class ClientTests(unittest.TestCase):
    def test_response_is_read_with_usage_and_finish_reason(self):
        class Enum:
            name = "STOP"

        class Cand:
            finish_reason = Enum()

        class Usage:
            prompt_token_count = 10
            candidates_token_count = 5
            thoughts_token_count = None
            total_token_count = 15

        class Response:
            text = "hello"
            candidates = [Cand()]
            usage_metadata = Usage()
            prompt_feedback = None

        record = gemini_client.read_response(Response())
        self.assertEqual((record.text, record.finish_reason, record.prompt_tokens, record.output_tokens, record.total_tokens),
                         ("hello", "STOP", 10, 5, 15))
        self.assertIsNone(record.thinking_tokens)

    def test_empty_or_blocked_response_gives_empty_text_not_an_error(self):
        class Enum:
            name = "SAFETY"

        class Feedback:
            block_reason = Enum()

        class Response:
            text = None
            candidates = None
            usage_metadata = None
            prompt_feedback = Feedback()

        record = gemini_client.read_response(Response())
        self.assertEqual(record.text, "")
        self.assertEqual(record.block_reason, "SAFETY")

    def test_text_property_that_raises_gives_empty_text(self):
        class Response:
            candidates = None
            usage_metadata = None
            prompt_feedback = None

            @property
            def text(self):
                raise ValueError("no text part")

        self.assertEqual(gemini_client.read_response(Response()).text, "")

    def test_generate_sends_model_prompt_and_settings(self):
        seen = {}

        class Models:
            def generate_content(self, model, contents, config):
                seen.update(model=model, contents=contents, config=config)

                class Response:
                    text = "ok"
                    candidates = None
                    usage_metadata = None
                    prompt_feedback = None
                return Response()

        class Sdk:
            models = Models()

        client = gemini_client.GeminiClient("gemini-test", "SYSTEM", 0.0, 1024, 42, api_key=FAKE_KEY, sdk_client=Sdk())
        self.assertEqual(client.generate("PROMPT").text, "ok")
        self.assertEqual(seen["model"], "gemini-test")
        self.assertEqual(seen["contents"], "PROMPT")
        self.assertEqual(seen["config"], {"system_instruction": "SYSTEM", "temperature": 0.0, "max_output_tokens": 1024, "seed": 42})

    def test_classification(self):
        for code in [408, 429, 500, 503, 504]:
            self.assertEqual(gemini_client.classify_exception(CodeError(code)), "transient", code)
        for code in [400, 401, 403, 404]:
            self.assertEqual(gemini_client.classify_exception(CodeError(code)), "permanent", code)
        self.assertEqual(gemini_client.classify_exception(ReadTimeout("slow")), "transient")
        self.assertEqual(gemini_client.classify_exception(TimeoutError("slow")), "transient")
        self.assertEqual(gemini_client.classify_exception(ConnectionError("down")), "transient")
        self.assertEqual(gemini_client.classify_exception(ValueError("bug")), "permanent")
        self.assertEqual(gemini_client.classify_exception(AttributeError("bug")), "permanent")

    def test_errors_are_wrapped_and_the_key_is_removed(self):
        class Models:
            def generate_content(self, model, contents, config):
                raise RuntimeError("bad key " + FAKE_KEY)

        class Sdk:
            models = Models()

        client = gemini_client.GeminiClient("m", "S", 0.0, 10, 1, api_key=FAKE_KEY, sdk_client=Sdk())
        with self.assertRaises(gemini_client.PermanentModelError) as caught:
            client.generate("p")
        self.assertNotIn(FAKE_KEY, str(caught.exception))
        self.assertIn("[redacted]", str(caught.exception))

        class Models503:
            def generate_content(self, model, contents, config):
                raise CodeError(503)

        class Sdk503:
            models = Models503()

        client = gemini_client.GeminiClient("m", "S", 0.0, 10, 1, api_key=FAKE_KEY, sdk_client=Sdk503())
        with self.assertRaises(gemini_client.TransientModelError) as caught:
            client.generate("p")
        self.assertEqual(caught.exception.status, 503)

    def test_sdk_is_imported_only_inside_a_function(self):
        tree = ast.parse(read_source("gemini_client.py"))
        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [a.name for a in node.names] + [getattr(node, "module", "") or ""]
                self.assertFalse(any(n.startswith("google") for n in names))


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_jsonl_round_trip_and_unfinished_last_line(self):
        path = os.path.join(self.tmp, "x.jsonl")
        store.append_jsonl(path, {"alert_id": "A", "n": 1})
        store.append_jsonl(path, {"alert_id": "B", "n": 2})
        self.assertEqual(len(store.read_jsonl(path)), 2)
        with open(path, "a") as f:
            f.write('{"alert_id": "C", "n"')
        with self.assertRaises(ValueError):
            store.read_jsonl(path)
        records = store.read_jsonl(path, repair=True)
        self.assertEqual([r["alert_id"] for r in records], ["A", "B"])
        store.append_jsonl(path, {"alert_id": "C", "n": 3})
        self.assertEqual([r["alert_id"] for r in store.read_jsonl(path)], ["A", "B", "C"])

    def test_latest_result_wins(self):
        latest = store.latest_results([{"alert_id": "A", "status": "model_error"}, {"alert_id": "B", "status": "ok"},
                                       {"alert_id": "A", "status": "ok"}])
        self.assertEqual(latest["A"]["status"], "ok")
        self.assertEqual(len(latest), 2)

    def test_csv_leaves_failed_alerts_blank(self):
        path = os.path.join(self.tmp, "v.csv")
        latest = {"A": {"alert_id": "A", "status": "ok", "verdict": dict(GOOD_MALICIOUS), "attempts": 1, "malformed_first_try": False},
                  "B": {"alert_id": "B", "status": "parse_failed", "verdict": None, "attempts": 3, "malformed_first_try": True,
                        "error_code": "no_json"}}
        store.write_verdicts_csv(path, ["A", "B", "C"], latest)
        frame = pd.read_csv(path, keep_default_na=False)
        self.assertEqual(list(frame["alert_id"]), ["A", "B"])
        self.assertEqual(frame.loc[1, "attack_type"], "")
        self.assertEqual(frame.loc[1, "error_code"], "no_json")


class RunnerCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.time = FakeTime()
        self.patches = [
            mock.patch.object(runner, "SLEEP", self.time.sleep),
            mock.patch.object(runner, "CLOCK", self.time.clock),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_dir(self):
        path = os.path.join(self.tmp, "run")
        os.makedirs(path, exist_ok=True)
        return store.RunDir(path)

    def process(self, script, alert_id="DEV-0001", prompt="PROMPT", retries=2):
        run_dir = self.run_dir()
        client = FakeClient(script)
        caller = runner.RecordingCaller(client, runner.Throttle(600), run_dir, 1, "gemini-test")
        record = runner.process_alert(alert_id, prompt, caller, 1, retries)
        return record, client, run_dir


class ProcessAlertTests(RunnerCase):
    def test_valid_reply_is_ok_and_raw_text_is_kept(self):
        record, client, run_dir = self.process([GOOD])
        self.assertEqual(record["status"], "ok")
        self.assertEqual(record["verdict"], GOOD_MALICIOUS)
        self.assertEqual(record["attempts"], 1)
        self.assertFalse(record["malformed_first_try"])
        raw = store.read_jsonl(run_dir.raw)
        self.assertEqual(len(raw), 1)
        self.assertEqual(raw[0]["reply"], GOOD)
        self.assertEqual(raw[0]["prompt"], "PROMPT")
        self.assertEqual(raw[0]["alert_id"], "DEV-0001")
        self.assertEqual(raw[0]["outcome"], "reply")
        self.assertEqual(raw[0]["total_tokens"], 150)
        self.assertEqual(record["total_tokens"], 150)

    def test_benign_reply(self):
        record, client, run_dir = self.process([json.dumps(GOOD_BENIGN)])
        self.assertEqual(record["status"], "ok")
        self.assertFalse(record["verdict"]["is_malicious"])

    def test_fenced_reply_is_repaired_locally_and_raw_text_keeps_the_fence(self):
        fenced = "```json\n" + GOOD + "\n```"
        record, client, run_dir = self.process([fenced])
        self.assertEqual(record["status"], "ok")
        self.assertEqual(record["attempts"], 1)
        self.assertIn("removed_code_fence", record["repairs"])
        self.assertEqual(store.read_jsonl(run_dir.raw)[0]["reply"], fenced)

    def test_malformed_then_valid_uses_one_retry_and_keeps_both_replies(self):
        record, client, run_dir = self.process(["I think this is a port scan.", GOOD])
        self.assertEqual(record["status"], "ok")
        self.assertEqual(record["attempts"], 2)
        self.assertTrue(record["malformed_first_try"])
        self.assertEqual(record["attempt_log"][0]["error_code"], "no_json")
        raw = store.read_jsonl(run_dir.raw)
        self.assertEqual([r["call_index"] for r in raw], [1, 2])
        self.assertEqual(raw[0]["reply"], "I think this is a port scan.")
        self.assertIn("Your previous reply could not be used", raw[1]["prompt"])
        self.assertIn("I think this is a port scan.", raw[1]["prompt"])
        self.assertEqual(len(client.prompts), 2)

    def test_always_malformed_is_parse_failed_and_no_verdict_is_invented(self):
        record, client, run_dir = self.process(["nope", "still nope", "{}"])
        self.assertEqual(record["status"], "parse_failed")
        self.assertIsNone(record["verdict"])
        self.assertEqual(record["error_code"], "missing_fields")
        self.assertEqual(record["attempts"], 3)
        self.assertTrue(record["malformed_first_try"])
        self.assertEqual(len(store.read_jsonl(run_dir.raw)), 3)
        self.assertEqual(len(client.prompts), 3)

    def test_contradictory_reply_is_not_accepted_or_fixed(self):
        bad = json.dumps(dict(GOOD_MALICIOUS, is_malicious=False))
        record, client, run_dir = self.process([bad, bad, bad])
        self.assertEqual(record["status"], "parse_failed")
        self.assertEqual(record["error_code"], "contradictory")
        self.assertIsNone(record["verdict"])

    def test_empty_reply_from_the_model_is_retried(self):
        record, client, run_dir = self.process(["", GOOD])
        self.assertEqual(record["status"], "ok")
        self.assertEqual(record["attempt_log"][0]["error_code"], "empty_response")

    def test_transient_error_is_retried_with_backoff(self):
        record, client, run_dir = self.process([transient(503), transient(429), GOOD])
        self.assertEqual(record["status"], "ok")
        self.assertEqual(record["attempts"], 1)
        self.assertEqual(self.time.sleeps[:2], runner.BACKOFF_SECONDS[:2])
        raw = store.read_jsonl(run_dir.raw)
        self.assertEqual(len(raw), 1)
        self.assertEqual([e["status"] for e in raw[0]["transport_errors"]], [503, 429])

    def test_transient_errors_that_never_stop_give_model_error_and_no_verdict(self):
        record, client, run_dir = self.process([transient()] * (runner.TRANSPORT_RETRIES + 1))
        self.assertEqual(record["status"], "model_error")
        self.assertIsNone(record["verdict"])
        self.assertEqual(record["error_code"], "model_unavailable")
        self.assertEqual(record["model_calls"], 0)
        self.assertEqual(len(client.prompts), runner.TRANSPORT_RETRIES + 1)
        raw = store.read_jsonl(run_dir.raw)
        self.assertEqual(raw[-1]["outcome"], "transport_failed")
        self.assertIsNone(raw[-1]["reply"])
        self.assertEqual(len(raw[-1]["transport_errors"]), runner.TRANSPORT_RETRIES + 1)

    def test_model_error_after_a_bad_reply_keeps_that_reply_in_the_log(self):
        script = ["not json"] + [transient()] * (runner.TRANSPORT_RETRIES + 1)
        record, client, run_dir = self.process(script)
        self.assertEqual(record["status"], "model_error")
        self.assertEqual(record["attempts"], 1)
        self.assertEqual(record["attempt_log"][0]["error_code"], "no_json")
        self.assertTrue(record["malformed_first_try"])
        self.assertEqual(len(store.read_jsonl(run_dir.raw)), 2)

    def test_permanent_error_is_recorded_raw_and_raised(self):
        run_dir = self.run_dir()
        client = FakeClient([gemini_client.PermanentModelError("API key not valid", 400)])
        caller = runner.RecordingCaller(client, runner.Throttle(600), run_dir, 1, "gemini-test")
        with self.assertRaises(gemini_client.PermanentModelError):
            runner.process_alert("DEV-0001", "PROMPT", caller, 1, 2)
        raw = store.read_jsonl(run_dir.raw)
        self.assertEqual(raw[0]["outcome"], "permanent_error")
        self.assertEqual(store.read_jsonl(run_dir.results), [])

    def test_tokens_and_latency_are_summed_over_retries(self):
        record, client, run_dir = self.process(["nope", GOOD])
        self.assertEqual(record["model_calls"], 2)
        self.assertEqual(record["total_tokens"], 300)
        self.assertEqual(record["prompt_tokens"], 200)
        self.assertEqual(record["finish_reasons"], ["STOP", "STOP"])

    def test_zero_parse_retries(self):
        record, client, run_dir = self.process(["nope", GOOD], retries=0)
        self.assertEqual(record["status"], "parse_failed")
        self.assertEqual(len(client.prompts), 1)


class ThrottleAndLoopTests(RunnerCase):
    def test_calls_are_spaced_by_the_rate_limit(self):
        throttle = runner.Throttle(10)
        stamps = []
        for i in range(4):
            throttle.wait()
            stamps.append(self.time.now)
        for i in range(1, 4):
            self.assertGreaterEqual(stamps[i] - stamps[i - 1], 6.0 - 1e-9)

    def test_retry_calls_are_throttled_too(self):
        record, client, run_dir = self.process(["nope", GOOD])
        self.assertGreaterEqual(self.time.now, 0.1 - 1e-9)

    def test_loop_stops_after_consecutive_model_errors(self):
        run_dir = self.run_dir()
        ids = ["DEV-%04d" % i for i in range(1, 9)]
        prompts = {i: "P " + i for i in ids}
        client = FakeClient([transient()] * 100)
        caller = runner.RecordingCaller(client, runner.Throttle(600), run_dir, 1, "m")
        said = []
        ended = runner.run_alerts(ids, prompts, run_dir, caller, 1, 2, say=said.append)
        self.assertEqual(ended, "stopped_after_model_errors")
        self.assertEqual(len(store.read_jsonl(run_dir.results)), runner.MAX_CONSECUTIVE_MODEL_ERRORS)

    def test_a_good_alert_resets_the_error_streak(self):
        run_dir = self.run_dir()
        ids = ["DEV-%04d" % i for i in range(1, 8)]
        prompts = {i: "P " + i for i in ids}
        bad = [transient()] * (runner.TRANSPORT_RETRIES + 1)
        script = bad * 4 + [GOOD] + bad * 2
        client = FakeClient(script)
        caller = runner.RecordingCaller(client, runner.Throttle(600), run_dir, 1, "m")
        ended = runner.run_alerts(ids, prompts, run_dir, caller, 1, 2, say=lambda x: None)
        self.assertEqual(ended, "finished")
        statuses = [r["status"] for r in store.read_jsonl(run_dir.results)]
        self.assertEqual(statuses, ["model_error"] * 4 + ["ok"] + ["model_error"] * 2)


class MainTests(RunnerCase):
    def setUp(self):
        RunnerCase.setUp(self)
        self.alerts = make_alerts(5)
        self.flows = make_flows(5)
        self.log_path = os.path.join(self.tmp, "frozen_access.log")
        with open(self.log_path, "w") as f:
            f.write("2026-10-03T18:40:50Z\talerts\t-c\tQA read\n")
        self.runs_dir = os.path.join(self.tmp, "runs")
        self.client = FakeClient()
        self.extra = []
        self.patches2 = [
            mock.patch.object(runner, "load_inputs", lambda: (self.alerts, self.flows, {"dev_alerts_sha256": "a", "flow_store_dev_sha256": "b"})),
            mock.patch.object(runner, "check_llm_config", lambda: {"small": "gemini-2.5-flash-lite", "strong": "gemini-2.5-pro"}),
            mock.patch.object(runner, "make_client", lambda model, key, timeout: self.client),
            mock.patch.object(runner, "week1_snapshot", lambda: {"x": "1"}),
            mock.patch.object(runner, "git_info", lambda: {"commit": "abc1234", "dirty": False}),
            mock.patch.object(runner, "package_versions", lambda: {}),
            mock.patch.object(config, "FROZEN_ACCESS_LOG", self.log_path),
            mock.patch.object(llm_config, "get_api_key", lambda: FAKE_KEY),
            mock.patch.dict(os.environ, {}, clear=False),
        ]
        os.environ.pop(config.FROZEN_UNLOCK_ENV, None)
        for p in self.patches2:
            p.start()

    def tearDown(self):
        for p in self.patches2:
            p.stop()
        RunnerCase.tearDown(self)

    def go(self, *extra):
        with contextlib.redirect_stdout(io.StringIO()):
            return runner.main(["--runs-dir", self.runs_dir, "--rpm", "600"] + list(extra))

    def dir_of(self, name):
        return store.RunDir(os.path.join(self.runs_dir, name))

    def test_dry_run_calls_nothing_and_writes_nothing(self):
        with mock.patch.object(runner, "make_client", side_effect=AssertionError("must not create a client")):
            code = self.go("--dry-run", "--run-name", "d")
        self.assertEqual(code, 0)
        self.assertFalse(os.path.exists(self.runs_dir))

    def test_full_run_writes_everything_day_4_needs(self):
        code = self.go("--run-name", "r1")
        self.assertEqual(code, 0)
        d = self.dir_of("r1")
        results = store.read_jsonl(d.results)
        self.assertEqual([r["alert_id"] for r in results], list(self.alerts["alert_id"]))
        self.assertTrue(all(r["status"] == "ok" for r in results))
        self.assertEqual(len(store.read_jsonl(d.raw)), 5)
        meta = store.read_json(d.meta)
        self.assertEqual(meta["status"], "complete")
        self.assertEqual(meta["set"], "dev")
        self.assertEqual(meta["model"], "gemini-2.5-flash-lite")
        self.assertEqual(meta["prompt_sha256"], baseline_prompt.prompt_sha256())
        self.assertEqual(meta["counts"], {"ok": 5, "parse_failed": 0, "model_error": 0})
        self.assertTrue(meta["frozen_access_log_unchanged"])
        self.assertTrue(meta["week1_files_unchanged"])
        self.assertEqual(meta["selected_alert_ids"], list(self.alerts["alert_id"]))
        frame = pd.read_csv(d.verdicts_csv)
        self.assertEqual(len(frame), 5)
        self.assertTrue(os.path.exists(d.prompt_snapshot))

    def test_the_key_is_never_written_to_disk(self):
        self.go("--run-name", "r1")
        for folder, names, files in os.walk(self.runs_dir):
            for name in files:
                with open(os.path.join(folder, name), encoding="utf-8") as f:
                    self.assertNotIn(FAKE_KEY, f.read(), name)

    def test_what_the_model_received_is_only_the_alert_and_the_instructions(self):
        self.go("--run-name", "r1")
        for prompt in self.client.prompts:
            self.assertTrue(prompt.startswith("Alert:\n"))
            for word in ["label", "is_attack", "source_file", "original_row", "mitre", "frozen"]:
                self.assertNotIn(word, prompt.lower())

    def test_limit_takes_the_first_alerts(self):
        self.go("--run-name", "r1", "--limit", "2")
        self.assertEqual([r["alert_id"] for r in store.read_jsonl(self.dir_of("r1").results)], ["DEV-0001", "DEV-0002"])

    def test_existing_run_name_is_refused(self):
        self.go("--run-name", "r1")
        with self.assertRaises(SystemExit):
            self.go("--run-name", "r1")

    def test_refused_when_the_frozen_unlock_is_set(self):
        with mock.patch.dict(os.environ, {config.FROZEN_UNLOCK_ENV: config.FROZEN_UNLOCK_VALUE}):
            with self.assertRaises(SystemExit):
                self.go("--run-name", "r1")
        self.assertFalse(os.path.exists(self.runs_dir))

    def test_permanent_error_stops_the_run_and_it_can_be_resumed(self):
        self.client = FakeClient([GOOD, GOOD, gemini_client.PermanentModelError("quota", 403)])
        code = self.go("--run-name", "r1")
        self.assertEqual(code, 2)
        d = self.dir_of("r1")
        self.assertEqual(len(store.read_jsonl(d.results)), 2)
        self.assertEqual(store.read_json(d.meta)["status"], "incomplete")
        self.client = FakeClient()
        code = self.go("--resume", "--run-name", "r1")
        self.assertEqual(code, 0)
        results = store.read_jsonl(d.results)
        self.assertEqual([r["alert_id"] for r in results], list(self.alerts["alert_id"]))
        meta = store.read_json(d.meta)
        self.assertEqual(meta["status"], "complete")
        self.assertEqual(len(meta["sessions"]), 2)
        raw = store.read_jsonl(d.raw)
        self.assertEqual(sorted(set([r["session"] for r in raw])), [1, 2])
        self.assertEqual(len(self.client.prompts), 3)

    def test_resume_leaves_model_errors_alone_unless_asked(self):
        script = [GOOD] + [transient()] * (runner.TRANSPORT_RETRIES + 1) + [GOOD, GOOD, GOOD]
        self.client = FakeClient(script)
        self.go("--run-name", "r1")
        d = self.dir_of("r1")
        self.assertEqual(store.read_json(d.meta)["counts"]["model_error"], 1)
        self.assertEqual(store.read_json(d.meta)["status"], "incomplete")
        self.client = FakeClient()
        self.go("--resume", "--run-name", "r1")
        self.assertEqual(len(self.client.prompts), 0)
        self.assertEqual(store.read_json(d.meta)["counts"]["model_error"], 1)
        self.client = FakeClient()
        self.go("--resume", "--run-name", "r1", "--retry-model-errors")
        self.assertEqual(len(self.client.prompts), 1)
        meta = store.read_json(d.meta)
        self.assertEqual(meta["counts"], {"ok": 5, "parse_failed": 0, "model_error": 0})
        self.assertEqual(meta["status"], "complete")
        lines = store.read_jsonl(d.results)
        self.assertEqual(len(lines), 6)

    def test_a_parse_failed_alert_is_not_run_again_on_resume(self):
        self.client = FakeClient(["bad", "bad", "bad"])
        self.go("--run-name", "r1", "--limit", "1")
        d = self.dir_of("r1")
        self.assertEqual(store.read_json(d.meta)["counts"]["parse_failed"], 1)
        self.assertEqual(store.read_json(d.meta)["status"], "complete")
        self.client = FakeClient()
        self.go("--resume", "--run-name", "r1")
        self.assertEqual(len(self.client.prompts), 0)

    def test_resume_refuses_a_changed_prompt(self):
        self.go("--run-name", "r1", "--limit", "1")
        with mock.patch.object(baseline_prompt, "prompt_sha256", lambda: "different"):
            with self.assertRaises(SystemExit):
                self.go("--resume", "--run-name", "r1")

    def test_resume_refuses_a_changed_model(self):
        self.go("--run-name", "r1", "--limit", "1")
        with self.assertRaises(SystemExit):
            self.go("--resume", "--run-name", "r1", "--model", "strong")

    def test_change_to_the_frozen_log_during_a_run_is_reported(self):
        def touch(n):
            with open(self.log_path, "a") as f:
                f.write("2026-10-06T00:00:00Z\talerts\tx\tsomething opened it\n")
        self.client = FakeClient(on_call=touch)
        code = self.go("--run-name", "r1", "--limit", "1")
        self.assertEqual(code, 3)
        self.assertFalse(store.read_json(self.dir_of("r1").meta)["frozen_access_log_unchanged"])

    def test_change_to_a_week_1_file_during_a_run_is_reported(self):
        state = {"n": 0}

        def snapshot():
            state["n"] = state["n"] + 1
            return {"x": str(state["n"])}
        with mock.patch.object(runner, "week1_snapshot", snapshot):
            code = self.go("--run-name", "r1", "--limit", "1")
        self.assertEqual(code, 3)
        self.assertFalse(store.read_json(self.dir_of("r1").meta)["week1_files_unchanged"])

    def test_bad_option_combinations(self):
        for argv in [["--resume"], ["--retry-model-errors"], ["--resume", "--run-name", "x", "--limit", "2"], ["--limit", "0"], ["--rpm", "0"]]:
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit, msg=str(argv)):
                    runner.parse_args(argv)


class LlmConfigCheckTests(unittest.TestCase):
    def test_accepts_gemini_models(self):
        with mock.patch.object(llm_config, "models", lambda: {"small": "gemini-2.5-flash-lite", "strong": "gemini-2.5-pro"}):
            self.assertEqual(runner.check_llm_config()["small"], "gemini-2.5-flash-lite")

    def test_refuses_a_non_gemini_model(self):
        with mock.patch.object(llm_config, "models", lambda: {"small": "claude-haiku-4-5-20251001", "strong": "gemini-2.5-pro"}):
            with self.assertRaises(SystemExit):
                runner.check_llm_config()

    def test_refuses_a_non_gemini_provider(self):
        with mock.patch.object(llm_config, "PROVIDER", "anthropic", create=True):
            with mock.patch.object(llm_config, "models", lambda: {"small": "gemini-2.5-flash-lite", "strong": "gemini-2.5-pro"}):
                with self.assertRaises(SystemExit):
                    runner.check_llm_config()


class SeparationTests(unittest.TestCase):
    FORBIDDEN_NAMES = {"load_labels", "load_mitre_map", "MITRE_MAP", "eval_labels", "eval_io", "DEV_LABELS_PATH", "FROZEN_LABELS_PATH",
                       "FROZEN_ALERTS_PATH", "FLOW_STORE_FROZEN_PATH", "MITRE_MAP_PATH", "load_dev_labels", "load_answer_key"}
    FORBIDDEN_IMPORTS = ["anthropic", "openai", "langsmith", "langchain", "langgraph", "chromadb", "requests", "urllib", "socket", "http"]

    def names_used(self, name):
        tree = ast.parse(read_source(name))
        used = set()
        modules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                used.add(node.id)
            elif isinstance(node, ast.Attribute):
                used.add(node.attr)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    used.add(alias.name.split(".")[-1])
                    modules.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    used.add(node.module.split(".")[-1])
                    modules.add(node.module.split(".")[0])
                for alias in node.names:
                    used.add(alias.name.split(".")[-1])
        return used, modules

    def test_day3_modules_never_touch_labels_answer_key_or_frozen_paths(self):
        for name in MODULES:
            used, modules = self.names_used(name)
            self.assertEqual(sorted(used & self.FORBIDDEN_NAMES), [], name)

    def test_day3_modules_import_no_other_provider_or_later_week_tools(self):
        for name in MODULES:
            used, modules = self.names_used(name)
            self.assertEqual(sorted(modules & set(self.FORBIDDEN_IMPORTS)), [], name)

    def test_day3_modules_never_select_the_frozen_set(self):
        for name in MODULES:
            text = read_source(name)
            self.assertNotIn('"frozen"', text, name)
            self.assertNotIn("'frozen'", text, name)
            self.assertNotIn(config.FROZEN_UNLOCK_VALUE, text, name)
        text = read_source("run_baseline_dev.py")
        self.assertEqual(text.count("FROZEN_UNLOCK_ENV"), 2)

    def test_no_key_like_string_in_sources(self):
        for name in MODULES:
            text = read_source(name)
            self.assertNotIn("AIza", text)
            self.assertNotIn("sk-ant-", text)

    def test_requirements_have_no_anthropic_or_openai(self):
        path = os.path.join(ROOT, "requirements-week2.txt")
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                text = f.read().lower()
            self.assertNotIn("anthropic", text)
            self.assertNotIn("openai", text)

    def test_runner_reads_only_the_dev_loader(self):
        text = read_source("run_baseline_dev.py")
        self.assertIn("load_dev_alerts", text)
        self.assertIn("load_dev_flow_store", text)


@unittest.skipUnless(os.path.exists(os.path.join(ROOT, "eval", "dev_alerts.parquet")) and os.path.exists(os.path.join(ROOT, "eval", "flow_store_dev.parquet"))
                     and os.path.exists(os.path.join(ROOT, "eval", "MANIFEST.json")), "dev files not present")
class RealDevPromptTests(unittest.TestCase):
    def test_all_dev_prompts_build_and_hold_no_class_names(self):
        alerts, flows, hashes = runner.load_inputs()
        self.assertEqual(len(alerts), 300)
        prompts = runner.build_all_prompts(alerts, flows)
        self.assertEqual(len(prompts), 300)
        for alert_id in list(prompts)[:300]:
            prompt = prompts[alert_id]
            body = prompt.split("Alert:\n", 1)[1].rsplit("\n\nReply with", 1)[0]
            parsed = json.loads(body)
            self.assertEqual(parsed["alert"]["alert_id"], alert_id)
            for name in verdict_schema.ATTACK_TYPES:
                self.assertNotIn(name, prompt)


if __name__ == "__main__":
    unittest.main()
