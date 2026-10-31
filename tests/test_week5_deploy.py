"""Static checks of the Docker deployment files. They parse and inspect the files; nothing is built or started (Docker is not needed). The compose file is also validated by
`docker compose config` when you run it yourself (docs/WEEK5_DEPLOYMENT.md). Run: PYTHONPATH=src:. python -m unittest tests.test_week5_deploy"""
import os
import re
import unittest

from week5 import settings as S

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
try:
    import yaml
except ImportError:       # the tests that need a parser are skipped; the text tests still run
    yaml = None


def read(name):
    with open(os.path.join(ROOT, name), "r", encoding="utf-8") as fh:
        return fh.read()


def compose():
    return yaml.safe_load(read("docker-compose.week5.yml"))


APP_SERVICES = ("migrate", "api", "worker", "sweeper")


def env_of(service):
    env = service.get("environment") or {}
    return env if isinstance(env, dict) else dict(item.split("=", 1) for item in env)


@unittest.skipIf(yaml is None, "PyYAML not installed")
class ComposeFile(unittest.TestCase):
    def setUp(self):
        self.c = compose()
        self.services = self.c["services"]

    def test_expected_services(self):
        self.assertEqual(set(self.services), {"postgres", "redis", "migrate", "api", "worker", "sweeper"})

    def test_only_the_api_publishes_a_port_and_only_on_loopback(self):
        for name, svc in self.services.items():
            if name != "api":
                self.assertNotIn("ports", svc, name)
                self.assertNotIn("expose", svc, name)
        ports = self.services["api"]["ports"]
        self.assertEqual(len(ports), 1)
        self.assertTrue(str(ports[0]).startswith("127.0.0.1:"))

    def test_databases_and_broker_are_only_on_the_internal_network(self):
        self.assertTrue(self.c["networks"]["backend"]["internal"])
        for name in ("postgres", "redis", "migrate", "sweeper"):
            self.assertEqual(self.services[name]["networks"], ["backend"], name)
        self.assertEqual(sorted(self.services["api"]["networks"]), ["backend", "edge"])
        # The worker is the only service that may reach a model, so it is the only one allowed on the egress network (live Gemini setup);
        # `backend` is internal, so without that second network it has no route out at all. docker-compose.egress.yml moves it back to `backend` only.
        self.assertIn(sorted(self.services["worker"]["networks"]), (["backend"], ["backend", "model-egress"]))
        self.assertNotIn("model-egress", sum((list(self.services[n]["networks"]) for n in ("postgres", "redis", "migrate", "api", "sweeper")), []))

    def test_app_containers_are_hardened(self):
        for name in APP_SERVICES:
            svc = self.services[name]
            self.assertTrue(svc["read_only"], name)
            self.assertEqual(svc["cap_drop"], ["ALL"], name)
            self.assertIn("no-new-privileges:true", svc["security_opt"], name)
            self.assertTrue(svc["init"], name)
            self.assertFalse(svc.get("privileged"), name)
            self.assertTrue(any(str(t).startswith("/tmp") for t in svc["tmpfs"]), name)
        for name in ("postgres", "redis"):
            self.assertIn("no-new-privileges:true", self.services[name]["security_opt"], name)

    def test_nothing_dangerous_is_mounted_or_shared(self):
        text = read("docker-compose.week5.yml")
        for bad in ("docker.sock", "network_mode", "privileged: true", "pid: host", "cap_add", "env_file"):
            self.assertNotIn(bad, text)
        for name, svc in self.services.items():
            for vol in svc.get("volumes", []):
                self.assertFalse(str(vol).startswith(("/", ".", "~")), "%s mounts a host path: %s" % (name, vol))

    def test_every_long_running_service_has_a_health_check_and_dependencies_wait_for_it(self):
        for name in ("postgres", "redis", "api", "worker", "sweeper"):
            self.assertIn("healthcheck", self.services[name], name)
        self.assertNotIn("healthcheck", self.services["migrate"])
        for name in ("api", "worker", "sweeper"):
            dep = self.services[name]["depends_on"]
            self.assertEqual(dep["migrate"]["condition"], "service_completed_successfully")
            self.assertEqual(dep["redis"]["condition"], "service_healthy")
        self.assertEqual(self.services["migrate"]["depends_on"]["postgres"]["condition"], "service_healthy")

    def test_restart_stop_and_resource_limits(self):
        for name in ("postgres", "redis", "api", "worker", "sweeper"):
            self.assertEqual(self.services[name]["restart"], "unless-stopped", name)
            self.assertIn("limits", self.services[name]["deploy"]["resources"], name)
        self.assertEqual(self.services["migrate"]["restart"], "no")
        self.assertRegex(self.services["worker"]["stop_grace_period"], r"^\d+s$")
        self.assertGreater(int(self.services["worker"]["stop_grace_period"][:-1]), 60)         # longer than the 60 s job timeout (the hard-limit test below is stricter)

    def test_images_are_pinned_to_a_tag_not_latest(self):
        for name in ("postgres", "redis"):
            image = self.services[name]["image"]
            self.assertIn(":", image)
            self.assertFalse(image.endswith(":latest"))

    def test_no_credential_is_written_in_the_file(self):
        text = re.sub(r"\$\{[^}]*\}", "${VAR}", read("docker-compose.week5.yml"))        # the messages inside ${VAR:?message} are not values
        for match in re.finditer(r"(?i)(password|secret|token|api_key)[a-z_0-9]*\s*[:=]\s*([^\s#]+)", text):
            value = match.group(2)
            self.assertTrue(value.startswith("${") or value in ("", "'$$REDIS_PASSWORD'"), "literal value after " + match.group(1) + ": " + value)
        for match in re.finditer(r"://[^/\s]*:([^@\s]*)@", text):
            self.assertTrue(match.group(1).startswith("${") or match.group(1).startswith(":$"), "a literal password in a connection string")
        self.assertNotRegex(text, r"(?i)AIza[0-9A-Za-z_\-]{20,}")

    def test_every_required_variable_fails_loudly_and_is_documented(self):
        text = read("docker-compose.week5.yml")
        required = set(re.findall(r"\$\{([A-Z0-9_]+):\?", text))
        self.assertTrue({"WEEK5_DB_PASSWORD", "WEEK4_API_DB_PASSWORD", "WEEK5_WORKER_DB_PASSWORD", "WEEK5_REDIS_PASSWORD", "WEEK4_API_TOKEN_HASHES"} <= required)
        example = read(".env.week5.example")
        # The Gemini key is required only when the worker runs the live model; it is documented in docs/WEEK5_DEPLOYMENT.md and .env.integrations.example, not as a value in the example file.
        for name in required - {"GEMINI_API_KEY"}:
            self.assertRegex(example, r"(?m)^" + name + "=", name)
        # every variable the compose file mentions (other than ones with a default) appears in the example
        for name in set(re.findall(r"(?<!\$)\$\{([A-Z0-9_]+)(?::-|\})", text)) - {"GEMINI_API_KEY"}:
            self.assertIn(name, example, name)

    def test_least_privilege_secrets_per_service(self):
        api, worker, sweeper, migrate = (env_of(self.services[n]) for n in ("api", "worker", "sweeper", "migrate"))
        self.assertIn("WEEK5_API_DATABASE_URL", api)
        self.assertNotIn("WEEK5_WORKER_DATABASE_URL", api)
        for e in (worker, sweeper):
            self.assertIn("WEEK5_WORKER_DATABASE_URL", e)
            self.assertNotIn("WEEK5_API_DATABASE_URL", e)
            self.assertNotIn("WEEK4_API_TOKEN_HASHES", e)
        self.assertIn("WEEK4_API_TOKEN_HASHES", api)
        for e in (api, worker, sweeper):
            self.assertNotIn("WEEK4_ADMIN_DATABASE_URL", e)
            self.assertNotIn("WEEK5_DB_PASSWORD", " ".join(str(v) for v in e.values()))
        self.assertIn("WEEK4_ADMIN_DATABASE_URL", migrate)
        self.assertTrue(env_of(self.services["postgres"])["POSTGRES_PASSWORD"].startswith("${"))

    def test_the_model_is_the_fake_one_and_no_model_key_exists_anywhere(self):
        # Original invariant: fake model everywhere, no key. Live Gemini setup: ONLY the worker may run `gemini` mode, and the key may only be a ${VAR} reference
        # (never a value) on the worker. The API and the sweeper never get a model mode other than fake, a model key or the live-model switch.
        text = read("docker-compose.week5.yml") + read(".env.week5.example") + read("Dockerfile.week5")
        for name in ("api", "worker", "sweeper"):
            e = env_of(self.services[name])
            self.assertEqual(e["WEEK5_ALERT_SET"], "synthetic")
            self.assertEqual(e["WEEK5_FLOW_STORE"], "fixture")
            if name == "worker":
                self.assertIn(e["WEEK5_MODEL_MODE"], ("fake", "gemini"))
                if e["WEEK5_MODEL_MODE"] == "gemini":
                    self.assertEqual(str(e.get("WEEK5_ALLOW_LIVE_MODEL")), "1")        # the explicit opt-in the settings require
                    self.assertTrue(str(e["GEMINI_API_KEY"]).startswith("${GEMINI_API_KEY:?"), "the key must be a required reference, not a value")
                else:
                    self.assertNotIn("GEMINI_API_KEY", e)
            else:
                self.assertEqual(e["WEEK5_MODEL_MODE"], "fake", name)
                self.assertNotIn("GEMINI_API_KEY", e, name)
                self.assertNotIn("WEEK5_ALLOW_LIVE_MODEL", e, name)
        self.assertNotRegex(text, r"(?i)GOOGLE_API_KEY")
        self.assertNotRegex(read(".env.week5.example") + read("Dockerfile.week5"), r"(?i)GEMINI_API_KEY|WEEK5_ALLOW_LIVE_MODEL: ?['\"]?1")
        for m in re.finditer(r"(?im)^\s*GEMINI_API_KEY\s*[:=]\s*(\S+)", read("docker-compose.week5.yml")):
            self.assertTrue(m.group(1).startswith("${GEMINI_API_KEY:?"), "a literal Gemini key value")

    def test_week5_settings_accept_the_environment_the_compose_file_sets(self):
        for name in ("api", "worker", "sweeper"):
            env = {k: re.sub(r"\$\{[^}]*\}", "x", str(v)) for k, v in env_of(self.services[name]).items() if k.startswith("WEEK5_")}
            env["WEEK5_MAX_ATTEMPTS"], env["WEEK5_JOB_TIMEOUT_SECONDS"], env["WEEK5_MAX_QUEUE_DEPTH"] = "3", "60", "1000"
            env.pop("WEEK5_RATE_LIMIT_PER_MINUTE", None)
            s = S.from_env(env)
            expected_model = "gemini" if (name == "worker" and env_of(self.services[name]).get("WEEK5_MODEL_MODE") == "gemini") else "fake"
            self.assertEqual((s.queue_backend, s.model_mode, s.flow_store, s.alert_set), ("celery", expected_model, "fixture", "synthetic"))

    def test_celery_queue_name_matches_the_settings_default(self):
        self.assertEqual(S.Settings().celery_queue, "soc_triage")
        self.assertIn("soc_triage", self.services["worker"]["command"])

    def test_the_celery_hard_limit_leaves_room_before_the_stop_grace_period_ends(self):
        s = S.from_env({"WEEK5_JOB_TIMEOUT_SECONDS": "60"})
        grace = int(self.services["worker"]["stop_grace_period"][:-1])
        self.assertLess(s.job_timeout_seconds + s.celery_hard_limit_slack_seconds, grace)

    def test_api_binds_all_interfaces_inside_the_container_only_with_real_auth_required(self):
        api = self.services["api"]
        self.assertIn("0.0.0.0", api["command"])
        self.assertNotIn("WEEK4_API_DEV_MODE", env_of(api))           # dev mode refuses non-loopback binds, and must never be set in a container


class Dockerfile(unittest.TestCase):
    def setUp(self):
        self.text = read("Dockerfile.week5")

    def test_runs_as_a_numeric_non_root_user(self):
        users = re.findall(r"(?m)^USER\s+(\S+)", self.text)
        self.assertTrue(users)
        self.assertNotIn(users[-1].split(":")[0], ("root", "0"))
        self.assertRegex(users[-1], r"^\d+(:\d+)?$")

    def test_copies_only_code_and_config_and_no_secret(self):
        copies = re.findall(r"(?m)^COPY\s+(?:--\S+\s+)*(\S+)\s+\S+$", self.text)
        for src in copies:
            self.assertNotIn(".env", src)
            self.assertNotIn("data", src.split("/")[0])
            self.assertNotIn("eval", src.split("/")[0])
            self.assertNotIn("memory_store", src)
        self.assertEqual(set(copies) - {"--from=build"}, {"requirements-week5.txt", "requirements-genai.txt", "src/", "config/", "docker/", "/opt/venv"})

    def test_no_secret_in_env_or_arg(self):
        for line in re.findall(r"(?m)^\s*(?:ENV|ARG)\s+.*$", self.text):
            self.assertNotRegex(line, r"(?i)(password|secret|token|api_key|key)\s*=\s*\S")
        self.assertNotRegex(self.text, r"(?i)AIza[0-9A-Za-z_\-]{20,}")

    def test_base_image_is_a_slim_tagged_python(self):
        for image in re.findall(r"(?m)^FROM\s+(\S+)", self.text):
            self.assertNotIn("latest", image)
            self.assertIn("python:", image)
            self.assertIn("slim", image)

    def test_has_a_health_check_and_does_not_install_the_live_model_by_default(self):
        self.assertIn("HEALTHCHECK", self.text)
        self.assertRegex(self.text, r"ARG WITH_GENAI=0")

    def test_multi_stage_so_build_tools_stay_out_of_the_runtime_image(self):
        self.assertEqual(len(re.findall(r"(?m)^FROM\s", self.text)), 2)
        self.assertNotIn("apt-get", self.text)


class SupportFiles(unittest.TestCase):
    def test_dockerignore_keeps_secrets_and_data_out_of_the_build_context(self):
        lines = [l.strip() for l in read(".dockerignore").splitlines() if l.strip() and not l.startswith("#")]
        for needed in (".env", ".env.*", "data", "eval", "memory_store", "runs", ".git", "tests", "*.parquet"):
            self.assertIn(needed, lines, needed)
        self.assertIn("!.env.week5.example", lines)
        self.assertLess(lines.index(".env.*"), lines.index("!.env.week5.example"))

    def test_env_example_holds_only_placeholders(self):
        for line in read(".env.week5.example").splitlines():
            if not line or line.startswith("#"):
                continue
            key, _, value = line.partition("=")
            if "PASSWORD" in key or "TOKEN" in key:
                self.assertTrue(value == "" or (value.startswith("<") and value.endswith(">")), key)

    def test_gitignore_additions_cover_the_real_env_file(self):
        self.assertIn(".env.week5", read(".gitignore.week5-additions").splitlines())

    def test_migrate_script_is_strict_ordered_and_quiet(self):
        text = read("docker/migrate.sh")
        self.assertIn("set -eu", text)
        steps = [l for l in text.splitlines() if l.startswith("python ")]
        self.assertEqual(steps, ["python -m week4.db.migrate apply", "python -m week5.db.migrate apply", "python -m week4.db.admin create-api-login", "python -m week5.db.admin create-worker-login",
                                 "python -m week5.db.migrate verify"])
        self.assertNotRegex(text, r"(?i)echo.*(password|\$WEEK)")
        self.assertNotIn("\r", text)       # a CRLF script fails inside Linux ("sh\\r: not found"); autocrlf must not touch it

    def test_runtime_requirements_cover_what_the_service_imports(self):
        req = read("requirements-week5.txt").lower()
        for pkg in ("fastapi", "uvicorn", "celery", "redis", "psycopg", "langgraph", "pandas", "numpy", "pydantic"):
            self.assertIn(pkg, req)
        self.assertNotIn("google-genai", "\n".join(l for l in req.splitlines() if not l.startswith("#")))
        self.assertNotIn("pytest", req)

    def test_dev_requirements_extend_runtime(self):
        dev = read("requirements-week5-dev.txt")
        self.assertIn("-r requirements-week5.txt", dev)
        self.assertIn("pyyaml", dev.lower())


if __name__ == "__main__":
    unittest.main()
