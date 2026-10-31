"""Static checks of the egress override and the integration env template: only the worker holds keys and a route (through the proxy) to Gemini/AbuseIPDB, nothing else changes. Nothing is built."""
import os
import re
import unittest

from week5.egress import proxy

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
try:
    import yaml
except ImportError:
    yaml = None


def read(name):
    with open(os.path.join(ROOT, name), encoding="utf-8") as fh:
        return fh.read()


class Replace:
    """A value tagged !override (or !reset) in a Compose file: it replaces the base's value instead of merging with it."""

    def __init__(self, value):
        self.value = value


if yaml is not None:
    class ComposeLoader(yaml.SafeLoader):
        pass

    def _tagged(loader, node):
        if isinstance(node, yaml.SequenceNode):
            return Replace(loader.construct_sequence(node, deep=True))
        if isinstance(node, yaml.MappingNode):
            return Replace(loader.construct_mapping(node, deep=True))
        return Replace(loader.construct_scalar(node))

    ComposeLoader.add_constructor("!override", _tagged)
    ComposeLoader.add_constructor("!reset", _tagged)


def load(name):
    return yaml.load(read(name), Loader=ComposeLoader)


def merge(a, b, key=None):
    """The subset of Compose's merge rules these files use: mappings merge, `networks` lists are united, an !override/!reset value replaces, everything else is replaced."""
    if isinstance(b, Replace):
        return b.value
    if isinstance(a, dict) and isinstance(b, dict):
        out = dict(a)
        for k, v in b.items():
            out[k] = merge(a[k], v, k) if k in a else (v.value if isinstance(v, Replace) else v)
        return out
    if key == "networks" and isinstance(a, list) and isinstance(b, list):
        return a + [x for x in b if x not in a]
    return b


@unittest.skipIf(yaml is None, "PyYAML not installed")
class Override(unittest.TestCase):
    def setUp(self):
        self.base = load("docker-compose.week5.yml")
        self.over = load("docker-compose.egress.yml")
        self.merged = merge(self.base, self.over)
        self.s = self.merged["services"]

    def env(self, name):
        e = self.s[name].get("environment") or {}
        return e if isinstance(e, dict) else dict(x.split("=", 1) for x in e)

    def test_the_override_adds_only_the_proxy_and_one_network(self):
        self.assertEqual(set(self.over["services"]) - set(self.base["services"]), {"egress-proxy"})
        self.assertEqual(set(self.over["networks"]), {"soc-egress-out"})
        self.assertTrue(self.merged["networks"]["backend"]["internal"])

    def test_only_the_proxy_is_on_the_outbound_network_and_nothing_publishes_a_port(self):
        for name, svc in self.s.items():
            nets = svc.get("networks") or []
            on_out = "soc-egress-out" in nets
            self.assertEqual(on_out, name == "egress-proxy", name)
        self.assertEqual(set(self.s["egress-proxy"]["networks"]), {"backend", "soc-egress-out"})
        self.assertNotIn("ports", self.s["egress-proxy"])
        self.assertEqual(self.s["api"]["ports"], self.base["services"]["api"]["ports"])

    def test_only_the_worker_receives_keys_and_a_proxy(self):
        for name in ("api", "migrate", "sweeper", "postgres", "redis", "egress-proxy"):
            e = self.env(name)
            for key in ("GEMINI_API_KEY", "SOC_REPUTATION_API_KEY", "HTTPS_PROXY", "https_proxy"):
                self.assertNotIn(key, e, "%s must not receive %s" % (name, key))
        w = self.env("worker")
        self.assertEqual(w["HTTPS_PROXY"], "http://egress-proxy:3128")
        self.assertIn("postgres", w["NO_PROXY"])
        self.assertIn("redis", w["NO_PROXY"])

    def test_keys_are_references_never_values(self):
        text = read("docker-compose.egress.yml")
        for line in text.splitlines():
            if "API_KEY" in line and not line.lstrip().startswith("#"):
                self.assertRegex(line, r"\$\{[A-Z_]+:-\}", line)
        self.assertNotRegex(text, r"AIza[0-9A-Za-z_\-]{20,}")

    def test_the_override_never_touches_the_model_switches_or_the_gemini_key(self):
        """A live base (WEEK5_MODEL_MODE=gemini, a required GEMINI_API_KEY) must come out of the merge unchanged; an earlier draft reset it to the fake model."""
        over_env = self.over["services"]["worker"].get("environment") or {}
        for key in ("WEEK5_MODEL_MODE", "WEEK5_ALLOW_LIVE_MODEL", "GEMINI_API_KEY"):
            self.assertNotIn(key, over_env, key)
            self.assertEqual(self.env("worker").get(key), (self.base["services"]["worker"].get("environment") or {}).get(key), key)

    def test_the_worker_is_taken_off_every_network_with_a_direct_route(self):
        """Compose unites network lists, so without !override a base that puts the worker on a direct-internet network (model-egress) would let it bypass the proxy."""
        self.assertIsInstance(self.over["services"]["worker"]["networks"], Replace)
        self.assertEqual(self.s["worker"]["networks"], ["backend"])
        # and the united-list rule really is what the test merge applies to a base with an extra network
        live_like = {"services": {"worker": {"networks": ["backend", "model-egress"]}}}
        self.assertEqual(merge(live_like, {"services": {"worker": {"networks": ["x"]}}})["services"]["worker"]["networks"], ["backend", "model-egress", "x"])

    def test_every_service_using_the_shared_image_builds_it_the_same_way(self):
        args = {name: (self.s[name].get("build") or {}).get("args") for name in ("api", "migrate", "worker", "sweeper", "egress-proxy")}
        self.assertEqual(len({str(a) for a in args.values()}), 1, args)
        self.assertIn("WITH_GENAI", list(args.values())[0])

    def test_proxy_hardening_matches_the_application_services(self):
        p = self.s["egress-proxy"]
        self.assertTrue(p["read_only"])
        self.assertEqual(p["cap_drop"], ["ALL"])
        self.assertIn("no-new-privileges:true", p["security_opt"])
        self.assertEqual(p["command"], ["python", "-m", "week5.egress.proxy"])
        self.assertEqual(p["environment"]["WEEK5_EGRESS_PORTS"], "443")
        self.assertEqual(self.s["worker"]["depends_on"]["egress-proxy"]["condition"], "service_healthy")
        self.assertIn("migrate", self.s["worker"]["depends_on"])          # the base dependencies are kept

    def test_default_allow_list_is_exactly_the_two_providers(self):
        default = re.search(r"WEEK5_EGRESS_ALLOW: \$\{WEEK5_EGRESS_ALLOW:-([^}]*)\}", read("docker-compose.egress.yml")).group(1)
        self.assertEqual(set(proxy.parse_allow(default)), {"generativelanguage.googleapis.com", "api.abuseipdb.com"})
        self.assertEqual(set(proxy.DEFAULT_ALLOW), set(proxy.parse_allow(default)))


class Templates(unittest.TestCase):
    def test_env_template_has_placeholders_only(self):
        text = read(".env.integrations.example")
        for line in text.splitlines():
            if line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            if "KEY" in k or "SECRET" in k or "PASSWORD" in k or "TOKEN" in k:
                self.assertEqual(v.strip(), "", line)
        self.assertNotRegex(text, r"AIza[0-9A-Za-z_\-]{20,}")
        # later --env-file options win: the template must not define the key, the live switch or the mode, or it would replace the values kept in .env.week5
        for name in ("GEMINI_API_KEY", "WEEK5_MODEL_MODE", "WEEK5_ALLOW_LIVE_MODEL"):
            self.assertNotRegex(text, r"(?m)^%s=" % name)
        self.assertRegex(text, r"(?m)^WEEK5_WITH_GENAI=1$")

    def test_gitignore_additions_cover_the_new_secret_file(self):
        self.assertIn(".env.integrations", read(".gitignore.week5-additions") + read(".gitignore"))

    def test_dockerfile_fails_the_build_when_the_genai_library_is_missing(self):
        d = read("Dockerfile.week5")
        self.assertIn("requirements-genai.txt", d)
        self.assertIn("find_spec('google.genai')", d)
        self.assertIn("ARG WITH_GENAI=0", d)

    def test_dockerignore_excludes_env_files(self):
        d = read(".dockerignore")
        self.assertRegex(d, r"(?m)^\.env\*?")


if __name__ == "__main__":
    unittest.main()
