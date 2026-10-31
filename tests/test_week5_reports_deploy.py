"""Static check of docker-compose.reports.yml: only the API gets the report folder, read-only, and the setting points at it. Nothing is built or started."""
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
try:
    import yaml
except ImportError:
    yaml = None


@unittest.skipIf(yaml is None, "PyYAML not installed")
class ReportsOverride(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(ROOT, "docker-compose.reports.yml"), encoding="utf-8") as fh:
            self.over = yaml.safe_load(fh)

    def test_only_the_api_is_touched(self):
        self.assertEqual(set(self.over["services"]), {"api"})
        self.assertEqual(set(self.over), {"services"})

    def test_the_folder_is_read_only_and_matches_the_setting(self):
        api = self.over["services"]["api"]
        self.assertEqual(api["volumes"], ["./reports:/reports:ro"])
        self.assertEqual(api["environment"]["WEEK5_EVAL_REPORT_DIR"], "/reports")

    def test_no_secret_is_mentioned(self):
        with open(os.path.join(ROOT, "docker-compose.reports.yml"), encoding="utf-8") as fh:
            text = fh.read().lower()
        for word in ("password", "api_key", "token"):
            self.assertNotIn(word, text)

    def test_the_setting_is_a_real_one(self):
        from week5 import settings
        env = {"WEEK5_EVAL_REPORT_DIR": "/reports"}
        self.assertEqual(settings.from_env(env).eval_report_dir, "/reports")


if __name__ == "__main__":
    unittest.main()
