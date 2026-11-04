"""Authorization matrix over every route: no anonymous access except health; viewers read only; analysts submit but cannot approve; nothing in the API executes against a real system."""
import unittest

from week4.api import routes as routes4
from week5.api import routes5
from week5.auth.routes_auth import AUTH_NAMES

from tests.week5_support import ApiRig

PUBLIC = {"health_live", "health_ready"}
# The web sign-in routes (/auth/*) are authorised by session and role, not by API token: tests/test_week5_auth.py covers them (anonymous 401, non-admin 403, CSRF, origin).
APPROVAL = {"decide", "execute_action", "simulate_action"}


def routes():
    seen, out = set(), []
    for r in list(routes5.ROUTES5) + list(routes4.ROUTES):
        if r.name not in seen and r.name not in AUTH_NAMES:
            seen.add(r.name)
            out.append(r)
    return out


class Matrix(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rig = ApiRig(sensor=True)

    def status(self, route, who, **kw):
        path = {k: "00000000-0000-0000-0000-000000000000" for k in ("case_id", "job_id", "action_id")}
        path.update({"sensor": "s1", "name": "x.json"})
        r = self.rig.call(route.name, who, body={} if route.method == "POST" else None, path=path, **kw)
        return r.status

    def test_every_route_but_health_refuses_anonymous_callers(self):
        for r in routes():
            if r.name in PUBLIC or r.role is None:
                continue
            with self.subTest(r.name):
                self.assertEqual(self.status(r, None), 401)

    def test_a_wrong_or_unknown_token_is_refused_everywhere(self):
        for r in routes():
            if r.name in PUBLIC or r.role is None:
                continue
            with self.subTest(r.name):
                self.assertEqual(self.status(r, "bob", token="Z" * 40), 401)
                self.assertEqual(self.status(r, "ghost"), 403)          # a valid token for someone who is not an analyst
                self.assertEqual(self.status(r, "erin"), 403)           # an inactive account

    def test_a_viewer_can_never_write(self):
        for r in routes():
            if r.role == "submit":
                with self.subTest(r.name):
                    self.assertEqual(self.status(r, "carol"), 403)

    def test_viewers_can_read_what_the_dashboard_needs(self):
        for r in routes():
            if r.role == "read" and r.name not in PUBLIC and "{" not in r.path:
                with self.subTest(r.name):
                    self.assertIn(self.status(r, "carol"), (200,), r.path)

    def test_a_plain_analyst_cannot_decide_an_action(self):
        names = {r.name for r in routes()}
        self.assertIn("decide", names)
        r = next(x for x in routes() if x.name == "decide")
        resp = self.rig.call("decide", "bob", body={"decision": "approved", "reason": "x"}, path={"action_id": "00000000-0000-0000-0000-000000000000"}, headers={"Idempotency-Key": "k" * 16})
        self.assertEqual(resp.status, 403)

    def test_no_route_can_execute_a_real_action(self):
        for r in routes():
            text = (r.name + " " + r.path).lower()
            if "execute" in text or "simulate" in text:
                self.assertIn("simulat", text, r.name)          # the only execute-like route says so in its name

    def test_an_unknown_route_name_is_not_dispatched(self):
        try:
            status = self.rig.call("run_shell", "root").status
        except Exception:
            return
        self.assertGreaterEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
