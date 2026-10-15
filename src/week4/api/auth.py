"""Authentication for the approval API.

Normal mode (the only one to use outside a developer's own machine): each person has a random API token. The server stores only the SHA-256 HASH of each token, as
"analyst_id:hex" pairs, in the WEEK4_API_TOKEN_HASHES environment variable (comma-separated) or in the file named by WEEK4_API_TOKEN_HASHES_FILE (one pair per line, # comments allowed).
A request must send "Authorization: Bearer <token>". The token is hashed and compared in constant time. The identity comes from the token and nowhere else: never from the request body.
What the person may do is decided by their role in the analysts table (viewer, analyst, approver, admin), not by the token.

Dev mode: WEEK4_API_DEV_MODE=1 trusts an "X-Dev-Analyst: <id>" header, with no secret. It exists only so a developer can try the API on their own machine. It requires that NO token hashes
are configured (so it cannot be left on by accident next to real ones), and the server launcher refuses to start it on any address except loopback.

No configuration at all is an error (ConfigError): the approval routes are never open by default.
Generate a token:  python -m week4.api.auth new-token --analyst alice     (prints the token once, and the hash line to put in the server's environment)
"""
import argparse
import hashlib
import hmac
import os
import re
import secrets
import sys

from week4.db.repository import ANALYST_ID_RE

ENV_HASHES = "WEEK4_API_TOKEN_HASHES"
ENV_HASHES_FILE = "WEEK4_API_TOKEN_HASHES_FILE"
ENV_DEV = "WEEK4_API_DEV_MODE"
DEV_HEADER = "x-dev-analyst"
HEX_RE = re.compile(r"^[0-9a-f]{64}$")
MIN_TOKEN_CHARS = 32


class ConfigError(Exception):
    """The API is not configured safely. The server does not start."""


def hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_token():
    return secrets.token_urlsafe(32)


def parse_pairs(text, source):
    pairs = {}
    for raw in re.split(r"[,\n]", text):
        item = raw.strip()
        if not item or item.startswith("#"):
            continue
        analyst, sep, digest = item.partition(":")
        analyst, digest = analyst.strip(), digest.strip().lower()
        if not sep or not ANALYST_ID_RE.match(analyst) or not HEX_RE.match(digest):
            raise ConfigError("a token entry in " + source + " is not in the form analyst_id:<64 hex characters>")
        if analyst in pairs:
            raise ConfigError("analyst " + analyst + " appears twice in " + source)
        pairs[analyst] = digest
    if len(set(pairs.values())) != len(pairs):
        raise ConfigError("two analysts share the same token hash in " + source)
    return pairs


class AuthConfig:
    def __init__(self, mode, token_hashes=None):
        if mode not in ("token", "dev"):
            raise ConfigError("unknown authentication mode")
        if mode == "token" and not token_hashes:
            raise ConfigError("token mode needs at least one token hash")
        self.mode = mode
        self.token_hashes = dict(token_hashes or {})

    def authenticate(self, headers):
        """The analyst id for a request, or None. headers: a dict with lower-case names."""
        if self.mode == "dev":
            who = (headers.get(DEV_HEADER) or "").strip()
            return who if ANALYST_ID_RE.match(who) else None
        auth = headers.get("authorization") or ""
        scheme, _, token = auth.partition(" ")
        token = token.strip()
        if scheme.lower() != "bearer" or len(token) < MIN_TOKEN_CHARS:
            return None
        digest = hash_token(token)
        found = None
        for analyst, stored in self.token_hashes.items():      # every entry is compared, so timing does not reveal which one matched
            if hmac.compare_digest(digest, stored):
                found = analyst
        return found


def from_env(env=None):
    env = os.environ if env is None else env
    inline, path = (env.get(ENV_HASHES) or "").strip(), (env.get(ENV_HASHES_FILE) or "").strip()
    dev = (env.get(ENV_DEV) or "").strip()
    pairs = {}
    if inline:
        pairs.update(parse_pairs(inline, ENV_HASHES))
    if path:
        try:
            with open(path, encoding="utf-8") as fh:
                from_file = parse_pairs(fh.read(), path)
        except OSError:
            raise ConfigError("the token file named by " + ENV_HASHES_FILE + " could not be read") from None
        clash = set(pairs) & set(from_file)
        if clash:
            raise ConfigError("analyst " + sorted(clash)[0] + " is configured twice")
        pairs.update(from_file)
    if dev and dev != "1":
        raise ConfigError(ENV_DEV + " must be 1 or unset")
    if dev == "1":
        if pairs:
            raise ConfigError(ENV_DEV + "=1 cannot be combined with token hashes. Dev mode is for a developer's own machine only; remove one of them.")
        return AuthConfig("dev")
    if not pairs:
        raise ConfigError("no authentication is configured, so the API will not start. Set " + ENV_HASHES + " (see python -m week4.api.auth new-token), "
                          "or, on your own machine only, " + ENV_DEV + "=1.")
    return AuthConfig("token", pairs)


def main(argv=None):
    p = argparse.ArgumentParser(description="API token helper")
    sub = p.add_subparsers(dest="command", required=True)
    n = sub.add_parser("new-token", help="make a token for an analyst; prints it once")
    n.add_argument("--analyst", required=True)
    args = p.parse_args(argv)
    if not ANALYST_ID_RE.match(args.analyst):
        print("analyst id must be 1-64 characters from A-Z a-z 0-9 _ . @ -")
        return 2
    token = new_token()
    print("Token for " + args.analyst + " (shown once; give it to that person, do not store it in the repository):")
    print(token)
    print("")
    print("Add this entry to " + ENV_HASHES + " (comma-separated) on the server:")
    print(args.analyst + ":" + hash_token(token))
    return 0


if __name__ == "__main__":
    sys.exit(main())
