"""A small stand-in for the parts of Vercel that frontend/vercel.json uses, so the routing can be checked offline: `rewrites` (first match wins; a file that exists in the build wins over any
rewrite; an external destination is proxied) and `headers`. It is NOT Vercel: it implements the path-to-regexp subset these rules need (`:name*` and parenthesised regular expressions) and nothing else.
What it cannot show is Vercel's own behaviour (which request headers its proxy forwards, its timeouts); those are listed in docs/AUTHENTICATION.md as checks to make after deployment.
"""
import json
import re


def _compile(source):
    """vercel.json source pattern -> compiled regex. ':name*' = the rest of the path (may be empty); '(...)' is a regular expression group; everything else is literal."""
    out, i = [], 0
    while i < len(source):
        c = source[i]
        if c == ":":
            m = re.match(r":([A-Za-z_]\w*)(\*|\+|\?)?", source[i:])
            name, mod = m.group(1), m.group(2)
            body = {"*": ".*", "+": ".+", "?": "[^/]*"}.get(mod, "[^/]+")
            if mod == "*" and out and out[-1] == "/":      # '/api/:path*' also matches '/api'
                out.pop()
                out.append("(?:/(?P<%s>.*))?" % name)
            else:
                out.append("(?P<%s>%s)" % (name, body))
            i += m.end()
        elif c == "(":
            depth, j = 1, i + 1
            while depth:
                depth += {"(": 1, ")": -1}.get(source[j], 0)
                j += 1
            out.append(source[i:j])
            i = j
        else:
            out.append(re.escape(c))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def _substitute(destination, match):
    named = {k: (v or "") for k, v in match.groupdict().items()}
    for key, value in named.items():
        destination = destination.replace(":%s*" % key, value)
    for n, value in enumerate(match.groups(), 1):
        destination = destination.replace("$%d" % n, value or "")
    return destination


class VercelConfig:
    def __init__(self, path):
        with open(path, "r", encoding="utf-8") as fh:
            self.raw = json.load(fh)
        self.rewrites = [(_compile(r["source"]), r["destination"]) for r in self.raw.get("rewrites", [])]
        self.headers = [(_compile(h["source"]), h["headers"]) for h in self.raw.get("headers", [])]

    def route(self, path, query="", file_exists=lambda p: False):
        """-> ('file', path) | ('proxy', url) | ('spa', '/index.html') | ('none', None). Existing build files win over rewrites, as on Vercel."""
        if file_exists(path):
            return "file", path
        for rx, dest in self.rewrites:
            m = rx.match(path)
            if m:
                target = _substitute(dest, m)
                if target.startswith("http://") or target.startswith("https://"):
                    return "proxy", target + (("?" + query) if query else "")
                return "spa", target
        return "none", None

    def headers_for(self, path):
        out = {}
        for rx, items in self.headers:
            if rx.match(path):
                for h in items:
                    out[h["key"]] = h["value"]
        return out
