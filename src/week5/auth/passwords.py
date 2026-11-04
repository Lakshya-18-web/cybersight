"""Password hashing and the password / username rules.

Hashing: Argon2id (argon2-cffi) is the default. Every hash is a self-describing string ($argon2id$v=19$m=..,t=..,p=..$salt$hash) with its own random 16-byte salt, so parameters can be raised
later and old hashes still verify (needs_rehash tells the sign-in code to upgrade one after a successful sign-in). scrypt (standard library) is supported as an equivalent fallback for
environments where argon2-cffi cannot be installed; it is selected explicitly (WEEK5_PASSWORD_HASH=scrypt), never silently. A password is NFKC-normalised and UTF-8 encoded first, so the same
characters typed on different keyboards verify. Nothing here logs, prints or returns a password. verify() never raises on a malformed or unknown stored hash: it returns False.

Self-test on the machine that will run the API:   python -m week5.auth.passwords
"""
import base64
import hashlib
import hmac
import re
import secrets
import unicodedata

USERNAME_RE = re.compile(r"[a-z0-9][a-z0-9_.-]{2,31}", re.ASCII)
MIN_PASSWORD = 12
MAX_PASSWORD = 128
SCHEMES = ("argon2id", "scrypt")

COMMON = frozenset("""password123456 passwordpassword 123456789012 1234567890123 qwertyuiopasdf qwertyuiop12 letmein123456 iloveyou1234 administrator1 welcome12345 changeme12345
password1234 password12345 passw0rd12345 qwerty123456 abc123456789 111111111111 000000000000 123123123123 adminadmin12 cybersight123 cybersight1234 soctriage1234""".split())


class PasswordError(ValueError):
    """The password does not meet the policy. The message says what to change and never contains the password."""


def normalize_username(value):
    """Lower-cased, trimmed username, or None when it is not a string. Format is checked separately (check_username)."""
    if not isinstance(value, str):
        return None
    return value.strip().lower()


def check_username(value):
    """-> the normalised username. Raises PasswordError when it is not 3-32 characters of a-z 0-9 _ . - starting with a letter or digit."""
    name = normalize_username(value)
    if name is None or not USERNAME_RE.fullmatch(name):
        raise PasswordError("the username must be 3 to 32 characters: lower-case letters, digits, '.', '_' or '-', starting with a letter or digit")
    return name


def check_password(password, username=None):
    """Raises PasswordError when the password is not acceptable. Length is the main rule (12 to 128 characters); there are no composition rules, but obvious choices are refused."""
    if not isinstance(password, str):
        raise PasswordError("the password must be text")
    if len(password) < MIN_PASSWORD:
        raise PasswordError("the password must be at least %d characters long" % MIN_PASSWORD)
    if len(password) > MAX_PASSWORD:
        raise PasswordError("the password must be at most %d characters long" % MAX_PASSWORD)
    if "\x00" in password:
        raise PasswordError("the password contains a character that is not allowed")
    plain = unicodedata.normalize("NFKC", password).lower()
    squeezed = re.sub(r"[\s_\-.]+", "", plain)
    if plain in COMMON or squeezed in COMMON or len(set(plain)) < 5:
        raise PasswordError("that password is too easy to guess; choose a longer, less predictable one")
    name = normalize_username(username) if username else None
    if name and len(name) >= 3 and name in plain:
        raise PasswordError("the password must not contain the username")
    return password


def _material(password):
    return unicodedata.normalize("NFKC", password).encode("utf-8")


def _b64(raw):
    return base64.b64encode(raw).decode("ascii").rstrip("=")


def _unb64(text):
    return base64.b64decode(text + "=" * (-len(text) % 4), validate=True)


class PasswordHasher:
    def __init__(self, scheme="argon2id", time_cost=3, memory_kib=19456, parallelism=1, scrypt_n=65536, scrypt_r=8, scrypt_p=1):
        if scheme not in SCHEMES:
            raise ValueError("unknown password hash scheme")
        self.scheme, self.time_cost, self.memory_kib, self.parallelism = scheme, time_cost, memory_kib, parallelism
        self.scrypt_n, self.scrypt_r, self.scrypt_p = scrypt_n, scrypt_r, scrypt_p
        self._argon = None
        if scheme == "argon2id":
            try:
                import argon2
            except ImportError:
                raise RuntimeError("argon2-cffi is not installed. Install it with: pip install -r requirements-week5.txt (or set WEEK5_PASSWORD_HASH=scrypt)") from None
            self._argon = argon2.PasswordHasher(time_cost=time_cost, memory_cost=memory_kib, parallelism=parallelism, hash_len=32, salt_len=16, type=argon2.Type.ID)

    # ------------------------------------------------------------------ hashing
    def hash(self, password):
        if self.scheme == "argon2id":
            return self._argon.hash(_material(password))
        return self._scrypt_hash(_material(password), secrets.token_bytes(16), self.scrypt_n, self.scrypt_r, self.scrypt_p)

    @staticmethod
    def _scrypt_raw(material, salt, n, r, p):
        return hashlib.scrypt(material, salt=salt, n=n, r=r, p=p, maxmem=128 * n * r * p * 2 + (1 << 20), dklen=32)

    def _scrypt_hash(self, material, salt, n, r, p):
        return "$scrypt$n=%d,r=%d,p=%d$%s$%s" % (n, r, p, _b64(salt), _b64(self._scrypt_raw(material, salt, n, r, p)))

    # ------------------------------------------------------------------ verification
    def verify(self, password, stored):
        """True when the password matches the stored hash. Dispatches on the stored hash's own prefix, so hashes made with another scheme or other parameters still verify."""
        try:
            if not isinstance(password, str) or not isinstance(stored, str):
                return False
            material = _material(password)
            if stored.startswith("$argon2id$"):
                return self._verify_argon2(material, stored)
            if stored.startswith("$scrypt$"):
                return self._verify_scrypt(material, stored)
        except Exception:         # a malformed stored hash or an impossible parameter: not a match, and never a crash that reveals why
            return False
        return False

    @staticmethod
    def _verify_argon2(material, stored):
        try:
            import argon2
            from argon2 import exceptions
        except ImportError:
            return False
        try:
            return bool(argon2.PasswordHasher().verify(stored, material))
        except (exceptions.VerifyMismatchError, exceptions.VerificationError, exceptions.InvalidHashError):
            return False

    def _verify_scrypt(self, material, stored):
        parts = stored.split("$")
        if len(parts) != 5:
            return False
        params = dict(item.split("=", 1) for item in parts[2].split(","))
        n, r, p = int(params["n"]), int(params["r"]), int(params["p"])
        if not (2 ** 12 <= n <= 2 ** 20 and n & (n - 1) == 0 and 1 <= r <= 16 and 1 <= p <= 4):
            return False
        salt, expected = _unb64(parts[3]), _unb64(parts[4])
        return hmac.compare_digest(self._scrypt_raw(material, salt, n, r, p), expected)

    # ------------------------------------------------------------------ upgrades
    def needs_rehash(self, stored):
        """True when the stored hash is not the configured scheme with the configured parameters."""
        try:
            if self.scheme == "argon2id":
                return not stored.startswith("$argon2id$") or self._argon.check_needs_rehash(stored)
            if not stored.startswith("$scrypt$"):
                return True
            params = dict(item.split("=", 1) for item in stored.split("$")[2].split(","))
            return (int(params["n"]), int(params["r"]), int(params["p"])) != (self.scrypt_n, self.scrypt_r, self.scrypt_p)
        except Exception:
            return True

    def dummy_hash(self):
        """A hash of a random secret, checked when the username does not exist so that an unknown name costs about as much time as a wrong password."""
        return self.hash(secrets.token_urlsafe(24))


def selftest():
    """Hash and verify with every available scheme; prints one line per scheme and returns a process exit code (0 = the configured default works)."""
    ok = True
    for scheme in SCHEMES:
        try:
            hasher = PasswordHasher(scheme)
            stored = hasher.hash("correct horse battery staple")
            good = hasher.verify("correct horse battery staple", stored) and not hasher.verify("wrong horse battery staple", stored)
            print("%-9s %s (%s...)" % (scheme, "OK" if good else "FAILED", stored[:24]))
            ok = ok and (good or scheme != "argon2id")
        except RuntimeError as error:
            print("%-9s NOT AVAILABLE: %s" % (scheme, error))
            ok = ok and scheme != "argon2id"
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
