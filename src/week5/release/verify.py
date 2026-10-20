"""Read-only verification. Every function takes paths and returns a list of Check records; nothing here writes into a project tree, opens a model, a database or the network, or touches the protected evaluation data.

What it reads in a project tree (all by path, hash only): the lock records reports/week4_memory_lock.json, reports/week3_agent_lock.json, reports/week2_baseline_lock.json (when present), the files those locks name,
and the Week 1 files the Week 4 lock lists. It refuses to hash any path that looks like protected evaluation data.
"""
import hashlib
import json
import os
import re

SCHEMA = "week5_verification_v1"
W4_LOCK = "reports/week4_memory_lock.json"
W3_LOCK = "reports/week3_agent_lock.json"
W2_LOCK = "reports/week2_baseline_lock.json"
FROZEN_LOG = "eval/frozen_access.log"
PROTECTED_MARKERS = ("frozen", "test.parquet", "final_test", "heldout", "held_out")      # a path containing one of these is never hashed (the access LOG is the one named exception)

# a payload file must never be one of these (secrets, state, data, history)
FORBIDDEN_TOP = ("eval", "data", "models", "reports", "memory_store", "runs", ".venv", ".git")          # top-level folders of the project that hold data, state or history
FORBIDDEN_ANYWHERE = ("memory_store", "runs", ".git", "__pycache__", ".venv", "node_modules")
FORBIDDEN_NAMES = (".env", ".env.week4", ".env.week5", ".env.local")
ALLOWED_ENV_SUFFIXES = (".example",)
SECRET_PATTERN = re.compile(r"AIza[0-9A-Za-z_\-]{30,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|sk-ant-[0-9A-Za-z_\-]{20,}|ghp_[0-9A-Za-z]{30,}|xox[bp]-[0-9A-Za-z\-]{10,}")


class Check(dict):
    def __init__(self, name, ok, detail="", kind="required"):
        super().__init__(name=name, ok=bool(ok), detail=str(detail)[:400], kind=kind)


def read_bytes(path):
    with open(path, "rb") as fh:
        return fh.read()


def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha_file(path, normalize=False):
    data = read_bytes(path)
    if normalize:
        data = data.replace(b"\r\n", b"\n")
    return sha_bytes(data)


def full(root, rel):
    return os.path.join(root, *rel.split("/"))


def refuse_protected(rel):
    low = rel.lower()
    if low == FROZEN_LOG:
        return False
    return any(m in low for m in PROTECTED_MARKERS)


def load_json(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def summarize(checks):
    required = [c for c in checks if c["kind"] == "required"]
    return {"required_total": len(required), "required_passed": sum(1 for c in required if c["ok"]), "failed": [c["name"] for c in required if not c["ok"]],
            "info_total": len(checks) - len(required), "info_failed": [c["name"] for c in checks if c["kind"] != "required" and not c["ok"]], "ok": all(c["ok"] for c in required)}


# ------------------------------------------------------------------------------------------------ the package manifest
def check_manifest(manifest, root, normalize=False, categories=("new", "modified")):
    """Every file the manifest lists (in the given categories) exists under root with its recorded hash. normalize=True compares LF-normalised hashes (for a tree checked out with CRLF line endings)."""
    out = []
    field = "sha256" if normalize else "raw_sha256"
    bad, missing, n = [], [], 0
    for rel, entry in sorted(manifest["files"].items()):
        if entry["category"] not in categories:
            continue
        n += 1
        path = full(root, rel)
        if not os.path.isfile(path):
            missing.append(rel)
        elif sha_file(path, normalize) != entry[field]:
            bad.append(rel)
    out.append(Check("every listed file is present (%d)" % n, not missing and n > 0, ", ".join(missing[:5])))
    out.append(Check("every listed file has its recorded SHA-256", not bad, ", ".join(bad[:5])))
    return out


def check_no_extra_files(manifest, root, payload_dir_only=True):
    """Nothing is in the package payload that the manifest does not list."""
    listed = set(manifest["files"])
    found = []
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for name in files:
            found.append(os.path.relpath(os.path.join(base, name), root).replace(os.sep, "/"))
    extra = sorted(set(found) - listed)
    return [Check("the payload holds no file the manifest does not list", not extra, ", ".join(extra[:5]))]


def check_forbidden(manifest, root=None):
    """No secret file, state folder, dataset or cache is listed; no file holds a key-shaped string."""
    out, bad, leaks = [], [], []
    for rel in manifest["files"]:
        parts = rel.split("/")
        name = parts[-1]
        if parts[0] in FORBIDDEN_TOP or any(p in FORBIDDEN_ANYWHERE for p in parts[:-1]) or (name.startswith(".env") and not name.endswith(ALLOWED_ENV_SUFFIXES)) or name in FORBIDDEN_NAMES:
            bad.append(rel)
        if root is not None:
            path = full(root, rel)
            if os.path.isfile(path):
                text = read_bytes(path).decode("utf-8", errors="ignore")
                if SECRET_PATTERN.search(text) and not rel.startswith("tests/") and "security/injection/data" not in rel and "docs/" not in rel:
                    leaks.append(rel)
    out.append(Check("no secret file, state folder, dataset or cache is shipped", not bad, ", ".join(bad[:5])))
    if root is not None:
        out.append(Check("no shipped source file holds a key-shaped string", not leaks, ", ".join(leaks[:5])))
    return out


def check_conflicts(manifest, root):
    """BEFORE applying: no file the package adds already exists in the project with different content (copying would silently overwrite it). An identical file is not a conflict."""
    clash, same = [], 0
    for rel, entry in sorted(manifest["files"].items()):
        path = full(root, rel)
        if os.path.isfile(path):
            if sha_file(path, True) == entry["sha256"]:
                same += 1
            else:
                clash.append(rel)
    return [Check("no existing project file would be overwritten with different content (%d already identical)" % same, not clash, ", ".join(clash[:8]))]


# ------------------------------------------------------------------------------------------------ the locked Week 1 / 2 / 3 / 4 artifacts
def _norm_map(root, mapping, label, normalize=True):
    """Compare files to {path: sha256}. normalize=True: CRLF->LF first (source and text files, as the Week 2/3/4 locks record them). normalize=False: raw bytes (the Week 1 data and model files)."""
    changed, missing = [], []
    for rel, want in sorted(mapping.items()):
        if refuse_protected(rel):
            changed.append(rel + " (refused: protected path)")
            continue
        path = full(root, rel)
        if not os.path.isfile(path):
            missing.append(rel)
        elif sha_file(path, normalize) != want:
            changed.append(rel)
    return changed, missing


def check_locks(root):
    """The Week 4 lock and everything it records, then the Week 3 and Week 2 locks. A missing or malformed lock is a failed check, not a skipped one."""
    out = []
    p4 = full(root, W4_LOCK)
    if not os.path.isfile(p4):
        return [Check("Week 4 lock record exists (" + W4_LOCK + ")", False, "not found under " + root)]
    try:
        lock4 = load_json(p4)
        sources4 = lock4["source_files_sha256"]
        w3 = lock4["week3"]
        w1 = lock4["split_boundaries"]["week1_files_sha256"]
        report = lock4["report"]
        art = lock4["artifact_manifest"]
        frozen_log = lock4["split_boundaries"]["frozen_access_log"]
    except (ValueError, KeyError, TypeError, OSError) as error:
        return [Check("Week 4 lock record is readable and well formed", False, type(error).__name__ + ": " + str(error)[:120])]
    out.append(Check("Week 4 lock record is readable and well formed", True))

    changed, missing = _norm_map(root, sources4, "w4")
    out.append(Check("every locked Week 4 file is unchanged (%d)" % len(sources4), not changed and not missing, ", ".join((changed + ["missing: " + m for m in missing])[:5])))
    rp = full(root, report["path"])
    out.append(Check("WEEK4_REPORT.md is unchanged", os.path.isfile(rp) and sha_file(rp, True) == report["sha256_normalized"]))
    ap = full(root, art["path"])
    out.append(Check("Week 4 artifact manifest is unchanged", os.path.isfile(ap) and sha_file(ap) == art["sha256"]))
    if os.path.isfile(ap):
        try:
            entries = load_json(ap)["files"]
            bad = []
            for rel, e in sorted(entries.items()):
                if refuse_protected(rel):
                    bad.append(rel + " (refused)")
                    continue
                path = full(root, rel)
                norm = rel in sources4 or rel == report["path"]
                if not os.path.isfile(path) or sha_file(path, norm) != e["sha256"]:
                    bad.append(rel)
            out.append(Check("every artifact in the Week 4 manifest keeps its SHA-256 (%d)" % len(entries), not bad, ", ".join(bad[:5])))
        except (ValueError, KeyError, TypeError) as error:
            out.append(Check("every artifact in the Week 4 manifest keeps its SHA-256", False, type(error).__name__))

    changed, missing = _norm_map(root, w1, "w1", normalize=False)       # Week 1 files are hashed as raw bytes by run_baseline_dev.week1_snapshot (they include binary data)
    out.append(Check("the Week 1 files recorded in the Week 4 lock are unchanged (%d)" % len(w1), not changed and not missing and len(w1) > 0, ", ".join((changed + missing)[:5])))

    p3 = full(root, w3["lock_file"])
    out.append(Check("Week 3 lock file is unchanged", os.path.isfile(p3) and sha_file(p3) == w3["lock_file_sha256"]))
    rp3 = full(root, "WEEK3_REPORT.md")
    out.append(Check("WEEK3_REPORT.md is unchanged", os.path.isfile(rp3) and sha_file(rp3, True) == w3["report_sha256_normalized"]))
    changed, missing = _norm_map(root, w3["locked_sources_sha256"], "w3")
    out.append(Check("every locked Week 3 source file is unchanged (%d)" % len(w3["locked_sources_sha256"]), not changed and not missing, ", ".join((changed + missing)[:5])))
    if os.path.isfile(p3):
        try:
            lock3 = load_json(p3)
            changed, missing = _norm_map(root, lock3["source_files_sha256"], "w3b")
            out.append(Check("every source file in the Week 3 lock itself is unchanged (%d)" % len(lock3["source_files_sha256"]), not changed and not missing, ", ".join((changed + missing)[:5])))
        except (ValueError, KeyError, TypeError) as error:
            out.append(Check("the Week 3 lock record is well formed", False, type(error).__name__))
    p2 = full(root, W2_LOCK)
    if os.path.isfile(p2):
        try:
            locked2 = load_json(p2)["locked_source_files_sha256"]
            changed, missing = _norm_map(root, locked2, "w2")
            out.append(Check("the Week 2 locked source files are unchanged (%d)" % len(locked2), not changed and not missing, ", ".join((changed + missing)[:5])))
        except (ValueError, KeyError, TypeError) as error:
            out.append(Check("the Week 2 lock record is well formed", False, type(error).__name__))
    else:
        out.append(Check("Week 2 lock record present", False, "not found; the Week 2 hash check was skipped", kind="info"))

    fl = full(root, FROZEN_LOG)
    if os.path.isfile(fl):
        lines = read_bytes(fl).count(b"\n")
        same = lines == frozen_log.get("lines") and sha_file(fl, True) == frozen_log.get("sha256_normalized")
        out.append(Check("frozen-set access LOG equals the Week 4 lock (the log only; the set is never opened). Differs after any authorised final evaluation, by design", same,
                         "" if same else "log has %d line(s); the lock recorded %s" % (lines, frozen_log.get("lines")), kind="info"))
    else:
        out.append(Check("frozen-set access log present", frozen_log.get("lines") in (0, None), "no log file", kind="info"))
    return out


def locked_paths(root):
    """Every path any lock record names, for the overlap check. Empty set when the locks are absent."""
    paths = set()
    p4 = full(root, W4_LOCK)
    if not os.path.isfile(p4):
        return paths
    try:
        lock4 = load_json(p4)
        paths |= set(lock4["source_files_sha256"]) | set(lock4["week3"]["locked_sources_sha256"]) | set(lock4["split_boundaries"]["week1_files_sha256"])
        paths |= {lock4["week3"]["lock_file"], lock4["report"]["path"], lock4["artifact_manifest"]["path"], W4_LOCK, "WEEK3_REPORT.md"}
        p3 = full(root, lock4["week3"]["lock_file"])
        if os.path.isfile(p3):
            paths |= set(load_json(p3)["source_files_sha256"])
        p2 = full(root, W2_LOCK)
        if os.path.isfile(p2):
            paths |= set(load_json(p2)["locked_source_files_sha256"]) | {W2_LOCK}
    except (ValueError, KeyError, TypeError):
        pass
    return paths


def check_no_overlap(manifest, root):
    """The package replaces no locked file: its paths and the locked paths are disjoint, and nothing is listed as 'modified'."""
    locked = locked_paths(root)
    clash = sorted(set(manifest["files"]) & locked)
    modified = sorted(p for p, e in manifest["files"].items() if e["category"] == "modified")
    out = [Check("the package replaces no locked Week 1/2/3/4 file (%d locked paths known)" % len(locked), not clash, ", ".join(clash[:5])),
           Check("the package modifies no existing file", not modified, ", ".join(modified[:5]))]
    if not locked:
        out.append(Check("lock records were readable, so the overlap check was complete", False, "no lock record found under the project root; overlap not proven", kind="info"))
    return out


# ------------------------------------------------------------------------------------------------ the before / after fingerprint
def fingerprint(root):
    """Raw-byte hashes of the lock records and of every file they name, so a run before applying the package and a run after can be compared (same tree, so line endings cannot differ)."""
    paths = sorted(locked_paths(root))
    out = {}
    for rel in paths:
        path = full(root, rel)
        if refuse_protected(rel):
            continue
        out[rel] = sha_file(path) if os.path.isfile(path) else None
    return {"schema": "week5_locked_fingerprint_v1", "note": "sha256 of the raw bytes; null means the file was absent", "files": out}


def compare_fingerprint(before, root):
    now = fingerprint(root)["files"]
    changed = sorted(p for p, h in before["files"].items() if now.get(p) != h)
    appeared = sorted(p for p in now if p not in before["files"])
    return [Check("no locked file changed since the fingerprint was taken (%d files)" % len(before["files"]), not changed and not appeared, ", ".join((changed + appeared)[:5]))]
