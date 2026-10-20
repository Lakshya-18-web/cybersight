"""Build and read the package manifest. The manifest lists every payload file with two hashes: raw_sha256 (the bytes as shipped, checked on the extracted package) and sha256 (CRLF normalised to LF,
checked on a project tree where Git may have changed line endings). Categories: new (the file does not exist in the project), modified (a complete replacement of an existing file; Week 5 ships none)."""
import datetime
import json
import os

from . import VERSION
from .verify import read_bytes, sha_bytes

SCHEMA = "week5_package_manifest_v1"


def build(payload_dir, modified=(), extra_note=""):
    files = {}
    for base, dirs, names in os.walk(payload_dir):
        dirs[:] = sorted(d for d in dirs if d != "__pycache__")
        for name in sorted(names):
            if name.endswith((".pyc", ".pyo")):
                continue
            path = os.path.join(base, name)
            rel = os.path.relpath(path, payload_dir).replace(os.sep, "/")
            data = read_bytes(path)
            files[rel] = {"raw_sha256": sha_bytes(data), "sha256": sha_bytes(data.replace(b"\r\n", b"\n")), "bytes": len(data), "category": "modified" if rel in set(modified) else "new"}
    return {"schema": SCHEMA, "package_version": VERSION, "generated_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "payload_root": "payload",
            "note": extra_note or "Paths are relative to the project root. Copy the contents of payload/ onto the project root. No listed file replaces an existing one.",
            "file_count": len(files), "total_bytes": sum(f["bytes"] for f in files.values()), "files": dict(sorted(files.items()))}


def load(path):
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if data.get("schema") != SCHEMA or not isinstance(data.get("files"), dict):
        raise ValueError("not a Week 5 package manifest")
    return data


def write(manifest, path):
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=False)
        fh.write("\n")
