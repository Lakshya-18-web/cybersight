"""File hashing for the Week 4 lock and manifest.

Text files are hashed after normalising line endings to LF, so a Windows checkout with core.autocrlf=true gives the same hash as the repository. Binary files are hashed as they are.
"""
import hashlib
import os

TEXT_SUFFIXES = (".py", ".sql", ".json", ".md", ".txt", ".yml", ".yaml", ".csv", ".jsonl", ".cfg", ".toml", ".example")


def is_text(path):
    return os.path.basename(path).lower().endswith(TEXT_SUFFIXES) or os.path.basename(path).startswith(".env")


def sha256_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def normalized_sha256(path):
    with open(path, "rb") as fh:
        raw = fh.read()
    if is_text(path):
        raw = raw.replace(b"\r\n", b"\n")
    return sha256_bytes(raw)


def tree_hashes(root, relative_files):
    """{relative path with '/': normalised sha256} for the given files (missing files raise FileNotFoundError: a lock must never silently skip one)."""
    return {rel: normalized_sha256(os.path.join(root, *rel.split("/"))) for rel in sorted(relative_files)}


def list_files(root, subdir, suffixes):
    """Sorted relative paths ('/' separators) of files under root/subdir with one of the suffixes, skipping __pycache__."""
    found = []
    base = os.path.join(root, *subdir.split("/"))
    for folder, dirs, files in os.walk(base):
        dirs[:] = sorted(d for d in dirs if d != "__pycache__")
        for name in sorted(files):
            if name.endswith(tuple(suffixes)):
                found.append(os.path.relpath(os.path.join(folder, name), root).replace(os.sep, "/"))
    return sorted(found)


def combined_sha256(hashes):
    """One hash over a {path: sha} map (sorted, so order never matters)."""
    return sha256_bytes("\n".join(k + " " + hashes[k] for k in sorted(hashes)).encode("utf-8"))
