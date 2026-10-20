"""python -m week5.release <command>

  build-manifest   --payload DIR --out FILE              list every payload file with SHA-256 (used when the package was assembled)
  verify-package   --package-dir DIR [--json FILE]       the extracted package: manifest hashes, no extra or forbidden files
  check-conflicts  --root DIR --package-dir DIR          BEFORE copying: would any project file be overwritten with different content?
  verify-applied   --root DIR --package-dir DIR [--json FILE]   after copying: the files in the project equal the manifest, no locked file is replaced
  verify-locks     --root DIR [--json FILE]              the Week 1/2/3/4 locked artifacts hash as their lock records say
  fingerprint      --root DIR --out FILE                 save the locked-artifact hashes BEFORE applying the package
  compare          --root DIR --fingerprint FILE         compare them AFTER applying

Read-only except for the output file you name. Exit code 0 only when every required check passed. No model, database, network or protected data is touched.
"""
import argparse
import json
import os
import sys

from . import manifest as M
from . import verify as V


def _say(checks):
    for c in checks:
        mark = "PASS" if c["ok"] else ("FAIL" if c["kind"] == "required" else "NOTE")
        print("[%s] %s%s" % (mark, c["name"], ("  -> " + c["detail"]) if c["detail"] and not c["ok"] else ""))
    s = V.summarize(checks)
    print("required checks passed: %d of %d%s" % (s["required_passed"], s["required_total"], "" if s["ok"] else "  (FAILED: " + "; ".join(s["failed"][:6]) + ")"))
    return s


def _emit(checks, path, command):
    s = _say(checks)
    if path:
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump({"schema": V.SCHEMA, "command": command, "summary": s, "checks": checks}, fh, indent=2)
            fh.write("\n")
    return 0 if s["ok"] else 1


def _manifest_and_payload(package_dir):
    manifest = M.load(os.path.join(package_dir, "release", "WEEK5_MANIFEST.json"))
    return manifest, os.path.join(package_dir, manifest.get("payload_root", "payload"))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m week5.release", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build-manifest")
    b.add_argument("--payload", required=True)
    b.add_argument("--out", required=True)
    p = sub.add_parser("verify-package")
    p.add_argument("--package-dir", required=True)
    p.add_argument("--json")
    x = sub.add_parser("check-conflicts")
    x.add_argument("--root", required=True)
    x.add_argument("--package-dir", required=True)
    x.add_argument("--json")
    a = sub.add_parser("verify-applied")
    a.add_argument("--root", required=True)
    a.add_argument("--package-dir", required=True)
    a.add_argument("--json")
    k = sub.add_parser("verify-locks")
    k.add_argument("--root", required=True)
    k.add_argument("--json")
    f = sub.add_parser("fingerprint")
    f.add_argument("--root", required=True)
    f.add_argument("--out", required=True)
    c = sub.add_parser("compare")
    c.add_argument("--root", required=True)
    c.add_argument("--fingerprint", required=True)
    c.add_argument("--json")
    args = ap.parse_args(argv)
    try:
        if args.command == "build-manifest":
            M.write(M.build(args.payload), args.out)
            print("wrote", args.out)
            return 0
        if args.command == "verify-package":
            manifest, payload = _manifest_and_payload(args.package_dir)
            checks = V.check_manifest(manifest, payload, normalize=False) + V.check_no_extra_files(manifest, payload) + V.check_forbidden(manifest, payload)
            return _emit(checks, args.json, "verify-package")
        if args.command == "check-conflicts":
            manifest, _payload = _manifest_and_payload(args.package_dir)
            return _emit(V.check_conflicts(manifest, args.root) + V.check_no_overlap(manifest, args.root), args.json, "check-conflicts")
        if args.command == "verify-applied":
            manifest, _payload = _manifest_and_payload(args.package_dir)
            checks = V.check_manifest(manifest, args.root, normalize=True) + V.check_no_overlap(manifest, args.root) + V.check_locks(args.root)
            return _emit(checks, args.json, "verify-applied")
        if args.command == "verify-locks":
            return _emit(V.check_locks(args.root), args.json, "verify-locks")
        if args.command == "fingerprint":
            with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
                json.dump(V.fingerprint(args.root), fh, indent=2)
                fh.write("\n")
            print("wrote", args.out)
            return 0
        if args.command == "compare":
            return _emit(V.compare_fingerprint(V.load_json(args.fingerprint), args.root), args.json, "compare")
    except (OSError, ValueError, KeyError) as error:
        print("verification could not run: %s: %s" % (type(error).__name__, str(error)[:200]), file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main())
