"""Send an EVE file to a running API.   python -m week5.eve_send --base-url http://127.0.0.1:8000 --sensor sensor-lab-1 --file samples/eve/eve_mixed.ndjson

The token is read from the environment variable WEEK5_SENSOR_TOKEN (never from the command line, so it does not land in shell history or a process list). The file is sent in batches of up to 400 lines as
application/x-ndjson; every batch is idempotent, so running the command again creates nothing new. Prints one summary line per batch (counts only; no event content, no token).
Use it with a Suricata eve.json (one JSON object per line) or with the sample file. --no-analyze stores the events as evidence without queueing analysis jobs.
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request

BATCH_LINES = 400
SENSOR_OK = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")


def batches(path, size=BATCH_LINES):
    batch = []
    with open(path, "rb") as fh:
        for line in fh:
            if not line.strip():
                continue
            batch.append(line.rstrip(b"\r\n"))
            if len(batch) >= size:
                yield b"\n".join(batch) + b"\n"
                batch = []
    if batch:
        yield b"\n".join(batch) + b"\n"


def send(base_url, sensor, token, payload, analyze=True, timeout=30):
    """-> (status, parsed JSON or {})"""
    url = "%s/sensors/%s/eve%s" % (base_url.rstrip("/"), sensor, "" if analyze else "?analyze=false")
    req = urllib.request.Request(url, data=payload, method="POST", headers={"Authorization": "Bearer " + token, "Content-Type": "application/x-ndjson"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8") or "{}")
        except ValueError:
            return e.code, {}


def main(argv=None, out=None):
    out = out or print
    p = argparse.ArgumentParser(description="Send Suricata EVE JSON lines to the SOC API (sensor ingestion).")
    p.add_argument("--base-url", required=True)
    p.add_argument("--sensor", required=True, help="a name for this sensor (letters, digits, - _ .)")
    p.add_argument("--file", required=True)
    p.add_argument("--no-analyze", action="store_true")
    args = p.parse_args(argv)
    token = os.environ.get("WEEK5_SENSOR_TOKEN", "")
    if not token:
        out("STOPPED: set the environment variable WEEK5_SENSOR_TOKEN (an analyst or admin token)")
        return 2
    if not args.sensor or any(c not in SENSOR_OK for c in args.sensor) or len(args.sensor) > 64:
        out("STOPPED: the sensor name may use letters, digits, - _ . and at most 64 characters")
        return 2
    if not os.path.isfile(args.file):
        out("STOPPED: file not found")
        return 2
    totals = {"received": 0, "usable": 0, "stored": 0, "duplicates": 0, "rejected": 0, "alerts": 0}
    worst = 0
    for i, payload in enumerate(batches(args.file), 1):
        status, body = send(args.base_url, args.sensor, token, payload, analyze=not args.no_analyze)
        if status not in (200, 202):
            code = ((body.get("error") or {}).get("code")) if isinstance(body, dict) else None
            out("batch %d: HTTP %d %s" % (i, status, code or ""))
            worst = 1
            break
        for k in ("received", "usable", "stored", "duplicates"):
            totals[k] += int(body.get(k) or 0)
        totals["rejected"] += len(body.get("rejected") or [])
        totals["alerts"] += len(body.get("alerts") or [])
        out("batch %d: HTTP %d received=%s stored=%s duplicates=%s rejected=%s jobs=%s" % (i, status, body.get("received"), body.get("stored"), body.get("duplicates"), len(body.get("rejected") or []), body.get("jobs")))
    out("total: " + " ".join("%s=%d" % kv for kv in totals.items()))
    return worst


if __name__ == "__main__":
    sys.exit(main())
