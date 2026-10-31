# Week 4 JSONB Repository Change

## Change
Updated `src/week4/db/repository.py` so `PgRepository.ingest_case`
serializes the payload with `json.dumps(payload)` and explicitly casts
the SQL parameter to `jsonb`.

## Reason
The change addresses PostgreSQL parameter adaptation for JSON payloads.

## Validation
- PostgreSQL semantics tests: 30 passed, 0 failed, 0 skipped.
- Full Week 5 suite: 2,141 passed, 1 failed, 204 skipped.
- Remaining failure: Week 4 frozen-lock and artifact-manifest checks
  identify `src/week4/db/repository.py`.

## Evidence integrity
The Week 4 lock and artifact manifest remain unchanged.
The original tagged file's CRLF-normalized SHA-256 matches the recorded
Week 4 lock hash.

## Status
Reviewed change record; formal approval and release-baseline decision
are still pending. This record does not override or bypass lock checks.
