"""Week 5-specific PostgreSQL repository compatibility."""
import json

from week4.db.repository import PgRepository


class Week5PgRepository(PgRepository):
    """Keep Week 5 JSONB ingestion compatible with psycopg 3."""

    def ingest_case(self, payload):
        row = self._one(
            "SELECT * FROM soc.ingest_case(%s::jsonb)",
            [json.dumps(payload)],
        )
        return {
            "outcome": row["outcome"],
            "case_id": row["o_case_id"],
            "status": row["o_status"],
            "detail": row["detail"],
        }
