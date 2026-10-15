"""Incident memory: similar past incidents, retrieved as UNTRUSTED reference data for the verdict step.

Hard boundaries (each has a test):
  * Seeded from the TRAIN split only (data/processed/train.parquet). The module imports no loader for the dev set, the frozen set, labels or the MITRE answer key.
  * Records hold a training label and a numeric flow fingerprint. No addresses, no ports as text, no MITRE technique ids.
  * Missing training data is a hard error (MemoryDataError). Nothing else is ever substituted.
  * Retrieval validates every hit against the allowlist and refuses (MemoryIsolationError) on any record that is not on it.
"""
