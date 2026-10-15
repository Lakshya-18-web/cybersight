class MemoryDataError(Exception):
    """The training data needed to seed the memory is missing or unusable. Seeding stops; no other data is substituted."""


class MemoryIsolationError(Exception):
    """A record or a result crossed the train-only boundary. Seeding or retrieval stops."""


class MemoryStoreError(Exception):
    """The stored memory is missing, damaged or does not match its manifest."""


class MemoryQueryError(Exception):
    """The alert cannot be turned into a query (a needed feature is missing or not a finite number)."""
