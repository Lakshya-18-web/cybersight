"""Vector search backends for the memory store. Both answer: the n nearest stored vectors to a query, as (index, euclidean distance), nearest first.

NumpyBackend   exact brute-force search. Deterministic (ties are broken by stored order, which is memory_id order). The reference, used by the offline tests and recommended for evaluation runs.
ChromaBackend  an index in a ChromaDB collection (needs `pip install -r requirements-week4.txt`). It is built from the same verified files as the numpy store, with explicit embeddings,
               so ChromaDB never computes an embedding and never sees anything but the fingerprint vectors. Its search is approximate (HNSW); store.agreement_check() measures how often it
               agrees with the exact search. It was NOT run in the sandbox that produced this code (chromadb could not be installed there); see docs/WEEK4_OPERATIONS.md.
"""
import numpy as np

from .errors import MemoryStoreError


class NumpyBackend:
    name = "numpy"

    def __init__(self, vectors):
        self.vectors = np.asarray(vectors, dtype=np.float64)

    def query(self, vec, n):
        if len(self.vectors) == 0:
            return []
        dist = np.linalg.norm(self.vectors - np.asarray(vec, dtype=np.float64), axis=1)
        order = np.argsort(dist, kind="stable")[:n]
        return [(int(i), float(dist[i])) for i in order]


class ChromaBackend:
    name = "chroma"

    def __init__(self, path, collection_name, ids=None, vectors=None, metadatas=None):
        """Open (ids is None) or build (ids given) the collection. path is a directory for chromadb.PersistentClient."""
        try:
            import chromadb
        except ImportError as error:
            raise MemoryStoreError("ChromaDB is not installed. Install it with: pip install -r requirements-week4.txt (or use --backend numpy)") from error
        self.client = chromadb.PersistentClient(path=path)
        self.collection_name = collection_name
        if ids is not None:
            try:
                self.client.delete_collection(collection_name)
            except Exception:    # not there yet
                pass
            self.collection = self.client.create_collection(collection_name, metadata={"hnsw:space": "l2"})
            batch = 2000
            for start in range(0, len(ids), batch):
                end = start + batch
                self.collection.add(ids=list(ids[start:end]), embeddings=[list(map(float, v)) for v in vectors[start:end]], metadatas=list(metadatas[start:end]))
        else:
            try:
                self.collection = self.client.get_collection(collection_name)
            except Exception as error:
                raise MemoryStoreError("the ChromaDB collection " + collection_name + " does not exist; rebuild the memory") from error
        self.ids = None

    def count(self):
        return self.collection.count()

    def query_ids(self, vec, n):
        """[(memory_id, distance)] nearest first. Chroma's l2 space returns SQUARED distance, so it is square-rooted to match the numpy backend."""
        n = min(n, max(self.collection.count(), 1))
        out = self.collection.query(query_embeddings=[list(map(float, vec))], n_results=n, include=["distances"])
        return [(i, float(max(d, 0.0)) ** 0.5) for i, d in zip(out["ids"][0], out["distances"][0])]
