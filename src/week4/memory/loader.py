"""Reading the training split. The ONLY file this package will seed from is train.parquet; a missing file is an error, never a reason to use something else."""
import hashlib
import os

import config

from .errors import MemoryDataError

TRAIN_FILE_NAME = "train.parquet"


def default_train_path():
    return config.TRAIN_PATH


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def check_train_path(path):
    """Refuse any file that is not train.parquet, and any that is missing. Returns the path."""
    if os.path.basename(str(path)) != TRAIN_FILE_NAME:
        raise MemoryDataError("incident memory is seeded only from " + TRAIN_FILE_NAME + " (the training split); refusing " + os.path.basename(str(path)))
    if not os.path.isfile(path):
        raise MemoryDataError("the training split " + str(path) + " does not exist. Build it with the Week 1 pipeline (src/split.py). "
                              "Seeding stops here: no other data (dev, validation, test or frozen) is ever substituted.")
    return path


def load_train_frame(path=None):
    """(DataFrame, sha256 of the file). Needs pandas with a parquet engine (pyarrow)."""
    path = check_train_path(path or default_train_path())
    import pandas as pd
    try:
        frame = pd.read_parquet(path)
    except ImportError as error:
        raise MemoryDataError("reading parquet needs pyarrow: pip install pyarrow") from error
    except Exception as error:
        raise MemoryDataError("the training split could not be read: " + type(error).__name__) from None
    return frame, file_sha256(path)
