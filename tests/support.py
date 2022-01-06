import os
import tempfile
from contextlib import contextmanager


@contextmanager
def temporary_file(**kwargs):
    """
    Create a temporary file and delete it afterwards.
    """
    t = tempfile.NamedTemporaryFile(delete=False, **kwargs)
    try:
        yield t
    finally:
        t.close()
        os.remove(t.name)
