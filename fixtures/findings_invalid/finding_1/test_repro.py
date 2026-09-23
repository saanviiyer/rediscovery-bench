"""A claimed bug that is not a bug: this already passes on the buggy code.

Expected verdict: invalid. This is the noise channel -- the failure mode that
kills adoption if the harness cannot detect it.
"""

from toylib.core import chunk


def test_chunk_of_empty_is_empty():
    assert chunk([], 5) == []
