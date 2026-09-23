"""Correct repro: asserts the documented contract, which the defect violates.

Expected verdict: rediscovered (fails on base, passes under the gold patch).
"""

from toylib.core import chunk


def test_chunk_preserves_every_element():
    assert chunk([1, 2, 3, 4], 2) == [[1, 2], [3, 4]]
