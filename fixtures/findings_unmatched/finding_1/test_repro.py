"""A reproducible failure that the held-out fix does not address.

Expected verdict: unmatched. Distinguishing this from a rediscovery is the whole
reason the oracle is differential rather than "did the agent report something".
"""

from toylib.core import chunk


def test_negative_size_returns_empty():
    assert chunk([1, 2, 3], -1) == []
