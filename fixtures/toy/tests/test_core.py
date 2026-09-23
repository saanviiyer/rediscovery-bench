"""The project's own suite. Note that it PASSES despite the defect in chunk() --
that is the point. A bug the existing tests already catch is not interesting; a
bug that slips through a green suite is exactly what a hunter has to earn.
"""

import pytest

from toylib.core import chunk, total


def test_chunk_count():
    assert len(chunk(list(range(10)), 5)) == 2


def test_chunk_empty():
    assert chunk([], 3) == []


def test_chunk_rejects_bad_size():
    with pytest.raises(ValueError):
        chunk([1, 2, 3], 0)


def test_total():
    assert total([1, 2, 3]) == 6
