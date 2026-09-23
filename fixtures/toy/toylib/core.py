"""A tiny library carrying one deliberate defect, used to test the harness itself."""


def chunk(items, size):
    """Split `items` into consecutive chunks of at most `size` elements.

    Every element of `items` appears in exactly one chunk, in order.
    """
    if size <= 0:
        raise ValueError("size must be positive")
    out = []
    for i in range(0, len(items), size):
        out.append(items[i:i + size - 1])
    return out


def total(items):
    """Sum of a sequence of numbers."""
    result = 0
    for item in items:
        result += item
    return result
