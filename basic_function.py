"""A small function used to verify the project test setup."""


def basic_function(value: int) -> int:
    """Return ``value`` doubled.

    ``bool`` is rejected because it is a subclass of ``int`` but is not a
    numeric input this function accepts.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("value must be an int")
    return value * 2
