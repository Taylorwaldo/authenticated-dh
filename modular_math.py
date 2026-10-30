"""Square-and-multiply modular exponentiation (implemented by hand).

Python's built-in three-argument pow() is intentionally NOT used here. The
tests use it only as an independent reference to check this implementation.
"""

from __future__ import annotations


def is_strict_int(value: object) -> bool:
    """Return True for real integers, rejecting bool (which subclasses int)."""
    return isinstance(value, int) and not isinstance(value, bool)


def modular_exponentiation(base: int, exponent: int, modulus: int) -> int:
    """Compute base**exponent mod modulus without building the full power.

    Accepts any integer base, a nonnegative integer exponent, and a positive
    integer modulus. Returns a value in the range 0 .. modulus - 1.

    Each loop iteration looks at the lowest binary digit of the exponent:
      * if it is 1 (exponent is odd) the current power of the base is
        multiplied into the result;
      * the base is squared to become the next power-of-two power;
      * the exponent is halved to move to the next binary digit.
    Every product is reduced mod modulus immediately, so intermediate values
    never grow beyond modulus**2. The loop runs O(log exponent) times.
    """
    if not (is_strict_int(base) and is_strict_int(exponent) and is_strict_int(modulus)):
        raise TypeError("base, exponent, and modulus must all be integers")
    if exponent < 0:
        raise ValueError("exponent must be nonnegative")
    if modulus <= 0:
        raise ValueError("modulus must be positive")

    result = 1 % modulus          # handles modulus == 1 (everything is 0)
    base = base % modulus         # Python % always returns 0..modulus-1, so negative bases work

    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent = exponent // 2

    return result
