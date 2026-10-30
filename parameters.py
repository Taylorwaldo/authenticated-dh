"""Public parameter generation and validation.

* generate_prime          - wrapper around PyCryptodome's prime generator
* validate_received_modulus - type, size, then library primality check
* prime_factors           - trial-division factorization (implemented by hand)
* is_generator / find_generator - primitive-root test (implemented by hand)

Prime generation and primality testing are delegated to the library, as the
assignment requires. Factorization and generator checks are written here.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import FrozenSet, Iterable, Optional

from Crypto.Util.number import getPrime, isPrime

from modular_math import is_strict_int, modular_exponentiation

MIN_PRIME_BITS = 16
MAX_PRIME_BITS = 32
DEFAULT_PRIME_BITS = 16

# Smallest modulus allowed through the explicit test-fixture path. p must be at
# least 5 so that the range 2 .. p - 2 for g and private exponents is nonempty.
FIXTURE_MIN_MODULUS = 5

BIT_RANGE_ERROR = f"prime size must be between {MIN_PRIME_BITS} and {MAX_PRIME_BITS} bits."
BIT_TYPE_ERROR = "prime size must be an integer."


class ParameterError(ValueError):
    """Raised when a requested size or a received parameter is unacceptable."""


# --------------------------------------------------------------------------
# Bit-length handling
# --------------------------------------------------------------------------

def validate_bit_length(bits: object) -> int:
    """Return bits if it is an integer from 16 through 32; otherwise raise.

    Booleans are rejected even though bool is a subclass of int.
    """
    if not is_strict_int(bits):
        raise ParameterError(BIT_TYPE_ERROR)
    if not MIN_PRIME_BITS <= bits <= MAX_PRIME_BITS:
        raise ParameterError(BIT_RANGE_ERROR)
    return bits


def parse_bit_length_input(text: str) -> int:
    """Parse user-typed input such as "16" and validate it.

    Noninteger text (for example "16.5" or "abc") is rejected rather than
    rounded.
    """
    try:
        value = int(str(text).strip())
    except ValueError:
        raise ParameterError(BIT_TYPE_ERROR) from None
    return validate_bit_length(value)


def allowed_prime_range(bits: int) -> range:
    """Return the range of integers with exactly `bits` bits: 2^(k-1) <= p < 2^k."""
    bits = validate_bit_length(bits)
    return range(2 ** (bits - 1), 2 ** bits)


# --------------------------------------------------------------------------
# Step 2: library prime generation
# --------------------------------------------------------------------------

def generate_prime(bits: int = DEFAULT_PRIME_BITS) -> int:
    """Return a prime with exactly `bits` bits using PyCryptodome.

    The library performs candidate selection and its own internal primality
    checks; this wrapper only validates the request and the returned value.
    """
    bits = validate_bit_length(bits)
    p = getPrime(bits, randfunc=secrets.token_bytes)
    if p.bit_length() != bits or p % 2 == 0:
        # Should never happen with a correct library; fail closed if it does.
        raise RuntimeError(f"library returned an unexpected value for a {bits}-bit prime")
    return p


def generate_prime_timed(bits: int = DEFAULT_PRIME_BITS) -> "tuple[int, float]":
    """Run generate_prime and measure the total wrapper time with perf_counter."""
    start = time.perf_counter()
    p = generate_prime(bits)
    return p, time.perf_counter() - start


def validate_received_modulus(p: object, *, allow_fixture: bool = False) -> int:
    """Validate a modulus received from a peer before using it.

    Order: type check, then size bounds, then the library's isPrime(p).
    Size bounds are enforced before any expensive arithmetic.

    Normal runs require a 16-32 bit modulus. allow_fixture=True is the explicit
    test-fixture path that also permits small values such as p = 23.
    """
    if not is_strict_int(p):
        raise ParameterError("modulus must be an integer")
    if allow_fixture:
        if p < FIXTURE_MIN_MODULUS or p.bit_length() > MAX_PRIME_BITS:
            raise ParameterError("fixture modulus is outside the permitted range")
    elif not MIN_PRIME_BITS <= p.bit_length() <= MAX_PRIME_BITS:
        raise ParameterError(
            f"modulus has {p.bit_length()} bits; {BIT_RANGE_ERROR}"
        )
    if not isPrime(p):
        raise ParameterError(f"modulus {p} failed the library primality check (composite)")
    return p


# --------------------------------------------------------------------------
# Step 3: factor p - 1
# --------------------------------------------------------------------------

def prime_factors(n: int) -> FrozenSet[int]:
    """Return the set of distinct prime factors of a positive integer n.

    Trial division:
      1. Divide out every factor of 2, recording 2 once.
      2. Try odd divisors starting at 3.
      3. For each divisor, divide out all occurrences and record it once.
      4. Stop when divisor * divisor exceeds the remaining n.
      5. If the remainder exceeds 1, it is prime; record it.

    prime_factors(1) returns an empty set.
    """
    if not is_strict_int(n):
        raise TypeError("n must be an integer")
    if n < 1:
        raise ValueError("n must be a positive integer")

    factors = set()
    remaining = n

    if remaining % 2 == 0:
        factors.add(2)
        while remaining % 2 == 0:
            remaining //= 2

    divisor = 3
    while divisor * divisor <= remaining:
        if remaining % divisor == 0:
            factors.add(divisor)
            while remaining % divisor == 0:
                remaining //= divisor
        divisor += 2

    if remaining > 1:
        factors.add(remaining)

    return frozenset(factors)


# --------------------------------------------------------------------------
# Step 4: find and verify a generator
# --------------------------------------------------------------------------

def is_generator(g: object, p: int, factors: Optional[Iterable[int]] = None) -> bool:
    """Return True if g is a primitive root (generator) modulo prime p.

    The multiplicative group mod p has order p - 1. g generates the whole group
    exactly when g^((p - 1) / r) != 1 (mod p) for every distinct prime factor r
    of p - 1. The complete set of distinct prime factors must be used.

    Assumes p has already been validated as prime.
    """
    if not is_strict_int(g):
        return False
    if not 2 <= g <= p - 2:
        return False
    if factors is None:
        factors = prime_factors(p - 1)
    for r in factors:
        if modular_exponentiation(g, (p - 1) // r, p) == 1:
            return False
    return True


def find_generator(p: int, factors: Optional[Iterable[int]] = None) -> int:
    """Return the smallest generator g in 2 .. p - 2 for prime p."""
    if factors is None:
        factors = prime_factors(p - 1)
    factors = frozenset(factors)
    for g in range(2, p - 1):
        if is_generator(g, p, factors):
            return g
    raise ParameterError(f"no generator found for p = {p}")


# --------------------------------------------------------------------------
# Full parameter set with timings
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class DHParameters:
    """Public Diffie-Hellman parameters plus how long each step took."""

    p: int
    g: int
    factors: FrozenSet[int]
    prime_generation_seconds: float
    factorization_seconds: float
    generator_search_seconds: float

    @property
    def bits(self) -> int:
        return self.p.bit_length()


def generate_parameters(bits: int = DEFAULT_PRIME_BITS) -> DHParameters:
    """Generate p with the library, factor p - 1, and find a generator."""
    p, prime_seconds = generate_prime_timed(bits)

    start = time.perf_counter()
    factors = prime_factors(p - 1)
    factor_seconds = time.perf_counter() - start

    start = time.perf_counter()
    g = find_generator(p, factors)
    generator_seconds = time.perf_counter() - start

    return DHParameters(
        p=p,
        g=g,
        factors=factors,
        prime_generation_seconds=prime_seconds,
        factorization_seconds=factor_seconds,
        generator_search_seconds=generator_seconds,
    )
