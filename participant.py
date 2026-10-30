"""Local state for one participant: identity signing key, trusted keys, DH math."""

from __future__ import annotations

import secrets
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from authentication import (
    TrustStore,
    generate_signing_key,
    sign_payload,
    verify_payload,
)
from messages import IDENTITY_LABELS
from modular_math import is_strict_int, modular_exponentiation

# Upper bound on retries when a fresh public value lands outside 2 .. p - 2.
_MAX_KEYGEN_ATTEMPTS = 1000


def public_value_in_range(value: int, p: int) -> bool:
    """Basic classroom check: 2 <= value <= p - 2 (rejects 0, 1, and p - 1)."""
    return is_strict_int(value) and 2 <= value <= p - 2


def generate_dh_keypair(p: int, g: int, fixture_exponent: Optional[int] = None) -> Tuple[int, int]:
    """Return a fresh (private_exponent, public_value) pair.

    private exponent: secrets.randbelow(p - 3) + 2, so 2 <= x <= p - 2
    public value:     g^x mod p using square-and-multiply

    If the public value falls outside 2 .. p - 2, a new exponent is drawn.
    fixture_exponent is the explicit test-fixture path (e.g. a = 6, b = 15).
    """
    if fixture_exponent is not None:
        if not is_strict_int(fixture_exponent) or not 2 <= fixture_exponent <= p - 2:
            raise ValueError("fixture exponent must be an integer in 2 .. p - 2")
        public = modular_exponentiation(g, fixture_exponent, p)
        if not public_value_in_range(public, p):
            raise ValueError("fixture exponent produces an out-of-range public value")
        return fixture_exponent, public

    for _ in range(_MAX_KEYGEN_ATTEMPTS):
        private = secrets.randbelow(p - 3) + 2
        public = modular_exponentiation(g, private, p)
        if public_value_in_range(public, p):
            return private, public
    raise RuntimeError("could not generate an in-range public value")


def compute_shared_secret(peer_public: int, private_exponent: int, p: int) -> int:
    """S = peer_public^private mod p."""
    return modular_exponentiation(peer_public, private_exponent, p)


class Participant:
    """Alice or Bob. Holds a long-term Ed25519 identity and trusted peer keys.

    The signing key is generated once and retained across exchanges within the
    simulation. It never leaves this object.
    """

    def __init__(self, name: str):
        if name not in IDENTITY_LABELS:
            raise ValueError(f"identity must be one of {sorted(IDENTITY_LABELS)}")
        self.name = name
        self._signing_key = generate_signing_key()
        self._trust_store: Optional[TrustStore] = None

    def __repr__(self) -> str:  # never print key material
        return f"Participant(name={self.name!r})"

    @property
    def verification_key(self) -> Ed25519PublicKey:
        return self._signing_key.public_key()

    def install_trust_store(self, trust_store: TrustStore) -> None:
        if self._trust_store is not None:
            raise RuntimeError("trusted configuration has already been provisioned")
        self._trust_store = trust_store

    @property
    def trust_store(self) -> TrustStore:
        if self._trust_store is None:
            raise RuntimeError(f"{self.name} has no trusted keys; run trusted_setup() first")
        return self._trust_store

    def sign(self, payload: Dict) -> bytes:
        return sign_payload(self._signing_key, payload)

    def verify_from(self, identity: str, payload: Dict, signature: bytes) -> None:
        """Raise AuthenticationError unless `identity`'s trusted key verifies it."""
        verify_payload(self.trust_store, identity, payload, signature)
