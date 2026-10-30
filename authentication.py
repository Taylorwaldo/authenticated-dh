"""Ed25519 identity signatures and trusted-key lookup.

The signature math comes entirely from the `cryptography` package. This module
only decides which key to use (the pre-configured trusted key for the claimed
identity) and what bytes to sign (the canonical payload encoding).
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Dict, Iterable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from messages import canonical_encode


class AuthenticationError(Exception):
    """Raised when a signature is invalid or no trusted key exists."""


class TrustStore:
    """Read-only mapping of identity label -> authentic Ed25519 public key.

    Built once by trusted_setup(). Eve controls the network but cannot modify
    this configuration, so a key that arrives in a message is never trusted.
    """

    def __init__(self, entries: Mapping[str, Ed25519PublicKey]):
        self._keys = MappingProxyType(dict(entries))

    def key_for(self, identity: str) -> Ed25519PublicKey:
        try:
            return self._keys[identity]
        except KeyError:
            raise AuthenticationError(f"no trusted signing key configured for {identity!r}") from None

    def __contains__(self, identity: object) -> bool:
        return identity in self._keys

    @property
    def identities(self) -> "tuple[str, ...]":
        return tuple(sorted(self._keys))


def generate_signing_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def key_fingerprint(public_key: Ed25519PublicKey) -> str:
    """Short hex fingerprint of a public key, for display only."""
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return raw.hex()[:16]


def sign_payload(signing_key: Ed25519PrivateKey, payload: Dict) -> bytes:
    return signing_key.sign(canonical_encode(payload))


def verify_payload(trust_store: TrustStore, identity: str, payload: Dict, signature: bytes) -> None:
    """Verify `signature` against the TRUSTED key for `identity`.

    verify() returns None on success and raises InvalidSignature on failure;
    its return value is never treated as a Boolean.
    """
    public_key = trust_store.key_for(identity)
    try:
        public_key.verify(signature, canonical_encode(payload))
    except InvalidSignature:
        raise AuthenticationError(f"signature attributed to {identity!r} is INVALID") from None


def trusted_setup(participants: Iterable) -> None:
    """Provision each participant with every other participant's real public key.

    Example result:
        Alice's trusted keys: "Bob"   -> Bob's authentic signing public key
        Bob's trusted keys:   "Alice" -> Alice's authentic signing public key
    """
    participants = list(participants)
    for me in participants:
        entries = {
            other.name: other.verification_key
            for other in participants
            if other.name != me.name
        }
        me.install_trust_store(TrustStore(entries))
