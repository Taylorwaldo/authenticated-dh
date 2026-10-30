"""Eve: an active network attacker.

Eve controls every simulated network message: she can read, record, drop,
modify, re-sign with her own key, and replay. She cannot modify the trusted
key configuration or read anyone's private keys.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from authentication import generate_signing_key, sign_payload
from messages import canonical_encode
from modular_math import modular_exponentiation
from protocol import (
    TEACHING_FIXTURE,
    ClassroomFixture,
    Endpoint,
    ExchangeReport,
    run_authenticated_exchange,
    unauthenticated_exchange,
)


class Eve:
    def __init__(self):
        self._signing_key = generate_signing_key()  # Eve's OWN key, not trusted by anyone
        self.recorded: Dict[str, List[bytes]] = {}

    # ------------------------------------------------------------ recording

    def record(self, label: str, raw: bytes) -> bytes:
        self.recorded.setdefault(label, []).append(raw)
        return raw

    def tap(self) -> Callable[[str, bytes], bytes]:
        """A passive channel that records everything and changes nothing."""
        return self.record

    # ------------------------------------------------------------ tampering

    @staticmethod
    def modify_field(raw: bytes, path: Sequence[str], value: Any) -> bytes:
        """Change one payload field but keep the ORIGINAL signature.

        path is relative to the payload, e.g. ("A",) or ("transcript", "B").
        """
        envelope = json.loads(raw)
        target = envelope["payload"]
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
        return canonical_encode(envelope)

    def resign(self, raw: bytes, path: Optional[Sequence[str]] = None, value: Any = None) -> bytes:
        """Optionally modify a field, then sign the payload with EVE's key."""
        envelope = json.loads(raw if path is None else self.modify_field(raw, path, value))
        envelope["signature"] = sign_payload(self._signing_key, envelope["payload"]).hex()
        return canonical_encode(envelope)

    @staticmethod
    def corrupt_signature(raw: bytes) -> bytes:
        """Flip one bit of the signature (still valid hex, wrong value)."""
        envelope = json.loads(raw)
        sig = bytearray(bytes.fromhex(envelope["signature"]))
        sig[0] ^= 0x01
        envelope["signature"] = sig.hex()
        return canonical_encode(envelope)

    @staticmethod
    def channel_that(label: str, transform: Callable[[bytes], bytes]) -> Callable[[str, bytes], bytes]:
        """Build a channel that applies `transform` only to messages named `label`."""
        def channel(msg_label: str, raw: bytes) -> bytes:
            return transform(raw) if msg_label == label else raw
        return channel


# ==========================================================================
# Demonstrations (use the small p = 23 teaching fixture)
# ==========================================================================

def unauthenticated_mitm_demo(
    fixture: ClassroomFixture = TEACHING_FIXTURE, e1: int = 3, e2: int = 7
) -> Dict[str, int]:
    """Eve substitutes E1 for B (to Alice) and E2 for A (to Bob)."""
    p, g = fixture.p, fixture.g
    E1 = modular_exponentiation(g, e1, p)
    E2 = modular_exponentiation(g, e2, p)

    def eve_channel(label: str, value: int) -> int:
        return E1 if label == "B" else E2  # every public value is swapped

    run = unauthenticated_exchange(p, g, fixture.alice_exponent, fixture.bob_exponent, eve_channel)
    run.update(
        e1=e1,
        e2=e2,
        E1=E1,
        E2=E2,
        eve_secret_with_alice=modular_exponentiation(run["A"], e1, p),
        eve_secret_with_bob=modular_exponentiation(run["B"], e2, p),
    )
    return run


def authenticated_substitution_demo(
    alice: Endpoint,
    bob: Endpoint,
    fixture: ClassroomFixture = TEACHING_FIXTURE,
    e1: int = 3,
) -> Tuple[ExchangeReport, int]:
    """Eve swaps Bob's B for her E1 but cannot re-sign it as Bob."""
    E1 = modular_exponentiation(fixture.g, e1, fixture.p)
    channel = Eve.channel_that("response", lambda raw: Eve.modify_field(raw, ("transcript", "B"), E1))
    return run_authenticated_exchange(alice, bob, fixture=fixture, channel=channel), E1
