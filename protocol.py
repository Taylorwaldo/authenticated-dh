"""Three-message authenticated Diffie-Hellman protocol with session state.

    1. Alice -> Bob : init     {protocol, init, Alice, Bob, p, g, A, nonce_A}   + Alice sig
    2. Bob -> Alice : response {response, transcript}                         + Bob sig
    3. Alice -> Bob : finish   {finish,   transcript}                         + Alice sig

transcript = {protocol, initiator, responder, p, g, A, B, nonce_A, nonce_B}

Each Endpoint keeps pending-session records (one active exchange per peer per
role) so that responses and finishes must match the active exchange. Any
rejection aborts the affected session, clears its private exponent, and its
secret is never used.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Optional, Tuple

from authentication import AuthenticationError
from messages import (
    NONCE_BYTES,
    PROTOCOL_LABEL,
    MessageError,
    build_envelope,
    parse_envelope,
    validate_confirmation_payload,
    validate_init_payload,
)
from modular_math import modular_exponentiation
from parameters import (
    DEFAULT_PRIME_BITS,
    DHParameters,
    ParameterError,
    generate_parameters,
    is_generator,
    prime_factors,
    validate_received_modulus,
)
from participant import (
    Participant,
    compute_shared_secret,
    generate_dh_keypair,
    public_value_in_range,
)

# Signature status strings used in reports.
VALID = "VALID"
INVALID = "INVALID"
NOT_CHECKED = "NOT CHECKED"


class ProtocolError(Exception):
    """A message was rejected. `category` says which kind of check failed."""

    def __init__(self, message: str, category: str):
        super().__init__(message)
        self.category = category  # "format", "signature", "parameters", "session"


def _categorize(exc: Exception) -> str:
    if isinstance(exc, AuthenticationError):
        return "signature"
    if isinstance(exc, ParameterError):
        return "parameters"
    if isinstance(exc, MessageError):
        return "format"
    return "session"


class _SessionReject(Exception):
    """Internal: session-state or semantic rejection."""


@dataclass(frozen=True)
class ClassroomFixture:
    """Explicit test-fixture path. p = 23 is never allowed in normal runs."""

    p: int = 23
    g: int = 5
    alice_exponent: Optional[int] = 6
    bob_exponent: Optional[int] = 15


TEACHING_FIXTURE = ClassroomFixture()


@dataclass
class InitiatorSession:
    responder: str
    p: int
    g: int
    A: int
    nonce_A: str
    private_exponent: Optional[int]


@dataclass
class ResponderSession:
    initiator: str
    transcript: Dict
    private_exponent: Optional[int]


@dataclass(frozen=True)
class SessionResult:
    """Local outcome of a completed exchange (visible to the test coordinator)."""

    role: str
    peer: str
    transcript: Dict
    shared_secret: int = field(repr=False)  # never printed by default
    authenticated: bool = True


class Endpoint:
    """Protocol engine for one participant (can act as initiator or responder)."""

    def __init__(self, participant: Participant, *, debug: bool = False):
        self.participant = participant
        self.debug = debug
        self.debug_values: Dict[str, int] = {}     # only filled when debug=True
        self.last_checks: Dict[str, str] = {}      # what the last handler verified
        self.last_parameters: Optional[DHParameters] = None
        self._initiator_sessions: Dict[str, InitiatorSession] = {}
        self._responder_sessions: Dict[str, ResponderSession] = {}
        self._completed_nonces: set = set()

    @property
    def name(self) -> str:
        return self.participant.name

    def has_pending_session(self, peer: str) -> bool:
        return peer in self._initiator_sessions or peer in self._responder_sessions

    # ----------------------------------------------------------------- abort

    def _abort_initiator(self, peer: str) -> None:
        session = self._initiator_sessions.pop(peer, None)
        if session is not None:
            session.private_exponent = None  # clear usable state

    def _abort_responder(self, peer: str) -> None:
        session = self._responder_sessions.pop(peer, None)
        if session is not None:
            session.private_exponent = None

    def _debug(self, label: str, value: int) -> None:
        if self.debug:
            self.debug_values[label] = value

    # ------------------------------------------------- message 1: initiation

    def initiate(
        self,
        responder: str,
        bits: int = DEFAULT_PRIME_BITS,
        fixture: Optional[ClassroomFixture] = None,
    ) -> bytes:
        """Alice: generate p, g, a, A, nonce_A and send a signed init."""
        if responder == self.name or responder not in self.participant.trust_store:
            raise ValueError(f"{responder!r} is not a trusted peer")

        if fixture is not None:
            p = validate_received_modulus(fixture.p, allow_fixture=True)
            if not is_generator(fixture.g, p):
                raise ValueError("fixture g is not a generator")
            g = fixture.g
            self.last_parameters = None
            private, A = generate_dh_keypair(p, g, fixture.alice_exponent)
        else:
            params = generate_parameters(bits)
            self.last_parameters = params
            p, g = params.p, params.g
            private, A = generate_dh_keypair(p, g)

        nonce_A = secrets.token_bytes(NONCE_BYTES).hex()

        # Starting a new exchange replaces (and wipes) any older pending one.
        self._abort_initiator(responder)
        self._initiator_sessions[responder] = InitiatorSession(
            responder=responder, p=p, g=g, A=A, nonce_A=nonce_A, private_exponent=private
        )
        self._debug("a", private)

        payload = {
            "protocol": PROTOCOL_LABEL,
            "message_type": "init",
            "initiator": self.name,
            "responder": responder,
            "p": p,
            "g": g,
            "A": A,
            "nonce_A": nonce_A,
        }
        return build_envelope(payload, self.participant.sign(payload))

    def handle_init(
        self,
        raw: bytes,
        *,
        allow_fixture: bool = False,
        fixture_exponent: Optional[int] = None,
    ) -> bytes:
        """Bob: validate Alice's init, then reply with a signed response."""
        checks = self.last_checks = {"signature": NOT_CHECKED}
        try:
            # 1. Format, size limits, protocol, message type, expected identities.
            payload, signature = parse_envelope(raw)
            validate_init_payload(payload)
            if payload["responder"] != self.name:
                raise _SessionReject(f"init is addressed to {payload['responder']!r}, not {self.name!r}")
            initiator = payload["initiator"]

            # 2. Signature, using the TRUSTED key for the claimed initiator.
            try:
                self.participant.verify_from(initiator, payload, signature)
            except AuthenticationError:
                checks["signature"] = INVALID
                raise
            checks["signature"] = VALID

            # 3. Independently validate p (library), factor p - 1, verify g.
            p = validate_received_modulus(payload["p"], allow_fixture=allow_fixture)
            checks["modulus"] = "PASS"
            if not is_generator(payload["g"], p, prime_factors(p - 1)):
                raise ParameterError(f"g = {payload['g']} is not a generator mod p")
            checks["generator"] = "PASS"
            g = payload["g"]

            # 4. A must be in 2 .. p - 2.
            if not public_value_in_range(payload["A"], p):
                raise ParameterError("A is outside the permitted range 2 .. p - 2")
            checks["public_value"] = "PASS"
        except (MessageError, AuthenticationError, ParameterError, _SessionReject) as exc:
            # 5. Abort on any failure (no session has been created yet).
            raise ProtocolError(f"{self.name} rejected init: {exc}", _categorize(exc)) from exc

        private, B = generate_dh_keypair(p, g, fixture_exponent)
        nonce_B = secrets.token_bytes(NONCE_BYTES).hex()
        transcript = {
            "protocol": PROTOCOL_LABEL,
            "initiator": initiator,
            "responder": self.name,
            "p": p,
            "g": g,
            "A": payload["A"],
            "B": B,
            "nonce_A": payload["nonce_A"],
            "nonce_B": nonce_B,
        }
        # A replayed old init can provoke a new response, but that response has
        # a brand-new nonce_B, so only a finish signed over it can complete.
        self._abort_responder(initiator)
        self._responder_sessions[initiator] = ResponderSession(
            initiator=initiator, transcript=transcript, private_exponent=private
        )
        self._debug("b", private)

        response = {"message_type": "response", "transcript": transcript}
        return build_envelope(response, self.participant.sign(response))

    # -------------------------------------------------- message 2: response

    def handle_response(self, raw: bytes) -> Tuple[bytes, SessionResult]:
        """Alice: validate Bob's response, compute S_A, send a signed finish."""
        checks = self.last_checks = {"signature": NOT_CHECKED}
        session: Optional[InitiatorSession] = None
        try:
            # 1. Schema and expected identities.
            payload, signature = parse_envelope(raw)
            validate_confirmation_payload(payload, "response")
            t = payload["transcript"]
            if t["initiator"] != self.name:
                raise _SessionReject(f"response names initiator {t['initiator']!r}, not {self.name!r}")
            session = self._initiator_sessions.get(t["responder"])
            if session is None:
                raise _SessionReject(
                    f"unexpected response: no pending exchange with {t['responder']!r} "
                    "(out of order, stale, or already completed)"
                )

            # 2. p, g, A, nonce_A must match the pending session exactly.
            mine = (session.p, session.g, session.A, session.nonce_A)
            theirs = (t["p"], t["g"], t["A"], t["nonce_A"])
            if mine != theirs:
                raise _SessionReject("session fields differ from the pending session (stale or modified)")

            # 3. B in range.
            if not public_value_in_range(t["B"], session.p):
                raise ParameterError("B is outside the permitted range 2 .. p - 2")

            # 4. Bob's signature with Bob's TRUSTED key.
            try:
                self.participant.verify_from(session.responder, payload, signature)
            except AuthenticationError:
                checks["signature"] = INVALID
                raise
            checks["signature"] = VALID
        except (MessageError, AuthenticationError, ParameterError, _SessionReject) as exc:
            # 5. Abort on any failure; clear the session's private exponent.
            if session is not None:
                self._abort_initiator(session.responder)
            raise ProtocolError(f"{self.name} rejected response: {exc}", _categorize(exc)) from exc

        shared = compute_shared_secret(t["B"], session.private_exponent, session.p)
        self._debug("S_A", shared)
        self._abort_initiator(session.responder)  # exchange done; wipe a
        self._completed_nonces.add(session.nonce_A)

        finish = {"message_type": "finish", "transcript": t}
        result = SessionResult(role="initiator", peer=session.responder, transcript=t, shared_secret=shared)
        return build_envelope(finish, self.participant.sign(finish)), result

    # ---------------------------------------------------- message 3: finish

    def handle_finish(self, raw: bytes) -> SessionResult:
        """Bob: verify Alice's finish matches his pending transcript, then compute S_B."""
        checks = self.last_checks = {"signature": NOT_CHECKED}
        session: Optional[ResponderSession] = None
        try:
            payload, signature = parse_envelope(raw)
            validate_confirmation_payload(payload, "finish")
            t = payload["transcript"]
            if t["responder"] != self.name:
                raise _SessionReject(f"finish names responder {t['responder']!r}, not {self.name!r}")
            if t["nonce_B"] in self._completed_nonces:
                raise _SessionReject("duplicate finish: that session is already completed")
            session = self._responder_sessions.get(t["initiator"])
            if session is None:
                raise _SessionReject(
                    f"unexpected finish: no pending exchange with {t['initiator']!r} (out of order or stale)"
                )
            if t != session.transcript:
                raise _SessionReject("session fields differ from the pending transcript (stale or modified)")
            try:
                self.participant.verify_from(session.initiator, payload, signature)
            except AuthenticationError:
                checks["signature"] = INVALID
                raise
            checks["signature"] = VALID
        except (MessageError, AuthenticationError, ParameterError, _SessionReject) as exc:
            if session is not None:
                self._abort_responder(session.initiator)
            raise ProtocolError(f"{self.name} rejected finish: {exc}", _categorize(exc)) from exc

        t = session.transcript
        shared = compute_shared_secret(t["A"], session.private_exponent, t["p"])
        self._debug("S_B", shared)
        self._abort_responder(session.initiator)  # exchange done; wipe b
        self._completed_nonces.add(t["nonce_B"])
        return SessionResult(role="responder", peer=session.initiator, transcript=t, shared_secret=shared)


# ==========================================================================
# Coordinator: runs a whole exchange over a (possibly hostile) channel
# ==========================================================================

Channel = Callable[[str, bytes], bytes]  # (message label, raw bytes) -> raw bytes delivered


def _passthrough(label: str, raw: bytes) -> bytes:
    return raw


@dataclass
class ExchangeReport:
    requested_bits: Optional[int]
    p: Optional[int] = None
    g: Optional[int] = None
    parameters: Optional[DHParameters] = None
    modulus_validation: str = NOT_CHECKED
    generator_validation: str = NOT_CHECKED
    init_signature: str = NOT_CHECKED
    response_signature: str = NOT_CHECKED
    finish_signature: str = NOT_CHECKED
    authenticated: bool = False
    secrets_match: Optional[bool] = None
    error: Optional[str] = None
    alice_result: Optional[SessionResult] = None
    bob_result: Optional[SessionResult] = None
    total_seconds: float = 0.0


def run_authenticated_exchange(
    alice: Endpoint,
    bob: Endpoint,
    bits: int = DEFAULT_PRIME_BITS,
    *,
    fixture: Optional[ClassroomFixture] = None,
    channel: Channel = _passthrough,
) -> ExchangeReport:
    """Run init -> response -> finish. The channel may observe or tamper.

    The coordinator compares the two LOCAL secrets directly; raw secrets are
    never sent across the simulated network.
    """
    report = ExchangeReport(requested_bits=None if fixture else bits)
    start = time.perf_counter()
    try:
        init_raw = alice.initiate(bob.name, bits, fixture=fixture)
        report.parameters = alice.last_parameters
        report.p = fixture.p if fixture else alice.last_parameters.p
        report.g = fixture.g if fixture else alice.last_parameters.g

        try:
            response_raw = bob.handle_init(
                channel("init", init_raw),
                allow_fixture=fixture is not None,
                fixture_exponent=fixture.bob_exponent if fixture else None,
            )
        finally:
            report.init_signature = bob.last_checks.get("signature", NOT_CHECKED)
            report.modulus_validation = bob.last_checks.get("modulus", NOT_CHECKED)
            report.generator_validation = bob.last_checks.get("generator", NOT_CHECKED)

        try:
            finish_raw, report.alice_result = alice.handle_response(channel("response", response_raw))
        finally:
            report.response_signature = alice.last_checks.get("signature", NOT_CHECKED)

        try:
            report.bob_result = bob.handle_finish(channel("finish", finish_raw))
        finally:
            report.finish_signature = bob.last_checks.get("signature", NOT_CHECKED)

        report.authenticated = True
        report.secrets_match = report.alice_result.shared_secret == report.bob_result.shared_secret
    except ProtocolError as exc:
        report.error = str(exc)
    report.total_seconds = time.perf_counter() - start
    return report


# ==========================================================================
# Unauthenticated baseline (for the man-in-the-middle demonstration only)
# ==========================================================================

def unauthenticated_exchange(
    p: int, g: int, a: int, b: int, channel: Optional[Callable[[str, int], int]] = None
) -> Dict[str, int]:
    """Plain Diffie-Hellman with no signatures: public values travel unprotected."""
    channel = channel or (lambda label, value: value)
    A = modular_exponentiation(g, a, p)
    B = modular_exponentiation(g, b, p)
    A_at_bob = channel("A", A)
    B_at_alice = channel("B", B)
    return {
        "A": A,
        "B": B,
        "A_received_by_bob": A_at_bob,
        "B_received_by_alice": B_at_alice,
        "alice_secret": modular_exponentiation(B_at_alice, a, p),
        "bob_secret": modular_exponentiation(A_at_bob, b, p),
    }


def new_simulation(*, debug: bool = False) -> Tuple[Endpoint, Endpoint]:
    """Create Alice and Bob, run trusted setup, and return their endpoints."""
    from authentication import trusted_setup

    alice, bob = Participant("Alice"), Participant("Bob")
    trusted_setup([alice, bob])
    return Endpoint(alice, debug=debug), Endpoint(bob, debug=debug)
