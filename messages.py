"""Wire format: deterministic JSON encoding and strict message validation.

Every message on the simulated network is an envelope:

    {"payload": {...signed fields...}, "signature": "<128 hex chars>"}

The signature sits outside the payload and covers the canonical encoding of
the payload. Parsing is strict: size limit, UTF-8, no duplicate keys, no
floats, exact field sets, exact types, and no string-to-integer coercion.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Tuple

PROTOCOL_LABEL = "DH-CLASSROOM-AUTH-v1"
MAX_MESSAGE_BYTES = 4096
IDENTITY_LABELS = frozenset({"Alice", "Bob"})
NONCE_BYTES = 32
MAX_NUMERIC_BITS = 32  # p, g, A, B can never legitimately exceed 32 bits

_NONCE_PATTERN = re.compile(r"[0-9a-f]{64}")       # 32 bytes as lowercase hex
_SIGNATURE_PATTERN = re.compile(r"[0-9a-f]{128}")  # 64-byte Ed25519 signature

ENVELOPE_FIELDS = frozenset({"payload", "signature"})
INIT_FIELDS = frozenset(
    {"protocol", "message_type", "initiator", "responder", "p", "g", "A", "nonce_A"}
)
TRANSCRIPT_FIELDS = frozenset(
    {"protocol", "initiator", "responder", "p", "g", "A", "B", "nonce_A", "nonce_B"}
)
CONFIRMATION_FIELDS = frozenset({"message_type", "transcript"})


class MessageError(ValueError):
    """Raised for malformed, oversized, or schema-violating messages."""


# --------------------------------------------------------------------------
# Encoding
# --------------------------------------------------------------------------

def canonical_encode(obj: Any) -> bytes:
    """Deterministic JSON: sorted keys, no whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_envelope(payload: Dict[str, Any], signature: bytes) -> bytes:
    """Wrap a payload and its detached signature for the simulated network."""
    raw = canonical_encode({"payload": payload, "signature": signature.hex()})
    if len(raw) > MAX_MESSAGE_BYTES:
        raise MessageError("outgoing message exceeds the maximum size")
    return raw


# --------------------------------------------------------------------------
# Strict parsing
# --------------------------------------------------------------------------

def _reject_duplicate_keys(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise MessageError(f"duplicate JSON key {key!r}")
        obj[key] = value
    return obj


def _reject_float(text: str):
    raise MessageError(f"non-integer number {text!r} is not allowed")


def _reject_constant(text: str):
    raise MessageError(f"JSON constant {text!r} is not allowed")


def parse_json_strict(raw: object) -> Dict[str, Any]:
    """Parse bytes into a dict, enforcing size and strict JSON rules."""
    if not isinstance(raw, (bytes, bytearray)):
        raise MessageError("message must be bytes")
    if len(raw) > MAX_MESSAGE_BYTES:
        raise MessageError(f"message is {len(raw)} bytes; maximum is {MAX_MESSAGE_BYTES}")
    try:
        text = bytes(raw).decode("utf-8")
    except UnicodeDecodeError:
        raise MessageError("message is not valid UTF-8") from None
    try:
        obj = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except MessageError:
        raise
    except (ValueError, RecursionError) as exc:
        raise MessageError(f"malformed JSON: {exc}") from None
    if not isinstance(obj, dict):
        raise MessageError("message must be a JSON object")
    return obj


def parse_envelope(raw: object) -> Tuple[Dict[str, Any], bytes]:
    """Split a raw message into (payload, signature bytes)."""
    envelope = parse_json_strict(raw)
    require_exact_fields(envelope, ENVELOPE_FIELDS, "envelope")
    signature = envelope["signature"]
    if not isinstance(signature, str) or not _SIGNATURE_PATTERN.fullmatch(signature):
        raise MessageError("signature must be 128 lowercase hexadecimal characters")
    payload = envelope["payload"]
    if not isinstance(payload, dict):
        raise MessageError("payload must be a JSON object")
    return payload, bytes.fromhex(signature)


# --------------------------------------------------------------------------
# Field validators (no coercion: "23" is a string, not an integer)
# --------------------------------------------------------------------------

def require_exact_fields(obj: object, expected: frozenset, what: str) -> None:
    if not isinstance(obj, dict):
        raise MessageError(f"{what} must be a JSON object")
    keys = set(obj)
    missing = expected - keys
    extra = keys - expected
    if missing:
        raise MessageError(f"{what} is missing field(s): {sorted(missing)}")
    if extra:
        raise MessageError(f"{what} has unexpected field(s): {sorted(extra)}")


def _require_int(obj: Dict[str, Any], field: str) -> int:
    value = obj[field]
    if type(value) is not int:  # rejects bool, float, str, None, ...
        raise MessageError(f"field {field!r} must be an integer, got {type(value).__name__}")
    # Integer-size bound enforced before any expensive arithmetic.
    if value < 0 or value.bit_length() > MAX_NUMERIC_BITS:
        raise MessageError(f"field {field!r} is outside the permitted integer bounds")
    return value


def _require_identity(obj: Dict[str, Any], field: str) -> str:
    value = obj[field]
    if not isinstance(value, str) or value not in IDENTITY_LABELS:
        raise MessageError(f"field {field!r} must be one of {sorted(IDENTITY_LABELS)}")
    return value


def _require_nonce(obj: Dict[str, Any], field: str) -> str:
    value = obj[field]
    if not isinstance(value, str) or not _NONCE_PATTERN.fullmatch(value):
        raise MessageError(f"field {field!r} must be 64 lowercase hexadecimal characters")
    return value


def _require_literal(obj: Dict[str, Any], field: str, expected: str) -> str:
    value = obj[field]
    if not isinstance(value, str) or value != expected:
        raise MessageError(f"field {field!r} must be {expected!r}")
    return value


def _require_distinct_identities(obj: Dict[str, Any]) -> None:
    if obj["initiator"] == obj["responder"]:
        raise MessageError("initiator and responder must be different identities")


# --------------------------------------------------------------------------
# Schemas
# --------------------------------------------------------------------------

def validate_init_payload(payload: object) -> Dict[str, Any]:
    """Message 1 schema: protocol, message_type="init", identities, p, g, A, nonce_A."""
    require_exact_fields(payload, INIT_FIELDS, "init payload")
    _require_literal(payload, "protocol", PROTOCOL_LABEL)
    _require_literal(payload, "message_type", "init")
    _require_identity(payload, "initiator")
    _require_identity(payload, "responder")
    _require_distinct_identities(payload)
    for field in ("p", "g", "A"):
        _require_int(payload, field)
    _require_nonce(payload, "nonce_A")
    return payload


def validate_transcript(transcript: object) -> Dict[str, Any]:
    """Complete transcript: protocol, identities, p, g, A, B, nonce_A, nonce_B."""
    require_exact_fields(transcript, TRANSCRIPT_FIELDS, "transcript")
    _require_literal(transcript, "protocol", PROTOCOL_LABEL)
    _require_identity(transcript, "initiator")
    _require_identity(transcript, "responder")
    _require_distinct_identities(transcript)
    for field in ("p", "g", "A", "B"):
        _require_int(transcript, field)
    _require_nonce(transcript, "nonce_A")
    _require_nonce(transcript, "nonce_B")
    return transcript


def validate_confirmation_payload(payload: object, expected_type: str) -> Dict[str, Any]:
    """Messages 2 and 3 schema: message_type plus the complete transcript."""
    if expected_type not in ("response", "finish"):
        raise ValueError("expected_type must be 'response' or 'finish'")
    require_exact_fields(payload, CONFIRMATION_FIELDS, f"{expected_type} payload")
    _require_literal(payload, "message_type", expected_type)
    validate_transcript(payload["transcript"])
    return payload
