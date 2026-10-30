"""Message validation tests: encoding, strict parsing, schemas, types, sizes."""

import json
import secrets
import unittest

from messages import (
    MAX_MESSAGE_BYTES,
    PROTOCOL_LABEL,
    MessageError,
    build_envelope,
    canonical_encode,
    parse_envelope,
    parse_json_strict,
    validate_confirmation_payload,
    validate_init_payload,
    validate_transcript,
)

NONCE = "ab" * 32
SIG = "cd" * 64


def init_payload(**overrides):
    payload = {"protocol": PROTOCOL_LABEL, "message_type": "init", "initiator": "Alice",
               "responder": "Bob", "p": 23, "g": 5, "A": 8, "nonce_A": NONCE}
    payload.update(overrides)
    return payload


def transcript(**overrides):
    t = {"protocol": PROTOCOL_LABEL, "initiator": "Alice", "responder": "Bob", "p": 23,
         "g": 5, "A": 8, "B": 19, "nonce_A": NONCE, "nonce_B": "ef" * 32}
    t.update(overrides)
    return t


class TestEncoding(unittest.TestCase):
    def test_deterministic_sorted_compact(self):
        self.assertEqual(canonical_encode({"p": 23, "g": 5, "A": 8}), b'{"A":8,"g":5,"p":23}')

    def test_key_order_does_not_matter(self):
        self.assertEqual(canonical_encode({"a": 1, "b": 2}), canonical_encode({"b": 2, "a": 1}))

    def test_envelope_roundtrip(self):
        sig = secrets.token_bytes(64)
        payload, parsed_sig = parse_envelope(build_envelope(init_payload(), sig))
        self.assertEqual(payload, init_payload())
        self.assertEqual(parsed_sig, sig)


class TestStrictParsing(unittest.TestCase):
    def test_rejects_duplicate_keys(self):
        with self.assertRaises(MessageError):
            parse_json_strict(b'{"p":23,"p":29}')

    def test_rejects_oversized(self):
        raw = b'{"x":"' + b"a" * MAX_MESSAGE_BYTES + b'"}'
        with self.assertRaises(MessageError):
            parse_json_strict(raw)

    def test_rejects_malformed_json(self):
        for raw in (b"", b"{", b"not json", b'{"a":1,}', b"[1,2]", b'"str"'):
            with self.subTest(raw=raw), self.assertRaises(MessageError):
                parse_json_strict(raw)

    def test_rejects_non_utf8_and_non_bytes(self):
        with self.assertRaises(MessageError):
            parse_json_strict(b'{"a":"\xff"}')
        with self.assertRaises(MessageError):
            parse_json_strict('{"a":1}')  # str, not bytes

    def test_rejects_floats_and_constants(self):
        for raw in (b'{"p":23.0}', b'{"p":2.3e1}', b'{"p":NaN}', b'{"p":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(MessageError):
                parse_json_strict(raw)

    def test_envelope_shape(self):
        good_payload = init_payload()
        for env in ({"payload": good_payload},
                    {"payload": good_payload, "signature": SIG, "extra": 1},
                    {"payload": good_payload, "signature": SIG[:-2]},
                    {"payload": good_payload, "signature": SIG.upper()},
                    {"payload": good_payload, "signature": 12345},
                    {"payload": [1, 2], "signature": SIG}):
            with self.subTest(env=env), self.assertRaises(MessageError):
                parse_envelope(json.dumps(env).encode())


class TestInitSchema(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(validate_init_payload(init_payload()), init_payload())

    def test_unexpected_and_missing_fields(self):
        with self.assertRaises(MessageError):
            validate_init_payload(init_payload(extra="x"))
        p = init_payload()
        del p["nonce_A"]
        with self.assertRaises(MessageError):
            validate_init_payload(p)

    def test_no_string_to_int_coercion(self):
        for field in ("p", "g", "A"):
            with self.subTest(field=field), self.assertRaises(MessageError):
                validate_init_payload(init_payload(**{field: "23"}))

    def test_wrong_types(self):
        for field, bad in (("p", True), ("g", None), ("A", [8]), ("A", 8.0),
                           ("initiator", 1), ("nonce_A", 123), ("protocol", None)):
            with self.subTest(field=field, bad=bad), self.assertRaises(MessageError):
                validate_init_payload(init_payload(**{field: bad}))

    def test_integer_size_bounds(self):
        for bad in (-1, 2 ** 32, 2 ** 200):
            with self.subTest(p=bad), self.assertRaises(MessageError):
                validate_init_payload(init_payload(p=bad))

    def test_wrong_protocol_and_type(self):
        with self.assertRaises(MessageError):
            validate_init_payload(init_payload(protocol="DH-CLASSROOM-AUTH-v2"))
        with self.assertRaises(MessageError):
            validate_init_payload(init_payload(message_type="response"))

    def test_identity_labels(self):
        for bad in ("Eve", "alice", "Alice ", ""):
            with self.subTest(label=bad), self.assertRaises(MessageError):
                validate_init_payload(init_payload(initiator=bad))
        with self.assertRaises(MessageError):
            validate_init_payload(init_payload(initiator="Bob"))  # same as responder

    def test_malformed_nonces(self):
        for bad in ("ab" * 31, "ab" * 33, "AB" * 32, "zz" * 32, "ab" * 32 + "\n", ""):
            with self.subTest(nonce=bad), self.assertRaises(MessageError):
                validate_init_payload(init_payload(nonce_A=bad))


class TestConfirmationSchema(unittest.TestCase):
    def test_valid_response_and_finish(self):
        for kind in ("response", "finish"):
            payload = {"message_type": kind, "transcript": transcript()}
            self.assertEqual(validate_confirmation_payload(payload, kind), payload)

    def test_wrong_message_type(self):
        payload = {"message_type": "finish", "transcript": transcript()}
        with self.assertRaises(MessageError):
            validate_confirmation_payload(payload, "response")

    def test_transcript_strictness(self):
        with self.assertRaises(MessageError):
            validate_transcript(transcript(B="19"))
        with self.assertRaises(MessageError):
            validate_transcript(transcript(extra=1))
        with self.assertRaises(MessageError):
            validate_transcript(transcript(nonce_B="xyz"))
        t = transcript()
        del t["B"]
        with self.assertRaises(MessageError):
            validate_transcript(t)

    def test_extra_top_level_field(self):
        payload = {"message_type": "response", "transcript": transcript(), "note": "hi"}
        with self.assertRaises(MessageError):
            validate_confirmation_payload(payload, "response")


if __name__ == "__main__":
    unittest.main()
