"""Complete exchange tests: key agreement, authentication, attacks, session state."""

import json
import unittest

from authentication import AuthenticationError, TrustStore, trusted_setup
from eve import Eve, authenticated_substitution_demo, unauthenticated_mitm_demo
from messages import MAX_MESSAGE_BYTES, canonical_encode
from participant import Participant
from protocol import (
    INVALID,
    TEACHING_FIXTURE,
    VALID,
    Endpoint,
    ProtocolError,
    new_simulation,
    run_authenticated_exchange,
)

F = TEACHING_FIXTURE


def fixture_init(alice, bob):
    """Alice starts a fixture exchange; Bob answers. Returns (init, response)."""
    init = alice.initiate("Bob", fixture=F)
    response = bob.handle_init(init, allow_fixture=True, fixture_exponent=F.bob_exponent)
    return init, response


class TestKeyAgreement(unittest.TestCase):
    def test_fixed_p23_example(self):
        alice, bob = new_simulation()
        report = run_authenticated_exchange(alice, bob, fixture=F)
        self.assertIsNone(report.error)
        self.assertTrue(report.authenticated)
        t = report.alice_result.transcript
        self.assertEqual((t["p"], t["g"], t["A"], t["B"]), (23, 5, 8, 19))
        self.assertEqual(report.alice_result.shared_secret, 2)
        self.assertEqual(report.bob_result.shared_secret, 2)

    def test_several_generated_exchanges_each_size(self):
        alice, bob = new_simulation()  # identities reused across exchanges
        nonces = set()
        for bits in (16, 24, 32):
            for _ in range(3):
                report = run_authenticated_exchange(alice, bob, bits)
                with self.subTest(bits=bits, p=report.p):
                    self.assertIsNone(report.error)
                    self.assertTrue(report.authenticated)
                    self.assertTrue(report.secrets_match)
                    self.assertEqual(report.p.bit_length(), bits)
                    self.assertEqual(report.modulus_validation, "PASS")
                    self.assertEqual(report.generator_validation, "PASS")
                    self.assertEqual(
                        (report.init_signature, report.response_signature, report.finish_signature),
                        (VALID, VALID, VALID),
                    )
                    t = report.bob_result.transcript
                    nonces.update({t["nonce_A"], t["nonce_B"]})
        self.assertEqual(len(nonces), 18, "every exchange must use fresh nonces")

    def test_private_values_never_on_the_wire(self):
        eve = Eve()
        alice, bob = new_simulation(debug=True)
        report = run_authenticated_exchange(alice, bob, 32, channel=eve.tap())
        self.assertTrue(report.secrets_match)
        secret = report.alice_result.shared_secret
        private = {alice.debug_values["a"], bob.debug_values["b"], secret}

        def walk(node):
            if isinstance(node, dict):
                for key, value in node.items():
                    yield key
                    yield from walk(value)
            else:
                yield node

        sent = [m for msgs in eve.recorded.values() for m in msgs]
        self.assertEqual(len(sent), 3)
        for raw in sent:
            items = list(walk(json.loads(raw)))
            self.assertFalse(private & {v for v in items if type(v) is int})
            self.assertFalse({"a", "b", "secret", "shared_secret"} & {v for v in items if isinstance(v, str)})
        self.assertNotIn("shared_secret", repr(report.alice_result))

    def test_normal_run_rejects_p23(self):
        """p = 23 is only allowed through the explicit fixture path."""
        alice, bob = new_simulation()
        init = alice.initiate("Bob", fixture=F)
        with self.assertRaises(ProtocolError) as ctx:
            bob.handle_init(init)  # allow_fixture defaults to False
        self.assertEqual(ctx.exception.category, "parameters")


class TestAuthentication(unittest.TestCase):
    def setUp(self):
        self.alice, self.bob = new_simulation()
        self.eve = Eve()

    def run_with(self, label, transform, fixture=F):
        return run_authenticated_exchange(
            self.alice, self.bob, fixture=fixture, channel=Eve.channel_that(label, transform)
        )

    def assert_rejected(self, report):
        self.assertIsNotNone(report.error)
        self.assertFalse(report.authenticated)
        self.assertIsNone(report.bob_result)

    def test_valid_messages(self):
        report = run_authenticated_exchange(self.alice, self.bob, 16)
        self.assertTrue(report.authenticated and report.secrets_match)

    def test_wrong_trusted_key(self):
        """Bob trusts the wrong key for Alice, so her genuine signature fails."""
        alice, bob, imposter = Participant("Alice"), Participant("Bob"), Participant("Alice")
        alice.install_trust_store(TrustStore({"Bob": bob.verification_key}))
        bob.install_trust_store(TrustStore({"Alice": imposter.verification_key}))
        report = run_authenticated_exchange(Endpoint(alice), Endpoint(bob), fixture=F)
        self.assertEqual(report.init_signature, INVALID)
        self.assertFalse(report.authenticated)

    def test_untrusted_identity_has_no_key(self):
        store = TrustStore({})
        with self.assertRaises(AuthenticationError):
            store.key_for("Alice")

    def test_trusted_setup_cannot_be_replaced(self):
        with self.assertRaises(RuntimeError):
            self.alice.participant.install_trust_store(TrustStore({}))

    # --- attack table -----------------------------------------------------

    def test_modify_A_without_resigning(self):
        report = self.run_with("init", lambda r: Eve.modify_field(r, ("A",), 10))
        self.assertEqual(report.init_signature, INVALID)
        self.assert_rejected(report)

    def test_modify_B_without_resigning(self):
        report, E1 = authenticated_substitution_demo(self.alice, self.bob)
        self.assertEqual(E1, 10)
        self.assertEqual(report.init_signature, VALID)
        self.assertEqual(report.response_signature, INVALID)
        self.assert_rejected(report)
        self.assertFalse(self.alice.has_pending_session("Bob"))  # session aborted

    def test_modify_B_19_to_17(self):
        report = self.run_with("response", lambda r: Eve.modify_field(r, ("transcript", "B"), 17))
        self.assertEqual(report.response_signature, INVALID)
        self.assert_rejected(report)

    def test_modify_p_or_g(self):
        # Changing p to another prime or g to another generator: signature fails.
        for path, value in ((("p",), 29), (("g",), 7)):
            with self.subTest(path=path):
                alice, bob = new_simulation()
                report = run_authenticated_exchange(
                    alice, bob, fixture=F,
                    channel=Eve.channel_that("init", lambda r: Eve.modify_field(r, path, value)))
                self.assertEqual(report.init_signature, INVALID)
                self.assertFalse(report.authenticated)
        # Changing p/g inside Bob's response: Alice sees fields differ from her session.
        for field, value in (("p", 29), ("g", 7)):
            with self.subTest(field=field):
                alice, bob = new_simulation()
                report = run_authenticated_exchange(
                    alice, bob, fixture=F,
                    channel=Eve.channel_that("response",
                                             lambda r: Eve.modify_field(r, ("transcript", field), value)))
                self.assertIn("session fields differ", report.error)
                self.assertFalse(alice.has_pending_session("Bob"))

    def test_modify_identity_labels(self):
        cases = [("init", ("initiator",), "Bob"),
                 ("init", ("responder",), "Alice"),
                 ("response", ("transcript", "initiator"), "Bob"),
                 ("response", ("transcript", "responder"), "Alice"),
                 ("finish", ("transcript", "responder"), "Alice")]
        for label, path, value in cases:
            with self.subTest(label=label, path=path):
                alice, bob = new_simulation()
                report = run_authenticated_exchange(
                    alice, bob, fixture=F,
                    channel=Eve.channel_that(label, lambda r: Eve.modify_field(r, path, value)))
                self.assertFalse(report.authenticated)
                self.assertIsNone(report.bob_result)

    def test_corrupt_signature_each_message(self):
        for label in ("init", "response", "finish"):
            with self.subTest(label=label):
                alice, bob = new_simulation()
                report = run_authenticated_exchange(
                    alice, bob, fixture=F, channel=Eve.channel_that(label, Eve.corrupt_signature))
                self.assertFalse(report.authenticated)
                self.assertIsNone(report.bob_result)
                field = {"init": "init_signature", "response": "response_signature",
                         "finish": "finish_signature"}[label]
                self.assertEqual(getattr(report, field), INVALID)

    def test_sign_as_alice_using_eves_key(self):
        report = self.run_with("init", lambda r: self.eve.resign(r, ("A",), 10))
        self.assertEqual(report.init_signature, INVALID)
        self.assert_rejected(report)

    def test_eve_resigns_unmodified_finish(self):
        report = self.run_with("finish", lambda r: self.eve.resign(r))
        self.assertEqual(report.finish_signature, INVALID)
        self.assert_rejected(report)

    def test_unauthenticated_mitm_succeeds(self):
        r = unauthenticated_mitm_demo()
        self.assertEqual((r["A"], r["B"], r["E1"], r["E2"]), (8, 19, 10, 17))
        self.assertEqual((r["alice_secret"], r["eve_secret_with_alice"]), (6, 6))
        self.assertEqual((r["bob_secret"], r["eve_secret_with_bob"]), (15, 15))
        self.assertNotEqual(r["alice_secret"], r["bob_secret"])


class TestSessionState(unittest.TestCase):
    def setUp(self):
        self.alice, self.bob = new_simulation()

    def test_fresh_nonces_each_exchange(self):
        a1 = json.loads(self.alice.initiate("Bob", fixture=F))["payload"]["nonce_A"]
        a2 = json.loads(self.alice.initiate("Bob", fixture=F))["payload"]["nonce_A"]
        self.assertNotEqual(a1, a2)
        self.assertEqual(len(a1), 64)

    def test_replay_old_response_into_fresh_alice_session(self):
        _, old_response = fixture_init(self.alice, self.bob)
        self.alice.initiate("Bob", fixture=F)  # fresh session, new nonce_A
        with self.assertRaises(ProtocolError) as ctx:
            self.alice.handle_response(old_response)
        self.assertIn("session fields differ", str(ctx.exception))
        self.assertFalse(self.alice.has_pending_session("Bob"))  # aborted and cleared

    def test_replay_old_finish_into_fresh_bob_session(self):
        _, response = fixture_init(self.alice, self.bob)
        old_finish, _ = self.alice.handle_response(response)
        # Bob does NOT get the finish; Alice starts over and Bob opens a new session.
        fixture_init(self.alice, self.bob)
        with self.assertRaises(ProtocolError) as ctx:
            self.bob.handle_finish(old_finish)
        self.assertIn("session fields differ", str(ctx.exception))
        self.assertFalse(self.bob.has_pending_session("Alice"))

    def test_replayed_init_gets_new_nonce_and_cannot_complete_with_old_finish(self):
        init, response1 = fixture_init(self.alice, self.bob)
        finish1, _ = self.alice.handle_response(response1)
        self.bob.handle_finish(finish1)                       # first exchange completes
        # Eve replays the old init. Bob (no init cache) answers with a NEW nonce_B...
        response2 = self.bob.handle_init(init, allow_fixture=True, fixture_exponent=15)
        nb1 = json.loads(response1)["payload"]["transcript"]["nonce_B"]
        nb2 = json.loads(response2)["payload"]["transcript"]["nonce_B"]
        self.assertNotEqual(nb1, nb2)
        # ...but the old finish is bound to the OLD nonce_B, so it is rejected,
        with self.assertRaises(ProtocolError):
            self.bob.handle_finish(finish1)
        # and Alice has no pending session, so Bob's new response is also rejected.
        with self.assertRaises(ProtocolError):
            self.alice.handle_response(response2)

    def test_duplicate_finish_after_completion(self):
        _, response = fixture_init(self.alice, self.bob)
        finish, _ = self.alice.handle_response(response)
        result = self.bob.handle_finish(finish)
        self.assertTrue(result.authenticated)
        with self.assertRaises(ProtocolError) as ctx:
            self.bob.handle_finish(finish)
        self.assertIn("already completed", str(ctx.exception))

    def test_duplicate_response_after_completion(self):
        _, response = fixture_init(self.alice, self.bob)
        self.alice.handle_response(response)
        with self.assertRaises(ProtocolError):
            self.alice.handle_response(response)

    def test_wrong_message_order(self):
        # finish before any init
        _, response = fixture_init(self.alice, self.bob)
        finish, _ = self.alice.handle_response(response)
        fresh_alice, fresh_bob = new_simulation()
        with self.assertRaises(ProtocolError):
            fresh_bob.handle_finish(finish)
        # response with no pending initiation
        with self.assertRaises(ProtocolError):
            fresh_alice.handle_response(response)
        # message types delivered to the wrong handler
        init = self.alice.initiate("Bob", fixture=F)
        with self.assertRaises(ProtocolError):
            self.alice.handle_response(init)
        with self.assertRaises(ProtocolError):
            self.bob.handle_finish(init)
        response = self.bob.handle_init(init, allow_fixture=True)
        with self.assertRaises(ProtocolError):
            self.bob.handle_init(response, allow_fixture=True)
        with self.assertRaises(ProtocolError):
            self.bob.handle_finish(response)

    def test_malformed_and_oversized_messages(self):
        for bad in (b"", b"garbage", b"{}", b"[]", b'{"payload":{},"signature":"00"}',
                    b"x" * (MAX_MESSAGE_BYTES + 1)):
            with self.subTest(raw=bad[:20]):
                with self.assertRaises(ProtocolError) as ctx:
                    self.bob.handle_init(bad, allow_fixture=True)
                self.assertEqual(ctx.exception.category, "format")

    def test_duplicate_json_key_attack(self):
        init = self.alice.initiate("Bob", fixture=F)
        text = init.decode()
        smuggled = text.replace('"A":8', '"A":8,"A":10', 1).encode()
        with self.assertRaises(ProtocolError) as ctx:
            self.bob.handle_init(smuggled, allow_fixture=True)
        self.assertEqual(ctx.exception.category, "format")

    def test_rejection_clears_private_state(self):
        _, response = fixture_init(self.alice, self.bob)
        session = self.alice._initiator_sessions["Bob"]
        tampered = Eve.corrupt_signature(response)
        with self.assertRaises(ProtocolError):
            self.alice.handle_response(tampered)
        self.assertIsNone(session.private_exponent)
        # The genuine response can no longer complete the aborted session.
        with self.assertRaises(ProtocolError):
            self.alice.handle_response(response)

    def test_bob_does_not_complete_before_finish(self):
        alice, bob = new_simulation(debug=True)
        _, response = fixture_init(alice, bob)
        self.assertTrue(bob.has_pending_session("Alice"))
        self.assertNotIn("S_B", bob.debug_values)       # Bob has not computed S_B yet
        finish, _ = alice.handle_response(response)
        bob.handle_finish(finish)
        self.assertEqual(bob.debug_values["S_B"], 2)    # only after accepting the finish

    def test_composite_modulus_in_signed_init_rejected(self):
        """Even a validly signed init with composite p is rejected by Bob."""
        a, b = Participant("Alice"), Participant("Bob")
        trusted_setup([a, b])
        payload = {"protocol": "DH-CLASSROOM-AUTH-v1", "message_type": "init",
                   "initiator": "Alice", "responder": "Bob", "p": 32769, "g": 5,
                   "A": 8, "nonce_A": "00" * 32}
        raw = canonical_encode({"payload": payload, "signature": a.sign(payload).hex()})
        with self.assertRaises(ProtocolError) as ctx:
            Endpoint(b).handle_init(raw)
        self.assertEqual(ctx.exception.category, "parameters")

    def test_signed_init_with_non_generator_rejected(self):
        a, b = Participant("Alice"), Participant("Bob")
        trusted_setup([a, b])
        payload = {"protocol": "DH-CLASSROOM-AUTH-v1", "message_type": "init",
                   "initiator": "Alice", "responder": "Bob", "p": 23, "g": 2,
                   "A": 8, "nonce_A": "00" * 32}
        raw = canonical_encode({"payload": payload, "signature": a.sign(payload).hex()})
        with self.assertRaises(ProtocolError) as ctx:
            Endpoint(b).handle_init(raw, allow_fixture=True)
        self.assertIn("not a generator", str(ctx.exception))

    def test_signed_init_with_out_of_range_A_rejected(self):
        a, b = Participant("Alice"), Participant("Bob")
        trusted_setup([a, b])
        for bad_A in (0, 1, 22):
            payload = {"protocol": "DH-CLASSROOM-AUTH-v1", "message_type": "init",
                       "initiator": "Alice", "responder": "Bob", "p": 23, "g": 5,
                       "A": bad_A, "nonce_A": "00" * 32}
            raw = canonical_encode({"payload": payload, "signature": a.sign(payload).hex()})
            with self.subTest(A=bad_A), self.assertRaises(ProtocolError):
                Endpoint(b).handle_init(raw, allow_fixture=True)


if __name__ == "__main__":
    unittest.main()
