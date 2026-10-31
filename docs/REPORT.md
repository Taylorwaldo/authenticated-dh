# Authenticated Diffie-Hellman: Project Report

## 1. Overview

This project simulates an authenticated finite-field Diffie-Hellman (DH) exchange between Alice and Bob. Alice generates public parameters (a prime p from a library and a generator g found by hand), and both sides exchange public values inside a three-message protocol whose transcript is signed with long-term Ed25519 identity keys. An attacker, Eve, controls the simulated network. The program shows that Eve can silently split an unauthenticated exchange and that the same substitution is detected and rejected once signatures and trusted keys are added.

## 2. Algorithms

### 2.1 Square-and-multiply (`modular_math.py`)

`modular_exponentiation(base, exponent, modulus)` computes base^exponent mod modulus without forming the full power. It rejects non-integers (including `bool`), negative exponents, and non-positive moduli. The loop reads the exponent one bit at a time from the lowest bit: if the bit is 1 the current power is multiplied into the result, the base is squared to give the next power-of-two power, and the exponent is halved. Every product is reduced mod modulus immediately, so intermediate values stay below modulus^2. For exponent e the loop runs about log2(e) times, which is O(log e) modular operations.

### 2.2 Library prime generation (`parameters.generate_prime`)

The wrapper validates that the requested size is an integer from 16 through 32 (booleans and non-integers rejected), calls `Crypto.Util.number.getPrime(bits, randfunc=secrets.token_bytes)`, then confirms `p.bit_length() == bits` and that p is odd. The total wrapper time is measured with `time.perf_counter()`. For k bits, every accepted p satisfies 2^(k-1) <= p < 2^k.

### 2.3 Received-modulus validation (`parameters.validate_received_modulus`)

Bob does not trust Alice's p. He checks, in order: the type is a real integer, the size is 16 to 32 bits, and the library's `isPrime(p)` returns True. Size is checked before any expensive work. A separate, explicit fixture path (`allow_fixture=True`) is the only way small values such as p = 23 are accepted; it still runs the library primality check, so composite fixtures like 21 are rejected.

### 2.4 Factorization of p - 1 (`parameters.prime_factors`)

Trial division: divide out all 2s (record 2 once), then try odd divisors from 3, dividing out each one completely and recording it once, stopping when divisor^2 exceeds what remains. Any remainder greater than 1 is a prime factor. The function returns the set of distinct prime factors; `prime_factors(1)` is the empty set. For a 32-bit p, at most about 2^16 / 2 = 32,768 odd divisors are tried.

### 2.5 Generator verification and search (`parameters.is_generator`, `find_generator`)

For prime p the multiplicative group has order p - 1. A candidate g in 2 .. p - 2 is a primitive generator exactly when g^((p - 1)/r) mod p != 1 for every distinct prime factor r of p - 1. If any test equals 1, the order of g is a proper divisor of p - 1 and g is rejected. The full factor set must be used; a partial set can accept a non-generator (see the test `test_incomplete_factor_set_is_wrong`). `find_generator` returns the smallest passing candidate.

### 2.6 Diffie-Hellman keys and secrets (`participant.py`)

Each exchange uses a fresh private exponent `secrets.randbelow(p - 3) + 2`, so 2 <= x <= p - 2. The public value g^x mod p is computed with square-and-multiply; if it falls outside 2 .. p - 2 a new exponent is drawn. The shared secret is S_A = B^a mod p for Alice and S_B = A^b mod p for Bob. Received public values must also satisfy 2 <= value <= p - 2.

### 2.7 Messages and signatures (`messages.py`, `authentication.py`)

Every message is an envelope `{"payload": {...}, "signature": "<128 hex chars>"}`. The signature is outside the payload and covers the deterministic encoding `json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")`. Parsing is strict: 4096-byte limit, UTF-8 only, duplicate keys rejected, floats and NaN/Infinity rejected, exact field sets, exact types with no string-to-integer coercion, identity labels limited to "Alice" and "Bob", nonces exactly 64 lowercase hex characters, and every integer bounded to 32 bits before arithmetic. Signatures are verified with `Ed25519PublicKey.verify`, which returns nothing on success and raises `InvalidSignature` on failure; the exception aborts the exchange.

### 2.8 Protocol and session state (`protocol.py`)

1. **init** (Alice signs): protocol, "init", initiator, responder, p, g, A, nonce_A. Bob checks format and identities, verifies Alice's signature with her trusted key, validates p with the library, factors p - 1, verifies g, and range-checks A.
2. **response** (Bob signs): "response" plus the complete transcript {protocol, initiator, responder, p, g, A, B, nonce_A, nonce_B}. Alice checks the schema and identities, confirms p, g, A, nonce_A equal her pending session exactly, range-checks B, and verifies Bob's signature with his trusted key. She then computes S_A.
3. **finish** (Alice signs): "finish" plus the same transcript. Bob requires exact equality with his stored transcript and verifies Alice's signature. Only then does he compute S_B and mark the session complete.

Each endpoint keeps one pending session per peer per role. Any rejection aborts the affected session, sets its private exponent to `None`, and its secret is never computed or used. Completed responder nonces are remembered so a duplicate finish is rejected.

**Replayed initiations.** Bob does not cache old initiations, so a replayed init does provoke a new response. That response carries a brand-new nonce_B, and Bob will only complete if he receives a finish signed by Alice over a transcript containing that new nonce. Eve cannot produce that signature, and Alice has no matching pending session to create it, so a replayed init can make Bob do work but can never complete a fresh exchange (`test_replayed_init_gets_new_nonce_and_cannot_complete_with_old_finish`).

## 3. Worked examples (p = 23 teaching fixture)

**Square-and-multiply, 5^6 mod 23**

| Iteration | Exponent before | Base before | Result after odd check | Squared base mod 23 | Next exponent |
|---:|---:|---:|---:|---:|---:|
| 1 | 6 | 5 | 1 | 2 | 3 |
| 2 | 3 | 2 | 2 | 4 | 1 |
| 3 | 1 | 4 | 8 | 16 | 0 |

Answer: 8. Boundary cases: (5, 0, 23) -> 1, (5, 0, 1) -> 0, (5, -1, 23) and (5, 6, 0) are rejected.

**Factorization and generator**

- p = 23: p - 1 = 22 = 2 * 11, factors {2, 11}. g = 2: 2^11 mod 23 = 1, reject. g = 5: 5^11 mod 23 = 22 and 5^2 mod 23 = 2, accept.
- p = 65537: p - 1 = 2^16, factors {2}. g = 3: 3^32768 mod 65537 = 65536, accept.

**Key agreement:** a = 6, b = 15 gives A = 5^6 mod 23 = 8 and B = 5^15 mod 23 = 19. Alice computes 19^6 mod 23 = 2 and Bob computes 8^15 mod 23 = 2.

**Eve against unauthenticated DH:** Eve picks e1 = 3 (E1 = 10) and e2 = 7 (E2 = 17), sending E1 to Alice and E2 to Bob. Alice gets 10^6 mod 23 = 6 and Eve gets 8^3 mod 23 = 6; Bob gets 17^15 mod 23 = 15 and Eve gets 19^7 mod 23 = 15. Alice and Bob hold different secrets and Eve knows both, with nothing detected.

**Eve against the authenticated protocol:** Eve replaces B with 10 in Bob's response but cannot re-sign it as Bob. Alice reports `Bob response signature: INVALID`, aborts, and clears her session. Re-signing with Eve's own key fails because Alice verifies against Bob's pre-configured key.

## 4. Test results

`python -m unittest -v` runs 90 tests, all passing (full log in `test_results.txt`).

| Component | Coverage |
|---|---|
| Exponentiation | Known result 5^6 mod 23 = 8; exponent zero; modulus one; negative base; invalid types and values; 500 random comparisons with `pow` |
| Library prime generation | Exact bit length, oddness, and `isPrime` for every size 16 to 32; invalid sizes including `True`, `False`, `16.0`, `"16"` |
| Received modulus validation | Rejects composite 32769, wrong types, out-of-range sizes (including a 61-bit prime); fixture path accepts 23 and rejects 21 |
| Factorization | 1, 22, 65536, and other values |
| Generator | Accepts 5 and rejects 2 for p = 23; accepts 3 for p = 65537; brute-force order check |
| Key agreement | Fixed p = 23 example; 3 generated exchanges at each of 16, 24, 32 bits with fresh nonces |
| Authentication | Valid messages; wrong trusted key; every row of the attack table |
| Session state | Fresh nonces; stale responses; stale finishes; replayed init; duplicate completion; wrong message order; cleared state after rejection |

Attack table results: modifying A or B without re-signing, modifying p or g, modifying identity labels, corrupting any signature, signing as Alice with Eve's key, replaying an old response into a fresh Alice session, replaying an old finish into a fresh Bob session, a duplicate finish after completion, and malformed, oversized, or out-of-order messages are all rejected.

## 5. Performance

`python main.py benchmark` runs three exchanges at each of 16, 24, and 32 bits and records prime-generation, factorization, and generator-search time plus the authentication outcome; results and the environment are in `performance.md`. In the recorded run every step finished in under a millisecond, and run-to-run variation is dominated by the library's random prime search, since the number of candidates it tests before finding a prime varies. Factorization time depends on the shape of p - 1: when p - 1 has only small factors it finishes almost immediately, while the worst case (p - 1 = 2q with q prime) needs the full ~2^(k/2 - 1) odd trial divisors. No exact runtime is asserted in the tests.

## 6. Trust assumptions

- Each participant's Ed25519 public key is delivered authentically by `trusted_setup()` before any exchange. Eve cannot change this configuration, and keys or labels arriving in messages are never trusted.
- Signing private keys and DH private exponents never leave their owners; Eve cannot read memory.
- The PyCryptodome and `cryptography` libraries are correct, and `secrets` is a sound source of randomness.
- Eve fully controls the simulated network: she can read, drop, modify, re-sign with her own key, and replay.

## 7. Limitations

- 16 to 32-bit primes are trivially breakable (see section 8). This is a teaching tool, not a secure implementation.
- The shared secret is not passed through a key-derivation function and is not used to encrypt anything.
- There is no explicit key confirmation. The finish message is a signed acknowledgement of the transcript, not proof that Alice computed the secret. The coordinator compares the two local secrets directly instead.
- Primitive-root generators are used; real finite-field groups use a prime-order subgroup with full subgroup validation.
- Python integers are immutable, so "clearing" a private exponent drops the reference but cannot guarantee the value is erased from memory.
- Square-and-multiply here branches on exponent bits and is not constant-time.
- Bob does not cache initiations, so a replayed init costs him work (a denial-of-service consideration) even though it cannot complete an exchange.
- One pending session per peer means a newer initiation, or a rejected injected message, replaces or aborts the current one.

## 8. Research comparison: finite-field DH vs. elliptic-curve DH

Both protocols agree on a secret through a one-way operation in a group. Finite-field DH, as in this project, uses modular exponentiation: g^a mod p, computed by square-and-multiply. Elliptic-curve DH (ECDH) replaces the multiplicative group with points on a curve, and exponentiation becomes scalar multiplication: aP means adding the point P to itself a times, computed with the analogous double-and-add or Montgomery-ladder algorithm. Security rests on the discrete logarithm problem in each group. Elliptic-curve groups have no known sub-exponential attack comparable to the index calculus methods that work on finite fields, so NIST SP 800-57 rates a 256-bit ECC key at roughly the 128-bit security level, the same as a 3072-bit finite-field group [1].

That gap explains the classroom choice of 16 to 32-bit primes. Small moduli make trial division and generator search fast and let results be checked by hand, but they offer no security: a 32-bit discrete logarithm can be solved by brute force or baby-step giant-step in about 2^16 steps, and when p - 1 has only small factors the Pohlig-Hellman method makes it even easier.

Factoring p - 1 is itself a scaling limit. Trial division needs about sqrt(p) steps, which is impossible for a 2048-bit prime. Real systems avoid it with safe primes (p = 2q + 1, so the factorization is known by construction) or with standardized, pre-validated groups such as the RFC 7919 FFDHE groups [5]. ECDH avoids the issue completely: X25519 uses one fixed, published curve, so peers never generate or factor anything [2].

Ephemeral ECDH (ECDHE) means each session uses a fresh key pair that is discarded afterward. This is how fresh session keys deliver forward secrecy: if a long-term signing key leaks later, past session secrets cannot be recomputed because the ephemeral private values no longer exist. TLS 1.3 removed static RSA and static DH key exchange so that every handshake uses (EC)DHE [3]. This project mirrors that by generating fresh exponents and nonces every exchange.

ECDH still needs authentication. Its math is no more resistant to a man-in-the-middle than finite-field DH; Eve can substitute curve points exactly as she substituted E1 and E2 here. TLS 1.3 solves this the same way this project does, by having the server sign a hash of the handshake transcript with a certified key [3]. Note that Ed25519, used here for signatures, and X25519 (ECDH) are related curves but serve different purposes with different keys.

Production applications rely on established protocols, validated parameters, and vetted libraries because the failure modes are subtle: invalid-curve and small-subgroup attacks, weak or reused parameters, timing side channels, and transcript-binding mistakes. Specifications such as NIST SP 800-56A [4] and RFC 7748 [2] encode the required checks, and maintained libraries implement them in constant time.

## References

1. E. Barker, "Recommendation for Key Management: Part 1 - General," NIST Special Publication 800-57 Part 1 Revision 5, May 2020. https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final
2. A. Langley, M. Hamburg, and S. Turner, "Elliptic Curves for Security," RFC 7748, IETF, January 2016. https://www.rfc-editor.org/rfc/rfc7748
3. E. Rescorla, "The Transport Layer Security (TLS) Protocol Version 1.3," RFC 8446, IETF, August 2018. https://www.rfc-editor.org/rfc/rfc8446
4. E. Barker, L. Chen, A. Roginsky, A. Vassilev, and R. Davis, "Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography," NIST Special Publication 800-56A Revision 3, April 2018. https://csrc.nist.gov/pubs/sp/800/56/a/r3/final
5. D. Gillmor, "Negotiated Finite Field Diffie-Hellman Ephemeral Parameters for Transport Layer Security (TLS)," RFC 7919, IETF, August 2016. https://www.rfc-editor.org/rfc/rfc7919
