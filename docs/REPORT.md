# Authenticated Diffie-Hellman: Project Report

## 1. Introduction

The goal of this project was to implement and demonstrate an authenticated finite-field Diffie-Hellman (DH) key exchange between two participants, Alice and Bob. It explores how two parties can establish a shared secret over an untrusted network, and why that exchange must be authenticated to stop a man-in-the-middle attack.

Alice generates the public parameters: a prime $p$ and a generator $g$. Both participants then exchange public values through a three-message protocol. Each message is signed with a long-term Ed25519 identity key, and each side verifies the other's signatures against a public key it already trusts.

An attacker named Eve controls the simulated network. The project shows that Eve can intercept and manipulate an unauthenticated Diffie-Hellman exchange without either participant noticing. When digital signatures and trusted public keys are added, the same attack is detected and rejected.

The implementation is written in Python and uses PyCryptodome for prime generation and primality testing, and the `cryptography` library for Ed25519 signatures. Modular exponentiation, factorization, generator verification, and the Diffie-Hellman calculations are implemented by hand.

## 2. Algorithms and Implementation

### 2.1 Square-and-Multiply Modular Exponentiation

The function `modular_exponentiation(base, exponent, modulus)` in `modular_math.py` computes $\text{base}^{\text{exponent}} \bmod \text{modulus}$ without ever calculating the full power.

The algorithm reads the exponent one bit at a time, starting from the lowest bit. When the current bit is 1, the current power of the base is multiplied into the result. The base is then squared to produce the next power, and the exponent is halved to move to the next bit. Every product is reduced by the modulus immediately, so intermediate values never grow larger than the modulus squared.

For an exponent $e$, the loop runs about $`\log_2 e`$ times, so the algorithm uses $O(\log e)$ modular operations. For example, $5^6 \bmod 23 = 8$ (traced step by step in Section 3.1).

The function rejects invalid input: non-integers, Boolean values, negative exponents, and moduli less than or equal to zero.

### 2.2 Prime Number Generation

The `generate_prime` function in `parameters.py` produces the prime used in the exchange. It calls PyCryptodome's `getPrime()` with `secrets.token_bytes` as the random source, then confirms that the returned value has exactly the requested bit length and is odd. The total time is measured with `time.perf_counter()`.

The program supports prime sizes from 16 to 32 bits, with 16 as the default. For a $k$-bit prime, the result always satisfies

$$2^{k-1} \leq p < 2^k$$

These small sizes were chosen so the math is quick to run, easy to test, and possible to check by hand.

### 2.3 Received Modulus Validation

Bob does not automatically trust the prime he receives from Alice. Before continuing, `validate_received_modulus` checks, in order:

1. The value is a real integer, not a Boolean or another data type.
2. The value is between 16 and 32 bits long.
3. PyCryptodome's `isPrime()` confirms that it is prime.

The size check runs before the primality test so that no expensive work is done on out-of-range values.

A separate, explicit fixture option allows small teaching values such as $p = 23$. Even then, the number must still pass the primality check, so a composite like 21 is rejected.

### 2.4 Factoring $p - 1$

The `prime_factors` function finds the distinct prime factors of $p - 1$ using trial division. It first divides out every factor of 2, then tries odd divisors starting at 3, dividing each one out completely before moving on. It stops once the square of the current divisor is larger than what remains. Any remaining value greater than 1 is also a prime factor.

For example, $23 - 1 = 22 = 2 \times 11$, so the distinct prime factors are 2 and 11. An input of 1 returns an empty set.

### 2.5 Generator Verification and Search

The `is_generator` and `find_generator` functions find a primitive generator for the multiplicative group modulo $p$.

For a prime $p$, this group has order $p - 1$. A candidate $g$ is a generator only if, for every distinct prime factor $r$ of $p - 1$:

$$g^{(p-1)/r} \bmod p \neq 1$$

If any of these results equals 1, the order of $g$ is smaller than $p - 1$ and the candidate is rejected. The complete set of prime factors must be used; checking only some of them can wrongly accept a value that is not a generator, and one of the tests demonstrates exactly that.

`find_generator` tries candidates starting at 2 and returns the smallest one that passes every check.

### 2.6 Diffie-Hellman Keys and Shared Secrets

For every exchange, each participant generates a fresh private exponent with Python's `secrets` module, chosen from the range $2 \leq x \leq p - 2$. Each then computes a public value with square-and-multiply:

$$A = g^a \bmod p \qquad B = g^b \bmod p$$

After exchanging public values, each side computes the shared secret:

$$S_A = B^a \bmod p \qquad S_B = A^b \bmod p$$

Both calculations produce the same value, so $`S_A = S_B`$.

Public values must fall between 2 and $p - 2$. If a newly generated public value lands outside that range, a new private exponent is drawn, and any received public value outside the range is rejected.

### 2.7 Messages and Digital Signatures

Every message has two parts:

- `payload`: the protocol data.
- `signature`: the Ed25519 signature of the payload, as a hexadecimal string.

Before signing, the payload is encoded as deterministic JSON, with keys sorted and no extra spaces, so the signer and the verifier always work with exactly the same bytes.

Incoming messages are parsed strictly:

- Messages larger than 4096 bytes are rejected.
- Only valid UTF-8 is accepted.
- Duplicate JSON keys are rejected.
- Floating-point numbers, NaN, and Infinity are rejected.
- Each message must contain exactly the expected fields, with the expected types. Strings are never converted to integers.
- Integer fields are limited to 32 bits before any arithmetic is done.
- Identity labels must be exactly "Alice" or "Bob".
- Nonces must be exactly 64 lowercase hexadecimal characters.

Signatures are checked with `Ed25519PublicKey.verify()`. An invalid signature raises an `InvalidSignature` exception, which aborts the exchange.

### 2.8 Three-Message Authentication Protocol

The protocol in `protocol.py` uses three messages.

#### Message 1: Init

Alice sends a signed initiation message containing the protocol identifier, both identities, the prime $p$, the generator $g$, her public value $A$, and a fresh 32-byte nonce.

Bob checks the message format, then verifies Alice's signature using her trusted public key. Next he independently validates $p$, factors $p - 1$, verifies $g$, and checks that $A$ is in range.

#### Message 2: Response

Bob replies with a signed message containing the complete transcript: the protocol identifier, both identities, $p$, $g$, $A$, his public value $B$, Alice's nonce, and a new nonce of his own.

Alice confirms that $p$, $g$, $A$, and her nonce exactly match her pending session, checks that $B$ is in range, and verifies Bob's signature with his trusted public key. If everything passes, she computes her shared secret.

#### Message 3: Finish

Alice sends a signed finish message containing the same transcript. Bob requires it to match the transcript stored in his session exactly, then verifies Alice's signature. Only after both checks pass does he compute his shared secret and mark the session complete.

Each participant keeps a record of its pending sessions, and Bob remembers the nonces of completed sessions so a duplicate finish message is rejected. If any message is rejected, the affected session is aborted, its private exponent is cleared, and no shared secret is computed or used.

### 2.9 Replayed Initiation Messages

Bob does not keep a cache of previous initiation messages, so if Eve replays an old one, he will respond to it. However, every response contains a brand-new nonce from Bob, and he will only complete the exchange after receiving a finish message signed by Alice over a transcript that includes that new nonce.

Eve cannot create that signature because she does not have Alice's private signing key, and Alice has no pending session that would make her produce one. A replayed initiation can therefore make Bob do extra work, but it can never complete a new exchange.

## 3. Worked Mathematical Examples

These examples use $p = 23$ as a teaching fixture because every step can be checked by hand.

### 3.1 Square-and-Multiply Example

Calculate $5^6 \bmod 23$:

| Iteration | Exponent | Base | Result | Squared Base | Next Exponent |
|---:|---:|---:|---:|---:|---:|
| 1 | 6 | 5 | 1 | 2 | 3 |
| 2 | 3 | 2 | 2 | 4 | 1 |
| 3 | 1 | 4 | 8 | 16 | 0 |

$$5^6 \bmod 23 = 8$$

The tests also cover boundary cases: an exponent of zero, a modulus of one, a negative exponent, and a modulus of zero.

### 3.2 Prime Factorization and Generator Selection

For $p = 23$, $p - 1 = 22 = 2 \times 11$, so the distinct prime factors are 2 and 11.

- Testing $g = 2$: $2^{11} \bmod 23 = 1$, so 2 is rejected.
- Testing $g = 5$: $5^{11} \bmod 23 = 22$ and $5^2 \bmod 23 = 2$. Neither result is 1, so 5 is accepted.

For a larger example, take $p = 65537$. Since $65537 - 1 = 65536 = 2^{16}$, the only distinct prime factor is 2. Testing $g = 3$ gives $3^{32768} \bmod 65537 = 65536$, so 3 is accepted.

### 3.3 Diffie-Hellman Key Agreement

Using $p = 23$, $g = 5$, and private exponents $a = 6$ and $b = 15$:

| Step | Alice | Bob |
|---|---|---|
| Public value | $A = 5^6 \bmod 23 = 8$ | $B = 5^{15} \bmod 23 = 19$ |
| Shared secret | $`S_A = 19^6 \bmod 23 = 2`$ | $`S_B = 8^{15} \bmod 23 = 2`$ |

Both participants arrive at the same secret, $`S_A = S_B = 2`$, without the secret ever being sent across the network.

### 3.4 Eve's Man-in-the-Middle Attack

Without authentication, Eve can sit between Alice and Bob and run two separate Diffie-Hellman exchanges. She chooses private exponents $`e_1 = 3`$ and $`e_2 = 7`$, giving public values $`E_1 = 5^3 \bmod 23 = 10`$ and $`E_2 = 5^7 \bmod 23 = 17`$.

She sends $`E_1 = 10`$ to Alice in place of Bob's value, and $`E_2 = 17`$ to Bob in place of Alice's value:

| | Victim computes | Eve computes |
|---|---|---|
| Alice's side | $10^6 \bmod 23 = 6$ | $8^3 \bmod 23 = 6$ |
| Bob's side | $17^{15} \bmod 23 = 15$ | $19^7 \bmod 23 = 15$ |

Alice and Bob now hold different secrets, and Eve knows both. Neither of them can detect the attack, because plain Diffie-Hellman gives no way to verify who sent a public value.

### 3.5 Eve's Attack Against the Authenticated Protocol

In the authenticated version, Eve tries the same substitution by replacing Bob's public value in the response message with her own value of 10. Changing the message invalidates Bob's signature, so when Alice verifies it, the program reports:

```
Bob response signature: INVALID
Exchange aborted.
```

Alice rejects the message and aborts the session. Re-signing the modified message with Eve's own private key does not help either, because Alice only accepts signatures that verify against Bob's pre-configured public key. This is what protects the integrity and authenticity of the exchange.

## 4. Testing and Results

The project includes 90 automated tests, run with `python -m unittest -v`. All 90 pass.

| Component | Testing performed |
|---|---|
| Modular exponentiation | Known results, exponent zero, modulus one, negative bases, invalid inputs, and 500 random comparisons against Python's built-in `pow()` |
| Prime generation | Exact bit length, oddness, and primality for every size from 16 to 32 bits; rejection of invalid sizes and types, including Boolean values |
| Modulus validation | Composite input (32769), invalid types, unsupported sizes, and the teaching fixture option |
| Factorization | 1, 22, 65536, and other values |
| Generator verification | Accepting 5 and rejecting 2 for $p = 23$, accepting 3 for $p = 65537$, and brute-force order checks |
| Key agreement | The fixed $p = 23$ example plus three generated exchanges at each of 16, 24, and 32 bits |
| Authentication | Valid signatures, a wrong trusted key, and every attack in the assignment's attack table |
| Session management | Fresh nonces, stale messages, replayed messages, duplicate completion, and messages in the wrong order |

The attack tests confirm that the protocol rejects modified public values, a modified prime or generator, changed identity labels, corrupted signatures, and messages signed with Eve's key. Additional tests cover replayed responses, replayed finish messages, duplicate finish messages, and malformed, oversized, or out-of-order messages.

## 5. Performance

Running `python main.py benchmark` performs three complete exchanges at each of 16, 24, and 32 bits, recording prime-generation time, factorization time, generator-search time, and whether the exchange was authenticated. Full results and environment details are in `performance.md`.

On my Mac, all nine exchanges were authenticated with matching secrets. Prime generation was the slowest step, and its time grew with the prime size: about 0.4 to 0.5 ms at 16 bits and about 1.1 to 1.4 ms at 32 bits. Factorization and generator search each took well under 1 ms, and a complete three-message exchange, including all signing and verification, took under 5 ms.

Most of the variation between runs comes from prime generation. Because candidates are random, the number the library must test before finding a prime changes from run to run. Factorization time depends on the structure of $p - 1$: it finishes almost immediately when $p - 1$ has only small factors, but in the worst case ($p - 1 = 2q$ with $q$ prime) trial division needs roughly $2^{k/2-1}$ odd divisors for a $k$-bit prime.

## 6. Trust Assumptions

The security of the authenticated protocol depends on these assumptions:

- **Trusted key distribution.** Alice and Bob receive each other's Ed25519 public keys through a trusted process before any exchange, handled here by `trusted_setup()`. Eve cannot change this configuration, and keys or identity labels that arrive in network messages are never trusted.
- **Secret keys stay secret.** Signing keys and Diffie-Hellman private exponents never leave their owners, and Eve cannot read either participant's memory.
- **Correct libraries and randomness.** PyCryptodome and `cryptography` work correctly, and Python's `secrets` module is a reliable source of randomness.
- **Hostile network.** Eve has complete control of the simulated network: she can read, drop, modify, re-sign with her own key, and replay messages.

Under these assumptions, the project shows that authentication keeps the key exchange safe even when the network itself cannot be trusted.

## 7. Limitations

- **Tiny primes.** The program only supports 16 to 32-bit primes, which are far too small for real security. They were chosen so the calculations could be demonstrated and verified easily.
- **No key derivation or encryption.** The shared secret is not passed through a key-derivation function and is not used to encrypt any data.
- **No explicit key confirmation.** The finish message is a signed acknowledgement of the transcript, not proof that Alice actually computed the shared secret. The test coordinator compares the two local secrets directly instead.
- **Primitive-root generators.** Real systems use a standardized prime-order subgroup with additional parameter and subgroup validation.
- **Memory clearing.** Clearing a private exponent in Python only removes the reference to it; Python does not guarantee the value is erased from memory.
- **Not constant-time.** Square-and-multiply branches on each exponent bit, so its timing could leak information about the exponent.
- **Replay cost.** Because Bob does not cache initiation messages, a replayed initiation cannot complete an exchange but can still make him do unnecessary work, which is a potential denial-of-service concern.

## 8. Research Comparison: Finite-Field DH vs. Elliptic-Curve DH

Finite-field Diffie-Hellman and elliptic-curve Diffie-Hellman (ECDH) both let two parties agree on a secret using an operation that is easy to perform but hard to reverse. Finite-field DH uses modular exponentiation, $g^a \bmod p$, which this project computes with square-and-multiply. ECDH uses points on an elliptic curve instead, and the equivalent operation is scalar multiplication: adding a public point to itself a secret number of times, computed efficiently with double-and-add or the Montgomery ladder. Both depend on the difficulty of the discrete logarithm problem in their group.

The main advantage of elliptic curves is much smaller keys for the same security. NIST SP 800-57 rates a 256-bit elliptic-curve key at about 128-bit security, comparable to a 3072-bit finite-field group [1].

That gap explains this project's 16 to 32-bit primes. They keep the math fast and checkable by hand but provide no real security: a 32-bit discrete logarithm can be solved with baby-step giant-step in roughly $2^{16}$ steps.

Factoring $p - 1$ is another limit. Trial division takes about $\sqrt{p}$ steps, which is impossible for a 2048-bit prime. Real systems avoid it by using safe primes ($p = 2q + 1$), whose factorization is known by construction, or standardized, pre-validated groups such as the RFC 7919 FFDHE groups [5]. ECDH avoids the problem entirely; X25519, for example, uses one fixed, published curve, so nothing is generated or factored during an exchange [2].

Ephemeral ECDH (ECDHE) means each session uses a fresh key pair that is discarded afterward. This provides forward secrecy: if a long-term signing key is stolen later, past session secrets still cannot be recovered, because the temporary private values no longer exist. TLS 1.3 removed static RSA and static Diffie-Hellman so that every handshake uses ephemeral (EC)DHE [3]. This project follows the same idea by generating fresh exponents and nonces for every exchange.

ECDH still needs authentication. Its math does nothing to stop a man-in-the-middle; Eve could substitute curve points exactly as she substituted $`E_1`$ and $`E_2`$ here. TLS 1.3 solves this the same way this project does, by signing the handshake transcript [3]. Ed25519 and X25519 are related but serve different purposes: Ed25519 creates signatures, while X25519 performs key agreement.

Finally, production systems rely on established protocols, validated parameters, and maintained libraries because the failure modes are subtle, including invalid-curve and small-subgroup attacks, weak parameters, timing side channels, and transcript-binding mistakes. Standards such as NIST SP 800-56A [4] and RFC 7748 [2] define the required checks.

## 9. Conclusion

This project demonstrates how Diffie-Hellman key exchange works and why authentication is essential on an untrusted network.

In the unauthenticated exchange, Eve replaced the public values and set up a separate shared secret with each of Alice and Bob, and neither of them noticed. Adding Ed25519 signatures, trusted public keys, nonces, transcript verification, and session tracking stopped the same attack: any modified message was rejected, because Eve cannot produce a valid signature without the other participant's private key.

Along the way, the project implements and tests modular exponentiation, library-based prime generation, factorization, generator verification, key agreement, and replay handling. Its small primes and other limitations make it unsuitable for production use, but it gives a clear, working demonstration of how authenticated key exchange defends against active attackers.

## References

[1] E. Barker, "Recommendation for Key Management: Part 1 - General," NIST Special Publication 800-57 Part 1 Revision 5, May 2020. https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final

[2] A. Langley, M. Hamburg, and S. Turner, "Elliptic Curves for Security," RFC 7748, IETF, January 2016. https://www.rfc-editor.org/rfc/rfc7748

[3] E. Rescorla, "The Transport Layer Security (TLS) Protocol Version 1.3," RFC 8446, IETF, August 2018. https://www.rfc-editor.org/rfc/rfc8446

[4] E. Barker, L. Chen, A. Roginsky, A. Vassilev, and R. Davis, "Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography," NIST Special Publication 800-56A Revision 3, April 2018. https://csrc.nist.gov/pubs/sp/800/56/a/r3/final

[5] D. Gillmor, "Negotiated Finite Field Diffie-Hellman Ephemeral Parameters for Transport Layer Security (TLS)," RFC 7919, IETF, August 2016. https://www.rfc-editor.org/rfc/rfc7919
