# Authenticated Diffie-Hellman Key Exchange (Classroom Simulation)

A Python simulation of finite-field Diffie-Hellman between Alice and Bob, authenticated with trusted Ed25519 identity keys. It generates and validates public parameters, runs a three-message signed exchange, and shows an active attacker (Eve) succeeding against plain Diffie-Hellman and being detected by the authenticated version.

This is a local simulation. There are no network sockets, no message encryption, and no ECDH implementation.

## What is implemented by hand vs. by a library

| Component | Source |
|---|---|
| Square-and-multiply modular exponentiation | Implemented in `modular_math.py` |
| Factorization of p - 1 (trial division) | Implemented in `parameters.py` |
| Generator verification and search | Implemented in `parameters.py` |
| Diffie-Hellman key generation and shared secret | Implemented in `participant.py` |
| Prime generation (`getPrime`) and primality validation (`isPrime`) | PyCryptodome |
| Ed25519 signatures | `cryptography` |

Python's three-argument `pow()` appears only in the tests, as an independent reference.

## Library versions

| Package | Version |
|---|---|
| cryptography | 50.0.1 |
| pycryptodome | 4.2.0 |

Both are pinned in `requirements.txt`. Python 3.9.2 or newer is required (developed on 3.13).

## Project layout

| File | Responsibility |
|---|---|
| `modular_math.py` | Square-and-multiply |
| `parameters.py` | Library prime-generation wrapper, received-modulus validation, factorization, generator selection |
| `messages.py` | Deterministic JSON encoding, strict parsing, message schemas |
| `authentication.py` | Trusted-key store, trusted setup, Ed25519 signing and verification |
| `participant.py` | Per-participant identity key, trusted keys, DH key generation |
| `protocol.py` | Three-message protocol, pending-session state, exchange coordinator |
| `eve.py` | Interception, tampering, re-signing, replay, attack demos |
| `main.py` | Demonstrations, benchmarks, CLI |
| `tests/` | Automated tests (unittest) |
| `docs/REPORT.md` | Report and ECDH research comparison |
| `docs/performance.md` | Timing results for 16, 24, and 32 bits |
| `docs/sample_output_*.txt` | Sample program output |

## Setup (macOS)

```bash
cd authenticated-dh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

To use the latest library versions instead, run `python -m pip install cryptography pycryptodome`, then update the versions above with `python -m pip show cryptography pycryptodome`.

## Run

```bash
python main.py                         # successful exchange, default 16-bit prime
python main.py demo --bits 24          # any size from 16 to 32
python main.py demo --debug            # also prints private values, clearly labeled
python main.py attack                  # Eve vs. unauthenticated and authenticated DH
python main.py benchmark               # 3 exchanges each at 16, 24, 32 bits
python main.py benchmark --save docs/performance.md
python main.py all                     # everything
```

Invalid sizes are rejected:

```
$ python main.py demo --bits 12
main.py demo: error: argument --bits: prime size must be between 16 and 32 bits.
```

## Test

```bash
python -m unittest -v
```

Tests are split into four files:

| File | Covers |
|---|---|
| `tests/test_math.py` | Fixed math: exponentiation, factorization, generators, p = 23 key agreement |
| `tests/test_prime_generation.py` | Library prime-generator wrapper and received-modulus validation |
| `tests/test_message_validation.py` | Encoding, strict JSON, schemas, types, sizes, nonces |
| `tests/test_exchange.py` | Full exchanges, every attack in the attack table, session state |

In VS Code, the included `.vscode/settings.json` enables the Testing panel (beaker icon) for these tests.

## Protocol summary

```
1. Alice -> Bob   init      {protocol, "init", Alice, Bob, p, g, A, nonce_A}      + Alice's signature
2. Bob   -> Alice response  {"response", transcript}                             + Bob's signature
3. Alice -> Bob   finish    {"finish", transcript}                               + Alice's signature

transcript = {protocol, initiator, responder, p, g, A, B, nonce_A, nonce_B}
protocol   = "DH-CLASSROOM-AUTH-v1"
```

Each message is `{"payload": {...}, "signature": "<hex>"}` encoded with `json.dumps(..., sort_keys=True, separators=(",", ":"))`. Signatures are verified only against keys provisioned by `trusted_setup()`, never against keys carried in a message.

## Sample output

Successful exchange (`docs/sample_output_success.txt`):

```
Requested prime size: 16 bits
Modulus: generated using library prime generator
Modulus bit length: 16
Received modulus library validation: PASS
Generator: validated (g = 3)
Alice initiation signature: VALID
Bob response signature: VALID
Alice finish signature: VALID
Transcript authenticated: YES
Shared-secret equality in local test: PASS
Explicit key confirmation: NOT IMPLEMENTED
```

Attack (`docs/sample_output_attack.txt`):

```
Eve modified Bob's public value (B -> 10) and kept Bob's signature.
Bob response signature: INVALID
Transcript authenticated: NO
Exchange aborted.
```
