"""Run demonstrations and timing for the authenticated Diffie-Hellman project.

Usage:
    python main.py                       # successful exchange, 16-bit prime
    python main.py demo --bits 24        # successful exchange, 24-bit prime
    python main.py demo --debug          # also print private values (classroom debug)
    python main.py attack                # Eve vs. unauthenticated and authenticated DH
    python main.py benchmark             # 3 trials each at 16, 24, 32 bits
    python main.py benchmark --save docs/performance.md
    python main.py all                   # demo + attack + benchmark
"""

from __future__ import annotations

import argparse
import platform
import statistics
import sys
from datetime import datetime
from importlib.metadata import PackageNotFoundError, version
from typing import Dict, List, Optional

from eve import Eve, authenticated_substitution_demo, unauthenticated_mitm_demo
from parameters import DEFAULT_PRIME_BITS, ParameterError, parse_bit_length_input
from protocol import (
    TEACHING_FIXTURE,
    ExchangeReport,
    new_simulation,
    run_authenticated_exchange,
)

RULE = "=" * 64


def _yes(flag: Optional[bool]) -> str:
    return "YES" if flag else "NO"


def _pass(flag: Optional[bool]) -> str:
    if flag is None:
        return "NOT RUN"
    return "PASS" if flag else "FAIL"


def _fmt_factors(factors) -> str:
    return "{" + ", ".join(str(f) for f in sorted(factors)) + "}"


def library_versions() -> Dict[str, str]:
    out = {}
    for pkg in ("cryptography", "pycryptodome"):
        try:
            out[pkg] = version(pkg)
        except PackageNotFoundError:
            out[pkg] = "not installed"
    return out


def environment_lines() -> List[str]:
    libs = library_versions()
    return [
        f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"OS: {platform.platform()}",
        f"Machine: {platform.machine()} ({platform.processor() or 'unknown processor'})",
        f"Python: {platform.python_implementation()} {platform.python_version()}",
        f"cryptography: {libs['cryptography']}",
        f"pycryptodome: {libs['pycryptodome']}",
    ]


# --------------------------------------------------------------------------
# Successful exchange
# --------------------------------------------------------------------------

def print_exchange(report: ExchangeReport, debug_values: Optional[Dict[str, int]] = None) -> None:
    params = report.parameters
    if report.requested_bits is not None:
        print(f"Requested prime size: {report.requested_bits} bits")
        print("Modulus: generated using library prime generator")
    else:
        print("Modulus: classroom TEST FIXTURE (not a valid normal run)")
    print(f"p = {report.p}")
    if report.p is not None:
        print(f"Modulus bit length: {report.p.bit_length()}")
    if params is not None:
        print(f"Factors of p - 1: {_fmt_factors(params.factors)}")
        print(f"Prime generation time:   {params.prime_generation_seconds:.6f} s")
        print(f"Factorization time:      {params.factorization_seconds:.6f} s")
        print(f"Generator search time:   {params.generator_search_seconds:.6f} s")
    print(f"Received modulus library validation: {report.modulus_validation}")
    gen = "validated" if report.generator_validation == "PASS" else report.generator_validation
    print(f"Generator: {gen} (g = {report.g})")
    print(f"Alice initiation signature: {report.init_signature}")
    print(f"Bob response signature: {report.response_signature}")
    print(f"Alice finish signature: {report.finish_signature}")
    print(f"Transcript authenticated: {_yes(report.authenticated)}")
    print(f"Shared-secret equality in local test: {_pass(report.secrets_match)}")
    print("Explicit key confirmation: NOT IMPLEMENTED")
    if report.error:
        print(f"Exchange aborted: {report.error}")
    elif not debug_values:
        print("Shared secret: [hidden; use --debug to show]")
    if debug_values:
        print("-" * 64)
        print("[CLASSROOM DEBUG - private values, never sent on the network]")
        for key in ("a", "b", "S_A", "S_B"):
            if key in debug_values:
                print(f"[CLASSROOM DEBUG] {key} = {debug_values[key]}")


def run_demo(bits: int, debug: bool = False) -> ExchangeReport:
    print(RULE)
    print("SUCCESSFUL AUTHENTICATED DIFFIE-HELLMAN EXCHANGE")
    print(RULE)
    alice, bob = new_simulation(debug=debug)
    report = run_authenticated_exchange(alice, bob, bits)
    debug_values = {**alice.debug_values, **bob.debug_values} if debug else None
    print_exchange(report, debug_values)
    print()
    return report


# --------------------------------------------------------------------------
# Attack demonstrations
# --------------------------------------------------------------------------

def run_attack_demo() -> None:
    f = TEACHING_FIXTURE
    print(RULE)
    print("ATTACK 1: EVE vs. UNAUTHENTICATED DIFFIE-HELLMAN (teaching fixture)")
    print(RULE)
    r = unauthenticated_mitm_demo()
    print(f"p = {f.p}, g = {f.g}, Alice a = {f.alice_exponent}, Bob b = {f.bob_exponent}")
    print(f"Alice sends A = {r['A']}; Bob sends B = {r['B']}")
    print(f"Eve picks e1 = {r['e1']}: E1 = {f.g}^{r['e1']} mod {f.p} = {r['E1']}")
    print(f"Eve picks e2 = {r['e2']}: E2 = {f.g}^{r['e2']} mod {f.p} = {r['E2']}")
    print(f"Eve sends E1 = {r['E1']} to Alice as if from Bob, E2 = {r['E2']} to Bob as if from Alice")
    print(f"  Alice computes: {r['E1']}^{f.alice_exponent} mod {f.p} = {r['alice_secret']}")
    print(f"  Eve computes:   {r['A']}^{r['e1']} mod {f.p} = {r['eve_secret_with_alice']}")
    print(f"  Bob computes:   {r['E2']}^{f.bob_exponent} mod {f.p} = {r['bob_secret']}")
    print(f"  Eve computes:   {r['B']}^{r['e2']} mod {f.p} = {r['eve_secret_with_bob']}")
    print("Result: Alice and Bob hold DIFFERENT secrets, and Eve knows BOTH.")
    print("Unauthenticated exchange detected the attack: NO")
    print()

    print(RULE)
    print("ATTACK 2: SAME SUBSTITUTION vs. AUTHENTICATED PROTOCOL")
    print(RULE)
    alice, bob = new_simulation()
    report, E1 = authenticated_substitution_demo(alice, bob)
    print(f"Alice initiation signature: {report.init_signature}")
    print(f"Eve modified Bob's public value (B -> {E1}) and kept Bob's signature.")
    print(f"Bob response signature: {report.response_signature}")
    print(f"Transcript authenticated: {_yes(report.authenticated)}")
    print("Exchange aborted." if report.error else "Exchange completed (UNEXPECTED).")
    print(f"Reason: {report.error}")
    print(f"Alice still holds a pending session: {_yes(alice.has_pending_session('Bob'))}")
    print()

    print(RULE)
    print("ATTACK 3: EVE RE-SIGNS A MODIFIED INIT WITH HER OWN KEY, LABELED 'Alice'")
    print(RULE)
    eve = Eve()
    alice, bob = new_simulation()
    channel = Eve.channel_that("init", lambda raw: eve.resign(raw, ("A",), E1))
    report = run_authenticated_exchange(alice, bob, fixture=TEACHING_FIXTURE, channel=channel)
    print(f"Eve replaced A with {E1} and signed with her own key.")
    print("Bob verifies against Alice's ALREADY-CONFIGURED trusted key.")
    print(f"Alice initiation signature: {report.init_signature}")
    print("Exchange aborted." if report.error else "Exchange completed (UNEXPECTED).")
    print(f"Reason: {report.error}")
    print()


# --------------------------------------------------------------------------
# Benchmark
# --------------------------------------------------------------------------

def run_benchmark(bit_sizes: List[int], trials: int) -> str:
    alice, bob = new_simulation()  # identities retained across all exchanges
    rows = []
    for bits in bit_sizes:
        for trial in range(1, trials + 1):
            rep = run_authenticated_exchange(alice, bob, bits)
            prm = rep.parameters
            rows.append((bits, trial, rep.p, rep.g, prm.prime_generation_seconds,
                         prm.factorization_seconds, prm.generator_search_seconds,
                         rep.total_seconds, rep.authenticated, rep.secrets_match))

    out = ["# Performance results", "", "## Environment", ""]
    out += [f"- {line}" for line in environment_lines()]
    out += [
        "",
        "Durations measured with `time.perf_counter()`. Prime generation is the full",
        "`generate_prime` wrapper time. Total is the whole three-message exchange.",
        "",
        "## Trials",
        "",
        "| Bits | Trial | p | g | Prime generation (s) | Factorization (s) | Generator search (s) | Total exchange (s) | Authenticated | Secrets match |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for (bits, trial, p, g, tp, tf, tg, tt, auth, match) in rows:
        out.append(f"| {bits} | {trial} | {p} | {g} | {tp:.6f} | {tf:.6f} | {tg:.6f} | {tt:.6f} | "
                   f"{'Yes' if auth else 'No'} | {'Yes' if match else 'No'} |")

    out += ["", "## Timing variation (min / median / max, seconds)", "",
            "| Bits | Prime generation | Factorization | Generator search | Total exchange |",
            "|---|---|---|---|---|"]
    for bits in bit_sizes:
        sel = [r for r in rows if r[0] == bits]

        def span(i):
            vals = [r[i] for r in sel]
            return f"{min(vals):.6f} / {statistics.median(vals):.6f} / {max(vals):.6f}"
        out.append(f"| {bits} | {span(4)} | {span(5)} | {span(6)} | {span(7)} |")

    ok = all(r[8] and r[9] for r in rows)
    out += ["", f"All {len(rows)} exchanges authenticated with matching secrets: {'YES' if ok else 'NO'}", ""]
    return "\n".join(out)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _bits_arg(text: str) -> int:
    try:
        return parse_bit_length_input(text)
    except ParameterError as exc:
        raise argparse.ArgumentTypeError(str(exc))


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Authenticated Diffie-Hellman classroom simulation")
    sub = parser.add_subparsers(dest="command")

    demo = sub.add_parser("demo", help="run one successful authenticated exchange")
    demo.add_argument("--bits", type=_bits_arg, default=DEFAULT_PRIME_BITS, help="prime size, 16-32 (default 16)")
    demo.add_argument("--debug", action="store_true", help="show private values (classroom debug only)")

    sub.add_parser("attack", help="demonstrate Eve's attacks")

    bench = sub.add_parser("benchmark", help="time exchanges at 16, 24, and 32 bits")
    bench.add_argument("--trials", type=int, default=3)
    bench.add_argument("--bits", type=_bits_arg, nargs="+", default=[16, 24, 32])
    bench.add_argument("--save", metavar="PATH", help="also write the results to a Markdown file")

    sub.add_parser("all", help="demo + attack + benchmark")

    args = parser.parse_args(argv)
    command = args.command or "demo"

    if command == "demo":
        report = run_demo(getattr(args, "bits", DEFAULT_PRIME_BITS), getattr(args, "debug", False))
        return 0 if report.authenticated and report.secrets_match else 1
    if command == "attack":
        run_attack_demo()
        return 0
    if command == "benchmark":
        if args.trials < 1:
            parser.error("--trials must be at least 1")
        text = run_benchmark(args.bits, args.trials)
        print(text)
        if args.save:
            with open(args.save, "w", encoding="utf-8") as fh:
                fh.write(text)
            print(f"Saved to {args.save}")
        return 0
    if command == "all":
        run_demo(DEFAULT_PRIME_BITS)
        run_attack_demo()
        print(run_benchmark([16, 24, 32], 3))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
