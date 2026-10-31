# Performance results

## Environment

- Date: 2026-10-30 20:23
- OS: macOS-15.5-x86_64-i386-64bit
- Machine: x86_64 (i386)
- Python: CPython 3.11.5
- cryptography: 50.0.1
- pycryptodome: 4.2.0

Durations measured with `time.perf_counter()`. Prime generation is the full
`generate_prime` wrapper time. Total is the whole three-message exchange.

## Trials

| Bits | Trial | p | g | Prime generation (s) | Factorization (s) | Generator search (s) | Total exchange (s) | Authenticated | Secrets match |
|---|---|---|---|---|---|---|---|---|---|
| 16 | 1 | 59663 | 5 | 0.000509 | 0.000009 | 0.000048 | 0.003473 | Yes | Yes |
| 16 | 2 | 40903 | 3 | 0.000341 | 0.000007 | 0.000029 | 0.001889 | Yes | Yes |
| 16 | 3 | 37039 | 3 | 0.000328 | 0.000010 | 0.000019 | 0.001919 | Yes | Yes |
| 24 | 1 | 9860891 | 2 | 0.000896 | 0.000027 | 0.000025 | 0.002974 | Yes | Yes |
| 24 | 2 | 12402647 | 5 | 0.000836 | 0.000154 | 0.000033 | 0.003317 | Yes | Yes |
| 24 | 3 | 12601583 | 5 | 0.001256 | 0.000015 | 0.000044 | 0.003333 | Yes | Yes |
| 32 | 1 | 3847916587 | 2 | 0.001135 | 0.001528 | 0.000033 | 0.006754 | Yes | Yes |
| 32 | 2 | 3888217843 | 3 | 0.001620 | 0.000289 | 0.000077 | 0.004652 | Yes | Yes |
| 32 | 3 | 3488449999 | 3 | 0.001464 | 0.000085 | 0.000089 | 0.004218 | Yes | Yes |

## Timing variation (min / median / max, seconds)

| Bits | Prime generation | Factorization | Generator search | Total exchange |
|---|---|---|---|---|
| 16 | 0.000328 / 0.000341 / 0.000509 | 0.000007 / 0.000009 / 0.000010 | 0.000019 / 0.000029 / 0.000048 | 0.001889 / 0.001919 / 0.003473 |
| 24 | 0.000836 / 0.000896 / 0.001256 | 0.000015 / 0.000027 / 0.000154 | 0.000025 / 0.000033 / 0.000044 | 0.002974 / 0.003317 / 0.003333 |
| 32 | 0.001135 / 0.001464 / 0.001620 | 0.000085 / 0.000289 / 0.001528 | 0.000033 / 0.000077 / 0.000089 | 0.004218 / 0.004652 / 0.006754 |

All 9 exchanges authenticated with matching secrets: YES
