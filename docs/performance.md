# Performance results

## Environment

- Date: 2026-10-30 21:53
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
| 16 | 1 | 35933 | 2 | 0.000379 | 0.000008 | 0.000020 | 0.002862 | Yes | Yes |
| 16 | 2 | 54787 | 2 | 0.000466 | 0.000006 | 0.000020 | 0.001991 | Yes | Yes |
| 16 | 3 | 59611 | 2 | 0.000481 | 0.000007 | 0.000019 | 0.002080 | Yes | Yes |
| 24 | 1 | 10913897 | 3 | 0.000898 | 0.000035 | 0.000025 | 0.002996 | Yes | Yes |
| 24 | 2 | 13078799 | 13 | 0.001147 | 0.000143 | 0.000090 | 0.003751 | Yes | Yes |
| 24 | 3 | 12497141 | 2 | 0.000835 | 0.000011 | 0.000026 | 0.002856 | Yes | Yes |
| 32 | 1 | 2547005653 | 2 | 0.001244 | 0.000503 | 0.000036 | 0.004605 | Yes | Yes |
| 32 | 2 | 2609137579 | 3 | 0.001364 | 0.000074 | 0.000099 | 0.003994 | Yes | Yes |
| 32 | 3 | 3338444009 | 3 | 0.001144 | 0.000085 | 0.000055 | 0.003763 | Yes | Yes |

## Timing variation (min / median / max, seconds)

| Bits | Prime generation | Factorization | Generator search | Total exchange |
|---|---|---|---|---|
| 16 | 0.000379 / 0.000466 / 0.000481 | 0.000006 / 0.000007 / 0.000008 | 0.000019 / 0.000020 / 0.000020 | 0.001991 / 0.002080 / 0.002862 |
| 24 | 0.000835 / 0.000898 / 0.001147 | 0.000011 / 0.000035 / 0.000143 | 0.000025 / 0.000026 / 0.000090 | 0.002856 / 0.002996 / 0.003751 |
| 32 | 0.001144 / 0.001244 / 0.001364 | 0.000074 / 0.000085 / 0.000503 | 0.000036 / 0.000055 / 0.000099 | 0.003763 / 0.003994 / 0.004605 |

All 9 exchanges authenticated with matching secrets: YES
