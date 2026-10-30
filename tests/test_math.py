"""Fixed mathematical tests: exponentiation, factorization, generators, key agreement."""

import random
import unittest

from modular_math import modular_exponentiation
from parameters import find_generator, is_generator, prime_factors
from participant import compute_shared_secret, generate_dh_keypair


class TestModularExponentiation(unittest.TestCase):
    def test_known_result_from_handout(self):
        self.assertEqual(modular_exponentiation(5, 6, 23), 8)

    def test_exponent_zero(self):
        self.assertEqual(modular_exponentiation(5, 0, 23), 1)

    def test_modulus_one(self):
        self.assertEqual(modular_exponentiation(5, 0, 1), 0)
        self.assertEqual(modular_exponentiation(5, 6, 1), 0)

    def test_negative_base(self):
        self.assertEqual(modular_exponentiation(-5, 3, 23), pow(-5, 3, 23))
        self.assertEqual(modular_exponentiation(-1, 7, 10), 9)

    def test_result_in_range(self):
        for _ in range(200):
            m = random.randint(1, 10**6)
            r = modular_exponentiation(random.randint(-10**9, 10**9), random.randint(0, 10**6), m)
            self.assertTrue(0 <= r < m)

    def test_rejects_negative_exponent(self):
        with self.assertRaises(ValueError):
            modular_exponentiation(5, -1, 23)

    def test_rejects_nonpositive_modulus(self):
        with self.assertRaises(ValueError):
            modular_exponentiation(5, 6, 0)
        with self.assertRaises(ValueError):
            modular_exponentiation(5, 6, -7)

    def test_rejects_invalid_types(self):
        for args in [(5.0, 6, 23), (5, 6.0, 23), (5, 6, 23.0), ("5", 6, 23),
                     (True, 6, 23), (5, True, 23), (5, 6, True), (None, 6, 23)]:
            with self.subTest(args=args), self.assertRaises(TypeError):
                modular_exponentiation(*args)

    def test_matches_builtin_pow_reference(self):
        """pow(base, exp, mod) is used ONLY here, as an independent reference."""
        rng = random.Random(364)
        for _ in range(500):
            b = rng.randint(-2**40, 2**40)
            e = rng.randint(0, 2**40)
            m = rng.randint(1, 2**32)
            self.assertEqual(modular_exponentiation(b, e, m), pow(b, e, m))


class TestFactorization(unittest.TestCase):
    def test_one_returns_empty_set(self):
        self.assertEqual(prime_factors(1), set())

    def test_22(self):
        self.assertEqual(prime_factors(22), {2, 11})

    def test_repeated_factors_65536(self):
        self.assertEqual(prime_factors(65536), {2})

    def test_more_values(self):
        self.assertEqual(prime_factors(2), {2})
        self.assertEqual(prime_factors(97), {97})
        self.assertEqual(prime_factors(360), {2, 3, 5})
        self.assertEqual(prime_factors(3 ** 5 * 7 ** 2), {3, 7})
        self.assertEqual(prime_factors(2 ** 31 - 2), {2, 3, 7, 11, 31, 151, 331})

    def test_rejects_invalid(self):
        for bad in (0, -5):
            with self.assertRaises(ValueError):
                prime_factors(bad)
        for bad in (2.0, "22", True):
            with self.assertRaises(TypeError):
                prime_factors(bad)


class TestGenerator(unittest.TestCase):
    def test_p23_accepts_5_rejects_2(self):
        self.assertTrue(is_generator(5, 23))
        self.assertFalse(is_generator(2, 23))  # 2^11 mod 23 == 1

    def test_p23_handout_values(self):
        self.assertEqual(modular_exponentiation(2, 11, 23), 1)
        self.assertEqual(modular_exponentiation(5, 11, 23), 22)
        self.assertEqual(modular_exponentiation(5, 2, 23), 2)

    def test_p65537_accepts_3(self):
        self.assertEqual(prime_factors(65536), {2})
        self.assertEqual(modular_exponentiation(3, 32768, 65537), 65536)
        self.assertTrue(is_generator(3, 65537))

    def test_out_of_range_candidates_rejected(self):
        self.assertFalse(is_generator(1, 23))
        self.assertFalse(is_generator(22, 23))
        self.assertFalse(is_generator(0, 23))

    def test_find_generator_matches_brute_force_order(self):
        for p in (23, 29, 31, 101, 65537):
            g = find_generator(p)
            seen = {modular_exponentiation(g, k, p) for k in range(1, p)}
            self.assertEqual(len(seen), p - 1, f"g={g} is not primitive mod {p}")

    def test_incomplete_factor_set_is_wrong(self):
        # Checking only r = 11 for p = 23 would wrongly accept 2 (whose order is 11):
        # 2^(22/11) = 4 != 1, but the missing r = 2 check gives 2^11 = 1.
        self.assertTrue(is_generator(2, 23, factors={11}))
        self.assertFalse(is_generator(2, 23))


class TestKeyAgreementFixture(unittest.TestCase):
    def test_handout_fixture(self):
        p, g, a, b = 23, 5, 6, 15
        _, A = generate_dh_keypair(p, g, a)
        _, B = generate_dh_keypair(p, g, b)
        self.assertEqual((A, B), (8, 19))
        self.assertEqual(compute_shared_secret(B, a, p), 2)
        self.assertEqual(compute_shared_secret(A, b, p), 2)

    def test_eve_fixture(self):
        p = 23
        self.assertEqual(modular_exponentiation(5, 3, p), 10)
        self.assertEqual(modular_exponentiation(5, 7, p), 17)
        self.assertEqual(modular_exponentiation(10, 6, p), 6)
        self.assertEqual(modular_exponentiation(8, 3, p), 6)
        self.assertEqual(modular_exponentiation(17, 15, p), 15)
        self.assertEqual(modular_exponentiation(19, 7, p), 15)

    def test_random_keypair_in_range(self):
        for _ in range(200):
            x, X = generate_dh_keypair(23, 5)
            self.assertTrue(2 <= x <= 21)
            self.assertTrue(2 <= X <= 21)


if __name__ == "__main__":
    unittest.main()
