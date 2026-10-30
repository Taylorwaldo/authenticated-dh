"""Prime-generator integration tests: the wrapper and validation behavior.

These test OUR wrapper and validation logic, not the library's internal
primality algorithm.
"""

import unittest

from Crypto.Util.number import isPrime

from parameters import (
    BIT_RANGE_ERROR,
    ParameterError,
    allowed_prime_range,
    generate_parameters,
    generate_prime,
    generate_prime_timed,
    is_generator,
    parse_bit_length_input,
    validate_bit_length,
    validate_received_modulus,
)


class TestGeneratePrime(unittest.TestCase):
    def test_exact_bit_length_and_oddness_all_sizes(self):
        for bits in range(16, 33):
            with self.subTest(bits=bits):
                p = generate_prime(bits)
                self.assertEqual(p.bit_length(), bits)
                self.assertIn(p, allowed_prime_range(bits))
                self.assertEqual(p % 2, 1)
                self.assertTrue(isPrime(p))  # library validation of returned primes

    def test_default_is_16_bits(self):
        p = generate_prime()
        self.assertEqual(p.bit_length(), 16)
        self.assertTrue(32768 <= p <= 65535)

    def test_timed_wrapper(self):
        p, seconds = generate_prime_timed(24)
        self.assertEqual(p.bit_length(), 24)
        self.assertGreaterEqual(seconds, 0.0)

    def test_invalid_requested_sizes(self):
        for bad in (12, 15, 33, 0, -16, 1024):
            with self.subTest(bits=bad), self.assertRaises(ParameterError) as ctx:
                generate_prime(bad)
            self.assertEqual(str(ctx.exception), BIT_RANGE_ERROR)

    def test_boolean_and_noninteger_sizes(self):
        for bad in (True, False, 16.0, "16", None, [16]):
            with self.subTest(bits=bad), self.assertRaises(ParameterError):
                generate_prime(bad)

    def test_user_input_parsing(self):
        self.assertEqual(parse_bit_length_input("16"), 16)
        self.assertEqual(parse_bit_length_input(" 32 "), 32)
        for bad in ("12", "33", "16.5", "16.0", "abc", "", "true"):
            with self.subTest(text=bad), self.assertRaises(ParameterError):
                parse_bit_length_input(bad)

    def test_allowed_range_example(self):
        r = allowed_prime_range(16)
        self.assertEqual((r.start, r.stop - 1), (32768, 65535))
        self.assertEqual(validate_bit_length(16), 16)

    def test_generate_parameters_produces_valid_generator(self):
        for bits in (16, 24, 32):
            params = generate_parameters(bits)
            self.assertEqual(params.p.bit_length(), bits)
            self.assertTrue(is_generator(params.g, params.p))
            self.assertGreaterEqual(params.factorization_seconds, 0.0)


class TestReceivedModulusValidation(unittest.TestCase):
    def test_rejects_composite_32769(self):
        with self.assertRaises(ParameterError):
            validate_received_modulus(32769)  # 32769 = 3 * 10923; 16 bits, odd

    def test_accepts_generated_prime(self):
        p = generate_prime(20)
        self.assertEqual(validate_received_modulus(p), p)

    def test_accepts_65537(self):
        self.assertEqual(validate_received_modulus(65537), 65537)

    def test_rejects_wrong_types(self):
        for bad in ("65537", 65537.0, True, None, [65537]):
            with self.subTest(p=bad), self.assertRaises(ParameterError):
                validate_received_modulus(bad)

    def test_rejects_out_of_range_sizes(self):
        for bad in (23, 32749, 2 ** 32 + 15, 2 ** 61 - 1):  # 2^61-1 is prime but too big
            with self.subTest(p=bad), self.assertRaises(ParameterError):
                validate_received_modulus(bad)

    def test_fixture_path_allows_23_but_still_checks_primality(self):
        self.assertEqual(validate_received_modulus(23, allow_fixture=True), 23)
        with self.assertRaises(ParameterError):
            validate_received_modulus(21, allow_fixture=True)  # composite fixture
        with self.assertRaises(ParameterError):
            validate_received_modulus(3, allow_fixture=True)   # too small for 2..p-2

    def test_library_fixture_values(self):
        self.assertTrue(isPrime(23))
        self.assertFalse(isPrime(21))


if __name__ == "__main__":
    unittest.main()
