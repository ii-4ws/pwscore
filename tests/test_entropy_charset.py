import math

import pytest

from pwscore.entropy.charset import charset_size, naive_charset_entropy


class TestCharsetSize:
    def test_empty(self) -> None:
        assert charset_size("") == 0

    def test_lowercase_only(self) -> None:
        assert charset_size("abcdef") == 26

    def test_uppercase_only(self) -> None:
        assert charset_size("ABCDEF") == 26

    def test_digits_only(self) -> None:
        assert charset_size("123456") == 10

    def test_symbols_only(self) -> None:
        assert charset_size("!@#$%^") == 32

    def test_mixed_alpha(self) -> None:
        assert charset_size("AbCdEf") == 52

    def test_full_pool(self) -> None:
        assert charset_size("Ab1!") == 26 + 26 + 10 + 32


class TestNaiveEntropy:
    def test_empty(self) -> None:
        assert naive_charset_entropy("") == 0.0

    def test_lowercase_known_value(self) -> None:
        # 8 chars * log2(26) == 8 * 4.7004... == 37.603...
        assert naive_charset_entropy("abcdefgh") == pytest.approx(8 * math.log2(26))

    def test_full_pool_matches_textbook(self) -> None:
        # "Password1!" → L=10, N=94 → 10 * log2(94)
        assert naive_charset_entropy("Password1!") == pytest.approx(10 * math.log2(94))

    def test_rates_notoriously_weak_password_as_strong(self) -> None:
        # This is the point: the formula says "Password1!" has ~65.5 bits,
        # which is comfortably above the 30-bit threshold the original
        # script used. The benchmark will turn this misclassification
        # into hard numbers.
        assert naive_charset_entropy("Password1!") > 60
