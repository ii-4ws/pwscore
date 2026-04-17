import math

import pytest

from pwscore.entropy.shannon import shannon_bits_per_char, shannon_entropy


class TestShannon:
    def test_empty(self) -> None:
        assert shannon_bits_per_char("") == 0.0
        assert shannon_entropy("") == 0.0

    def test_all_same_char(self) -> None:
        # Pure repetition collapses to zero bits/char.
        assert shannon_bits_per_char("aaaaaaaa") == pytest.approx(0.0)
        assert shannon_entropy("aaaaaaaa") == pytest.approx(0.0)

    def test_uniform_two_chars(self) -> None:
        # "abab" → p(a)=p(b)=0.5 → H = 1 bit/char.
        assert shannon_bits_per_char("abab") == pytest.approx(1.0)
        assert shannon_entropy("abab") == pytest.approx(4.0)

    def test_uniform_four_chars(self) -> None:
        # 4 unique chars equally distributed → 2 bits/char.
        assert shannon_bits_per_char("abcdabcd") == pytest.approx(2.0)

    def test_known_value(self) -> None:
        # "aabbcc" → three chars at p=1/3 each → log2(3).
        assert shannon_bits_per_char("aabbcc") == pytest.approx(math.log2(3))

    def test_aaaaaaaa_defeats_charset_formula(self) -> None:
        # Charset formula would give 8 * log2(26) ~= 37 bits; Shannon gives 0.
        assert shannon_entropy("aaaaaaaa") < 1.0
