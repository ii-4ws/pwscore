from pwscore.checks.wordlist import is_common, is_common_case_insensitive


class TestWordlist:
    def test_empty(self) -> None:
        assert is_common("") is False

    def test_top_entry_hits(self) -> None:
        assert is_common("password") is True
        assert is_common("123456") is True
        assert is_common("qwerty") is True

    def test_random_misses(self) -> None:
        assert is_common("Xq7!mZ#p9kLwRt$2pL-7bN") is False

    def test_case_insensitive_catches_trivial_variants(self) -> None:
        # Plain "password" should be in the top-10k list. "Password" (upper P)
        # is trivially equivalent for an attacker running rule-based cracking.
        assert is_common_case_insensitive("Password") is True
