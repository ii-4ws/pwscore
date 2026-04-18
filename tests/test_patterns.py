from pwscore.checks.patterns import find_patterns


class TestPatterns:
    def test_empty(self) -> None:
        assert find_patterns("") == []

    def test_runs_detected(self) -> None:
        reasons = find_patterns("aaaabbb")
        assert any("run" in r for r in reasons)

    def test_keyboard_walk_detected(self) -> None:
        reasons = find_patterns("qwerty123")
        assert any("keyboard" in r or "numeric" in r for r in reasons)

    def test_digit_sequence_detected(self) -> None:
        reasons = find_patterns("abcd1234")
        assert any("1234" in r for r in reasons)

    def test_date_detected(self) -> None:
        reasons = find_patterns("Summer2024!")
        assert any("year-like" in r for r in reasons)

    def test_all_digits_detected(self) -> None:
        reasons = find_patterns("8675309")
        assert any("entirely digits" in r for r in reasons)

    def test_leet_decode_catches_passw0rd(self) -> None:
        reasons = find_patterns("P@ssw0rd!")
        assert any("password" in r.lower() for r in reasons)

    def test_strong_random_no_reasons(self) -> None:
        assert find_patterns("Xq7!mZ#pLwRt$") == []
