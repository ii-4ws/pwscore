from pwscore.checks.zxcvbn_wrap import run_zxcvbn


class TestZxcvbnWrap:
    def test_empty(self) -> None:
        r = run_zxcvbn("")
        assert r.score == 0
        assert r.guesses == 0.0

    def test_weak_password_low_score(self) -> None:
        r = run_zxcvbn("password")
        assert r.score <= 1
        assert "password" in r.warning.lower() or r.warning != ""

    def test_strong_password_high_score(self) -> None:
        r = run_zxcvbn("correct horse battery staple")
        assert r.score >= 3
        assert r.guesses_log2 > 30

    def test_random_string_high_score(self) -> None:
        r = run_zxcvbn("Xq7!mZ#p9kLwRt$2")
        assert r.score >= 3
