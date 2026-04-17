from pwscore.entropy.markov import markov_bits_per_char, markov_entropy


class TestMarkov:
    def test_empty(self) -> None:
        assert markov_entropy("") == 0.0
        assert markov_bits_per_char("") == 0.0

    def test_common_passwords_score_low(self) -> None:
        # Popular leaked passwords should cost an attacker very few bits.
        weak = ["password", "123456", "qwerty", "iloveyou", "letmein"]
        scores = [markov_entropy(p) for p in weak]
        for s, p in zip(scores, weak, strict=True):
            # Even if the model disagrees on exact value, all of these should
            # score meaningfully below a typical random 8-char string.
            assert s < 40, f"{p!r} scored too high: {s}"

    def test_random_string_scores_high(self) -> None:
        # A 12-char string drawn from many bigrams not in breach training
        # data should land well above common passwords.
        assert markov_entropy("Xq7!mZ#p9kLw") > 60

    def test_random_string_beats_common(self) -> None:
        assert markov_entropy("Xq7!mZ#p9kLw") > markov_entropy("password")

    def test_longer_same_pattern_scores_higher(self) -> None:
        # Additional random chars add entropy.
        assert markov_entropy("Xq7!mZ#p9kLwRt$2") > markov_entropy("Xq7!mZ#p9kLw")
