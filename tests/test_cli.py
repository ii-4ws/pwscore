import json

from typer.testing import CliRunner

from pwscore.cli import app

runner = CliRunner()


class TestCli:
    def test_help(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "password" in result.stdout.lower()

    def test_weak_password_exits_1(self) -> None:
        result = runner.invoke(app, ["--offline", "password"])
        assert result.exit_code == 1
        assert "WEAK" in result.stdout

    def test_strong_password_exits_0(self) -> None:
        result = runner.invoke(app, ["--offline", "Xq7!mZ#p9kLwRt$2pL-7bNx"])
        assert result.exit_code == 0
        # Fair or strong both accepted.
        assert "WEAK" not in result.stdout

    def test_json_output_is_valid(self) -> None:
        result = runner.invoke(app, ["--offline", "--json", "password"])
        assert result.exit_code == 1
        payload = json.loads(result.stdout)
        assert payload["verdict"] == "weak"
        assert "entropy" in payload and "flags" in payload

    def test_no_arg_errors(self) -> None:
        result = runner.invoke(app, [])
        # No args and no --interactive: show help + nonzero exit.
        assert result.exit_code != 0
