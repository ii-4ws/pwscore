"""Typer CLI.

    pwscore 'some password'
    pwscore -i                         # interactive, read from prompt
    pwscore --json 'some password'     # machine-readable
    pwscore --offline 'some password'  # skip the HIBP lookup

Exit code is 0 for strong/fair and 1 for weak, so the CLI fits into scripts
and pre-commit hooks.
"""

from __future__ import annotations

import getpass
import json
import sys
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from pwscore.analyzer import analyze_sync
from pwscore.models import AnalysisResult, Verdict

app = typer.Typer(add_completion=False, no_args_is_help=True, help=__doc__)
console = Console()

_VERDICT_STYLE = {
    Verdict.weak: "bold red",
    Verdict.fair: "bold yellow",
    Verdict.strong: "bold green",
}


def _render(result: AnalysisResult) -> None:
    header = Text()
    header.append("verdict: ", style="dim")
    header.append(result.verdict.value.upper(), style=_VERDICT_STYLE[result.verdict])
    header.append(f"   length: {result.length}")
    console.print(header)

    table = Table(title="scores (bits)", show_header=True, header_style="bold")
    table.add_column("signal", style="cyan")
    table.add_column("value", justify="right")
    table.add_row("charset (naive)", f"{result.entropy.charset_bits:.1f}")
    table.add_row("shannon (observed)", f"{result.entropy.shannon_bits:.1f}")
    table.add_row("markov (rockyou)", f"{result.entropy.markov_bits:.1f}")
    table.add_row("zxcvbn log2(guesses)", f"{result.entropy.zxcvbn_log2_guesses:.1f}")
    console.print(table)

    flags = Table(title="flags", show_header=True, header_style="bold")
    flags.add_column("signal", style="cyan")
    flags.add_column("value")
    flags.add_row(
        "hibp breach count", f"{result.flags.hibp_count:,}" if result.flags.hibp_pwned else "0"
    )
    flags.add_row("in rockyou top-10k", "yes" if result.flags.in_common_wordlist else "no")
    flags.add_row("zxcvbn score", f"{result.flags.zxcvbn_score}/4")
    flags.add_row("zxcvbn crack time", result.flags.zxcvbn_crack_time)
    console.print(flags)

    if result.reasons:
        console.print("[bold]reasons:[/bold]")
        for r in result.reasons:
            console.print(f"  • {r}")

    if result.flags.zxcvbn_suggestions:
        console.print("[bold]suggestions:[/bold]")
        for s in result.flags.zxcvbn_suggestions:
            console.print(f"  • {s}")


@app.command()
def main(
    password: Annotated[
        str | None,
        typer.Argument(
            help=(
                "The password to analyze. Omit with --interactive to be prompted "
                "without showing it in the terminal."
            ),
            show_default=False,
        ),
    ] = None,
    interactive: Annotated[
        bool,
        typer.Option(
            "--interactive",
            "-i",
            help="Prompt for the password without echoing it.",
        ),
    ] = False,
    json_out: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Emit a JSON document instead of a human-readable report.",
        ),
    ] = False,
    offline: Annotated[
        bool,
        typer.Option(
            "--offline",
            help="Skip the HaveIBeenPwned network lookup.",
        ),
    ] = False,
) -> None:
    if password is None and not interactive:
        console.print(
            "[red]error:[/red] provide a password argument or use --interactive.",
            style="red",
        )
        raise typer.Exit(code=2)

    if interactive:
        password = getpass.getpass("password: ")

    assert password is not None
    result = analyze_sync(password, skip_hibp=offline)

    if json_out:
        typer.echo(json.dumps(result.model_dump(mode="json"), indent=2))
    else:
        _render(result)

    sys.exit(1 if result.is_weak else 0)


if __name__ == "__main__":
    app()
