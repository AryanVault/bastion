"""Command-line entry point for Warden."""

from typing import Annotated

import typer

from warden import __version__

app = typer.Typer(
    name="warden",
    help="A secure, always-on personal AI agent.",
    no_args_is_help=True,
    add_completion=False,
)


def _print_version(value: bool) -> None:
    if value:
        typer.echo(f"warden {__version__}")
        raise typer.Exit


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_print_version,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = False,
) -> None:
    """Warden: the system, not the model, decides what the agent may do."""
