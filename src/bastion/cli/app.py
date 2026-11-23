"""The ``bastion`` command."""

from typing import Annotated

import typer

from bastion import __version__
from bastion.cli import admin, chat, setup

app = typer.Typer(
    name="bastion",
    help="A secure, always-on personal AI agent.",
    no_args_is_help=True,
    add_completion=False,
)


def _print_version(value: bool) -> None:
    if value:
        typer.echo(f"bastion {__version__}")
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
    """Bastion: the system, not the model, decides what the agent may do."""


app.command("init")(setup.init)
app.command("chat")(chat.chat)
app.add_typer(admin.audit_app, name="audit")
app.add_typer(admin.secrets_app, name="secrets")
app.add_typer(admin.policy_app, name="policy")
