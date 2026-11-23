"""``bastion init``: choose a model provider and store keys in the OS keyring.

API keys are only ever read from a hidden prompt. They are never accepted as command-line
arguments, which would leak into shell history and process listings.
"""

import os
from contextlib import closing
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape

from bastion.cli import deps
from bastion.config import (
    CONFIG_FILE,
    DATABASE_FILE,
    POLICY_FILE,
    Effort,
    LLMSettings,
    Settings,
    bastion_home,
    render_config,
)
from bastion.llm.factory import PRESETS, ProviderConfigError, validate_base_url
from bastion.runtime import open_audit_log
from bastion.security.policy import DEFAULT_POLICY_TOML
from bastion.security.redact import Redactor
from bastion.security.vault import (
    AUDIT_KEY,
    BRAVE_API_KEY,
    STORAGE_KEY,
    Vault,
    VaultError,
    llm_api_key,
)
from bastion.storage.db import connect


def _choose_provider(provider: str | None) -> str:
    if provider is not None:
        if provider not in PRESETS:
            raise typer.BadParameter(
                f"choose one of: {', '.join(PRESETS)}", param_hint="--provider"
            )
        return provider
    while True:
        answer = str(typer.prompt(f"LLM provider ({', '.join(PRESETS)})", default="anthropic"))
        if answer.strip().lower() in PRESETS:
            return answer.strip().lower()
        typer.echo("Unknown provider.")


def _choose_llm(provider: str | None, model: str | None, base_url: str | None) -> LLMSettings:
    name = _choose_provider(provider)
    preset = PRESETS[name]
    if model is None:
        model = (
            typer.prompt("Model", default=preset.default_model)
            if preset.default_model
            else typer.prompt("Model (exactly as your provider names it)")
        )
    if name == "custom" and base_url is None:
        base_url = typer.prompt("API base URL (https://...)")
    if base_url is not None:
        try:
            validate_base_url(base_url)
        except ProviderConfigError as exc:
            raise typer.BadParameter(str(exc), param_hint="--base-url") from exc
    effort: Effort | None = "medium" if preset.kind == "anthropic" else None
    return LLMSettings(provider=name, model=model.strip(), base_url=base_url, effort=effort)


def _store_llm_key(vault: Vault, provider: str) -> None:
    if not PRESETS[provider].needs_key:
        return
    name = llm_api_key(provider)
    if vault.get(name) and not typer.confirm(
        f"A {provider} API key is already stored. Replace it?", default=False
    ):
        return
    vault.set(name, typer.prompt(f"{provider} API key (input hidden)", hide_input=True).strip())


def _store_search_key(vault: Vault) -> None:
    if vault.get(BRAVE_API_KEY):
        return
    key = typer.prompt(
        "Brave Search API key for web search (hidden; press Enter to skip)",
        default="",
        show_default=False,
        hide_input=True,
    ).strip()
    if key:
        vault.set(BRAVE_API_KEY, key)


def _create_home(home: Path) -> None:
    home.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        home.chmod(0o700)


def init(
    provider: Annotated[
        str | None, typer.Option(help="LLM provider, e.g. anthropic or ollama.")
    ] = None,
    model: Annotated[str | None, typer.Option(help="Model name.")] = None,
    base_url: Annotated[str | None, typer.Option(help="API base URL (custom providers).")] = None,
    force: Annotated[bool, typer.Option("--force", help="Reconfigure an existing setup.")] = False,
) -> None:
    """Set up Bastion: pick a model provider and store keys in the OS keyring."""
    console = Console()
    home = bastion_home()
    if (home / CONFIG_FILE).exists() and not force:
        console.print(
            f"Bastion is already set up in {escape(str(home))}. Use --force to reconfigure."
        )
        raise typer.Exit(1)
    llm = _choose_llm(provider, model, base_url)
    vault = Vault(deps.secret_store(), Redactor())
    try:
        _store_llm_key(vault, llm.provider)
        _store_search_key(vault)
        vault.key(AUDIT_KEY, create=True)
        vault.key(STORAGE_KEY, create=True)
    except VaultError as exc:
        console.print(f"[red]Could not store secrets:[/] {escape(str(exc))}")
        raise typer.Exit(1) from exc
    _create_home(home)
    (home / CONFIG_FILE).write_text(render_config(Settings(llm=llm)), encoding="utf-8")
    if not (home / POLICY_FILE).exists():
        (home / POLICY_FILE).write_text(DEFAULT_POLICY_TOML, encoding="utf-8")
    with closing(connect(home / DATABASE_FILE)) as conn:
        open_audit_log(conn, vault, Redactor()).append(
            "setup.init", {"provider": llm.provider, "model": llm.model}, checkpoint=True
        )
    console.print(
        f"[green]Ready.[/] Configuration is in {escape(str(home))}; secrets are in the OS keyring."
    )
    console.print("Next: [bold]bastion chat[/]")
