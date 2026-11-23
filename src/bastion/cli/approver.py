"""Terminal approval prompt (control C4).

Shows exactly what will run (tool, risk, why approval is needed, and the exact arguments the
approval is bound to), with invisible characters made visible. The default is always "deny".
Step-up actions require typing the tool name, so a reflexive "y" is not enough; Telegram adds a
TOTP code for these.
"""

from collections.abc import Callable

from rich.console import Console, Group
from rich.panel import Panel
from rich.syntax import Syntax
from rich.text import Text

from bastion.security.approvals import ApprovalRequest
from bastion.text import reveal_invisible


def _panel(request: ApprovalRequest) -> Panel:
    body = Group(
        Text(reveal_invisible(request.summary), style="bold"),
        Text(f"Risk: {request.tier.value}"),
        Text(f"Why you are asked: {reveal_invisible(request.reason)}"),
        Syntax(reveal_invisible(request.arguments_json), "json", word_wrap=True, theme="ansi_dark"),
        Text(f"Request {request.id[:8]}, expires {request.expires_at:%H:%M:%S} UTC", style="dim"),
    )
    return Panel(body, title="Approval needed", border_style="yellow")


class ConsoleApprover:
    def __init__(self, console: Console, ask: Callable[[str], str] | None = None) -> None:
        self._console = console
        self._ask = ask or (lambda prompt: console.input(prompt, markup=False))

    async def request_approval(self, request: ApprovalRequest) -> bool:
        self._console.print(_panel(request))
        # Deliberately blocking: in the single-user terminal nothing else runs while the owner
        # decides, and reading on the main thread keeps Ctrl+C reliable.
        if request.step_up:
            prompt = (
                f"This is a {request.tier.value} action. "
                f"Type {request.tool} to approve, anything else to deny: "
            )
            return self._ask(prompt).strip() == request.tool
        return self._ask("Approve? [y/N] ").strip().lower() in {"y", "yes"}
