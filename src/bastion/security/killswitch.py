"""The kill switch (control C11).

``/stop`` from Telegram engages it: the running request is cancelled and the always-on agent
refuses all work. Only the owner *at the computer* can release it (``bastion resume``), so a
hijacked Telegram account can stop the agent but never restart it.

The switch is a file in the Bastion home directory, so it survives restarts and is visible to
every process (the daemon checks it on each message).
"""

from datetime import datetime
from pathlib import Path

STOP_FILE = "STOPPED"


class KillSwitch:
    def __init__(self, home: Path) -> None:
        self._path = home / STOP_FILE

    def engaged(self) -> bool:
        return self._path.exists()

    def engage(self, *, via: str, at: datetime) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(f"stopped {at.isoformat()} via {via}\n", encoding="utf-8")

    def release(self) -> bool:
        """Release the switch; returns whether it was engaged."""
        engaged = self.engaged()
        self._path.unlink(missing_ok=True)
        return engaged
