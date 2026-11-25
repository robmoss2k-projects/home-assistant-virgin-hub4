"""Draft maintenance actions; never return configuration bytes through a HA action."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import os
from pathlib import Path
import re
from secrets import token_hex
import stat
from time import monotonic
from typing import Any

from .client import MAX_BACKUP_BYTES, HubClient, HubError, InvalidResponse
from .modem_mode import hub_identity
from .parser import parse_script_group, seconds

OPERATIONS = ("reboot", "restore", "factory_reset")
PLAN_TTL = 600
_FILENAME = re.compile(r"[a-zA-Z0-9_-][a-zA-Z0-9._-]{0,100}\.(?:cfg|xml)\Z")


def _directory(root: Path, *, create: bool = False) -> Path:
    if root.is_symlink() or root.parent.is_symlink():
        raise ValueError("The private Hub configuration directory must not be a symlink")
    if create:
        root.parent.mkdir(mode=0o700, exist_ok=True)
        root.mkdir(mode=0o700, exist_ok=True)
    if not root.is_dir():
        raise ValueError("The private Hub configuration directory has not been created")
    return root


def read_configuration_file(root: Path, filename: str) -> bytes:
    """Read one bounded regular file from the entry's private staging directory."""
    if not _FILENAME.fullmatch(filename) or ".." in filename:
        raise ValueError("Supply a local .cfg or .xml filename, not a path")
    file = _directory(root) / filename
    if file.is_symlink() or not file.is_file():
        raise ValueError("The named configuration is not a regular file in this Hub's directory")
    fd = os.open(file, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("The chosen configuration is not a regular file")
        data = stream.read(MAX_BACKUP_BYTES + 1)
    if not 1 <= len(data) <= MAX_BACKUP_BYTES:
        raise ValueError("The configuration file is empty or exceeds the size limit")
    return data


def write_configuration_file(root: Path, content: bytes, extension: str) -> dict[str, Any]:
    """Persist the opaque Hub file without overwriting a file or exposing its contents."""
    if extension not in (".xml", ".cfg") or not 1 <= len(content) <= MAX_BACKUP_BYTES:
        raise ValueError("The downloaded configuration type or size is not supported")
    file = _directory(root, create=True) / f"hub4-{token_hex(12)}{extension}"
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(file, flags, mode=0o600), "wb") as stream:
        stream.write(content)
    return {"filename": file.name, "size": len(content), "sha256": sha256(content).hexdigest()}


async def read_maintenance_identity(hub: HubClient) -> dict[str, Any]:
    state = parse_script_group("device", await hub.read_script("device"))
    firmware = state.get("swVersion")
    if not isinstance(firmware, str) or not firmware:
        raise InvalidResponse("The Hub did not report its firmware version")
    return {
        "identity": hub_identity(state),
        "firmware": firmware,
        "uptime_seconds": seconds(state.get("systemUptime")),
    }


def _recheck(expected: dict[str, Any], observed: dict[str, Any]) -> None:
    if expected["identity"] != observed["identity"] or expected["firmware"] != observed["firmware"]:
        raise ValueError("The Hub identity or firmware changed; no maintenance request sent")


@dataclass(frozen=True)
class MaintenancePlan:
    id: str
    host: str
    operation: str
    identity: str
    firmware: str
    old_uptime: int | None
    filename: str | None
    digest: str | None
    expires: float

    @classmethod
    def create(
        cls,
        operation: str,
        host: str,
        state: dict[str, Any],
        filename: str | None,
        content: bytes | None,
    ) -> MaintenancePlan:
        if operation not in OPERATIONS:
            raise ValueError("Choose reboot, restore or factory reset")
        if (operation == "restore") != (filename is not None and content is not None):
            raise ValueError("Provide a configuration filename only when preparing a restore")
        return cls(
            token_hex(16),
            host,
            operation,
            state["identity"],
            state["firmware"],
            state["uptime_seconds"],
            filename,
            sha256(content).hexdigest() if content else None,
            monotonic() + PLAN_TTL,
        )

    def validate(self, plan_id: str, host: str, confirmed: bool) -> None:
        if plan_id != self.id or host != self.host or monotonic() >= self.expires:
            raise ValueError(
                "This maintenance plan is missing, stale or for another address; prepare again"
            )
        if confirmed is not True:
            raise ValueError("Confirm that someone at the Hub can recover access")


async def run_maintenance(hub: HubClient, group: str, changes: dict[str, Any]) -> dict[str, Any]:
    observed = await read_maintenance_identity(hub)
    if group == "maintenance_state":
        if changes.get("operation") == "factory_reset":
            hub.require_local_reset()
        return {"status": "read", **observed}
    if group == "maintenance_backup":
        if changes["identity"] != observed["identity"]:
            raise ValueError("The current address did not identify the configured Hub")
        content, extension = await hub.download_configuration()
        return {"status": "downloaded", "content": content, "extension": extension}
    _recheck(changes, observed)
    try:
        if changes["operation"] == "restore":
            result = await hub.upload_configuration(changes["filename"], changes["content"])
        else:
            result = await hub.submit_maintenance(changes["operation"])
    except InvalidResponse:
        raise
    except HubError as exc:
        return {"status": "submission_uncertain", "write_issue": type(exc).__name__}
    return {
        "status": result,
        "verification_required": result in ("submitted", "submission_uncertain"),
    }
