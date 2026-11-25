"""Guard a disruptive router/modem transition and report what is actually known."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import re
from secrets import token_urlsafe
from time import monotonic
from typing import Any

from .client import (
    HubClient,
    HubError,
    InvalidResponse,
    UnsupportedHub,
    _maintenance_reply,
    normalize_host,
)
from .const import DEFAULT_HOST, HUB_MODES, MODEM_HOST
from .parser import parse_script_group

PLAN_SECONDS = 600


def hub_identity(device: dict[str, Any]) -> str:
    mac = re.sub(r"[^A-Fa-f0-9]", "", str(device.get("cmMac", ""))).lower()
    if len(mac) != 12 or int(mac, 16) == 0:
        raise UnsupportedHub("The Hub did not provide a stable device identity")
    return sha256(("virgin_hub4:" + mac).encode()).hexdigest()[:32]


def verify_hub_identity(device: dict[str, Any], expected: str | None) -> None:
    """Reject an address serving a different unit without exposing either MAC."""
    if not expected or hub_identity(device) != expected:
        raise InvalidResponse(
            "The management address does not identify the configured Hub; check its address"
        )


async def read_mode(client: HubClient) -> str:
    values = parse_script_group("mode", await client.read_script("mode"))
    if mode := HUB_MODES.get(str(values["RouterMode"])):
        return mode
    raise InvalidResponse("The Hub did not report a recognised router or modem mode")


async def read_mode_identity(client: HubClient, *, for_switch: bool = False) -> dict[str, str]:
    mode = await read_mode(client)
    device = parse_script_group("device", await client.read_script("device"))
    if for_switch and not (await client.read_portal_provisioning()).allows("mode_submit"):
        raise ValueError("The portal hides modem-mode switching under DS-Lite")
    return {"mode": mode, "identity": hub_identity(device)}


@dataclass(frozen=True)
class ModePlan:
    id: str
    host: str
    target_host: str
    current_mode: str
    target_mode: str
    identity: str
    expires: float

    @classmethod
    def create(
        cls,
        host: str,
        observed: dict[str, str],
        target_mode: str,
        router_host: str | None,
    ) -> ModePlan:
        if target_mode not in HUB_MODES.values() or target_mode == observed["mode"]:
            raise ValueError("Choose the opposite operating mode")
        if router_host is not None and target_mode != "router":
            raise ValueError(
                "Supply a router management address only when returning to router mode"
            )
        target_host = (
            MODEM_HOST if target_mode == "modem" else normalize_host(router_host or DEFAULT_HOST)
        )
        if target_host == host:
            raise ValueError("The current and destination management addresses must be different")
        return cls(
            token_urlsafe(16),
            host,
            target_host,
            observed["mode"],
            target_mode,
            observed["identity"],
            monotonic() + PLAN_SECONDS,
        )

    def public(self) -> dict[str, Any]:
        return {
            "plan_id": self.id,
            "current_mode": self.current_mode,
            "target_mode": self.target_mode,
            "current_management_address": self.host,
            "expected_management_address": self.target_host,
        }

    def validate(self, plan_id: str, host: str, confirmed: bool) -> None:
        if plan_id != self.id or host != self.host or monotonic() >= self.expires:
            raise ValueError(
                "This operating mode plan is missing, stale or for another address; prepare again"
            )
        if confirmed is not True:
            raise ValueError("Confirm that someone is at the Hub with a local recovery path")


async def submit_mode(client: HubClient, prepared: dict[str, str]) -> dict[str, Any]:
    now = await read_mode_identity(client, for_switch=True)
    if now["identity"] != prepared["identity"] or now["mode"] != prepared["current_mode"]:
        raise ValueError(
            "The Hub identity or operating mode changed since preparation; no request sent"
        )
    target = prepared["target_mode"]
    if target not in HUB_MODES.values() or target == now["mode"]:
        raise ValueError("The target must be the opposite operating mode")
    try:
        reply = await client.submit_operating_mode(modem=target == "modem")
    except HubError as err:
        return {
            "status": "submission_uncertain",
            "verification_required": True,
            "write_issue": type(err).__name__,
        }
    if reply == "Wait for modem init":
        return {
            "status": "not_submitted",
            "reason": "The Hub reports that modem initialisation is not complete",
        }
    outcome = _maintenance_reply(reply)
    if outcome in {"rejected", "file_rejected"}:
        return {"status": "rejected", "verification_required": False}
    # A vanished socket, successful status code or old cached mode cannot say
    # that the requested mode was applied. Verify separately at the new address.
    return {"status": "submission_uncertain", "verification_required": True}
