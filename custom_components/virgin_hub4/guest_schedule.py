"""Portal guest-network timetable and optional explicit identity changes."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from functools import partial
import re
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .client import HubClient, InvalidResponse
from .parser import flag
from .portal import passphrase, require_radio, ssid
from .verification import write_and_verify

# The portal uses the latter two as the primary Wi-Fi keys, not guest-band keys.
GUEST_SETTINGS_CREDENTIAL_FIELDS = ("passphrase", "24Passphrase", "50Passphrase")
_INPUT = re.compile(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:(?:00|30)\Z")
_REPORTED = re.compile(r"\d{2}/\d{2}/\d{4}-\d{2}:\d{2}\Z")


@dataclass(frozen=True, repr=False)
class _Guest:
    enabled: bool
    name: str
    expires: datetime | None
    wizard_key: str
    broadcast: bool
    security: str
    keys: tuple[str | None, ...]

    def public(self) -> dict[str, Any]:
        return _public_timer(self.enabled, self.name, self.expires)


def _public_timer(enabled: bool, name: str, expires: datetime | None) -> dict[str, Any]:
    return {
        "enabled": enabled,
        "network_name": name,
        "expires_at": expires.isoformat(timespec="minutes") if expires else None,
        "expiry_enforcement_verified": False,
    }


def _expiry_from_hub(raw: Any) -> datetime | None:
    if raw == "":
        return None
    if isinstance(raw, str) and _REPORTED.fullmatch(raw):
        try:
            return datetime.strptime(raw, "%d/%m/%Y-%H:%M")
        except ValueError:
            pass
    raise InvalidResponse("The Hub did not report a recognised guest expiry")


async def _read(client: HubClient) -> _Guest:
    timer = await client.read_wifi("guest_expiry")
    wifi = await client.read_wifi("guest")
    enabled = flag(timer.get("EnableGuest"))
    name = timer.get("NetworkName")
    broadcast = flag(wifi.get("broadcast"))
    key = timer.get("GuestWizPassphrase")
    keys = tuple(wifi.get(field) for field in GUEST_SETTINGS_CREDENTIAL_FIELDS)
    security = str(wifi.get("security"))
    if (
        enabled is None
        or enabled != flag(wifi.get("enable"))
        or not isinstance(name, str)
        or name != wifi.get("ssid")
        or broadcast is None
        or not isinstance(key, str)
        or any(k is not None and not isinstance(k, str) for k in keys)
        or security not in {"0", "4", "5"}
    ):
        raise InvalidResponse("The Hub guest wizard and settings page did not agree")
    return _Guest(
        enabled, name, _expiry_from_hub(timer.get("ActiveTimeout")), key, broadcast, security, keys
    )


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _requested_expiry(text: object, zone: str) -> datetime:
    if not isinstance(text, str) or not _INPUT.fullmatch(text):
        raise ValueError("Use YYYY-MM-DD HH:MM and a time on a whole or half hour")
    try:
        naive = datetime.fromisoformat(text)
        timezone_local = ZoneInfo(zone)
    except ValueError, ZoneInfoNotFoundError:
        raise ValueError(
            "Use a real calendar date and a recognised Home Assistant time zone"
        ) from None
    candidates = {
        local.astimezone(timezone.utc)
        for fold in (0, 1)
        if (local := naive.replace(tzinfo=timezone_local, fold=fold))
        .astimezone(timezone.utc)
        .astimezone(timezone_local)
        .replace(tzinfo=None)
        == naive
    }
    if len(candidates) != 1:
        raise ValueError("That local time is skipped or repeated by a clock change")
    if candidates.pop() <= _now():
        raise ValueError("The guest expiry must be in the future")
    return naive


def _plan(
    before: _Guest, changes: dict[str, Any], zone: str
) -> tuple[dict[str, Any] | None, datetime | None]:
    mode = changes.get("mode")
    text = changes.get("expires_at")
    allow_enable = changes.get("enable_if_off", False)
    if (
        mode not in ("always", "until")
        or (text is None) != (mode == "always")
        or type(allow_enable) is not bool
    ):
        raise ValueError("Choose always without a date, or until with an expiry date and time")
    expires = _requested_expiry(text, zone) if mode == "until" else None
    name = ssid(changes["ssid"]) if "ssid" in changes else before.name
    key = before.wizard_key
    replace_key = "passphrase" in changes
    if replace_key:
        primary = before.keys[1:]
        if any(not isinstance(value, str) or (value and set(value) == {"*"}) for value in primary):
            raise ValueError("The Hub did not report verifiable primary Wi-Fi keys")
        key = passphrase(
            changes["passphrase"], open_network=before.security == "0", conflicting=primary
        )
    if (
        before.expires == expires
        and (before.enabled or not allow_enable)
        and name == before.name
        and key == before.wizard_key
        and (not replace_key or key == before.keys[0])
    ):
        return None, expires
    if not before.enabled and not allow_enable:
        raise ValueError(
            "The wizard enables guest Wi-Fi when it applies a schedule; allow that explicitly or enable it first"
        )
    if not name:
        raise ValueError("Set a guest network name before applying its schedule")
    # A timer-only save must preserve an existing usable key. An explicit
    # replacement needs no old guest key: the portal lets the user set one
    # while enabling the guest network for the first time.
    usable = (8 <= len(key) <= 63 and set(key) != {"*"}) or re.fullmatch(r"[0-9a-fA-F]{64}", key)
    reported_key = before.keys[0]
    if not replace_key and (
        (before.security != "0" and (reported_key is None or not usable))
        or (reported_key is not None and reported_key != key)
    ):
        raise ValueError("Unable to prove that the guest wizard will keep the existing passphrases")
    payload = {
        "EnableGuest": "true",
        "NetworkName": name,
        "GuestWizPassphrase": key,
        "GuestTimeBased": expires is not None,
        "timeout": 0,
        "yr": expires.year if expires else 0,
    }
    if expires:
        payload.update(mnt=expires.month, dy=expires.day, hr=expires.hour, min=expires.minute)
    return payload, expires


async def apply_guest_schedule(
    client: HubClient, changes: dict[str, Any], *, zone: str, read_only: bool
) -> dict[str, Any]:
    if read_only:
        timer = await client.read_wifi("guest_expiry")
        enabled, name = flag(timer.get("EnableGuest")), timer.get("NetworkName")
        if enabled is None or not isinstance(name, str):
            raise InvalidResponse("The Hub did not report an identifiable guest Wi-Fi schedule")
        return {
            "status": "read",
            **_public_timer(enabled, name, _expiry_from_hub(timer.get("ActiveTimeout"))),
        }
    before = await _read(client)
    payload, expires = _plan(before, changes, zone)
    if payload is None:
        return {"status": "unchanged", **before.public()}
    if any(
        not isinstance(value, str) or (value and set(value) == {"*"}) for value in before.keys[1:]
    ):
        raise ValueError("The Hub did not report verifiable primary Wi-Fi keys")
    await require_radio(client)
    expected_key = payload["GuestWizPassphrase"]

    def matches(latest: _Guest) -> bool:
        return (
            latest.enabled
            and latest.expires == expires
            and latest.name == payload["NetworkName"]
            and latest.broadcast == before.broadcast
            and latest.security == before.security
            and latest.wizard_key == expected_key
            and latest.keys == (expected_key, *before.keys[1:])
        )

    checked = await write_and_verify(
        partial(client.write_guest_schedule, payload),
        partial(_read, client),
        matches,
    )
    latest = checked.latest
    if checked.verified and latest is not None:
        # A recorded date doesn't prove the real radio will disable at that time.
        return {
            "status": "recorded",
            **latest.public(),
            **({"write_issue": checked.write_issue} if checked.write_issue else {}),
        }
    return {
        "status": "unverified",
        "write_issue": checked.write_issue,
        "readback": latest.public() if latest else None,
    }
