"""Preferences the signed-in Hub portal actually submits to the router."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from functools import partial
import re
from typing import Any
import unicodedata

from .client import HubClient, InvalidResponse
from .mac_rules import normalise_mac
from .parser import parse_clients
from .verification import write_and_verify

_LANGUAGE = re.compile(r"[a-z]{2}(?:-[a-z]{2})?\Z")


def decode_languages(active: dict[str, Any], available: dict[str, Any]) -> dict[str, Any]:
    """Reflect the Hub's actual choices rather than the shared GUI's known translations."""
    code = active.get("lang")
    choices = available.get("availableLang")
    if not isinstance(code, str) or not isinstance(choices, str):
        raise InvalidResponse("The Hub did not report the portal language and available languages")
    codes = list(dict.fromkeys(code.strip().lower() for code in choices.split(",")))
    current = code.strip().lower()
    if current not in codes or any(not _LANGUAGE.fullmatch(item) for item in codes):
        raise InvalidResponse("The Hub did not report a valid portal language list")
    return {"language": current, "available_languages": codes}


async def _languages(client: HubClient) -> dict[str, Any]:
    return decode_languages(
        await client.read_portal_language(choices=False),
        await client.read_portal_language(choices=True),
    )


def _labels(data: dict[str, Any]) -> dict[str, set[str]]:
    labels: dict[str, set[str]] = {}
    for row in parse_clients(data):
        try:
            mac = normalise_mac(row.get("mac", ""))
        except ValueError, TypeError:
            continue
        name = row.get("friendly_name", "")
        if not isinstance(name, str):
            raise InvalidResponse("The Hub returned an invalid saved device label")
        labels.setdefault(mac, set()).add(name)
    return labels


def _check_label(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("Provide a device label or an empty string to clear it")
    if (
        len(value.encode("utf-16-le", errors="surrogatepass")) // 2 > 30
        or any(unicodedata.category(c) in ("Cc", "Cs") for c in value)
        or any(marker in value.lower() for marker in ("<", ">", ".src"))
    ):
        raise ValueError(
            "Device labels must be at most 30 characters with no HTML or control characters"
        )
    return value


async def _apply_then_read(
    write: Callable[[], Awaitable[None]], verify: Callable[[], Awaitable[dict[str, Any] | None]]
) -> dict[str, Any]:
    checked = await write_and_verify(write, verify, lambda _: True)
    if checked.verified and checked.latest is not None:
        return {"status": "verified", **checked.latest}
    return {"status": "unverified", "write_issue": checked.write_issue}


async def apply_preference(
    client: HubClient, group: str, changes: dict[str, Any]
) -> dict[str, Any]:
    if group == "device_label":
        mac = normalise_mac(changes["mac"])
        label = _check_label(changes["label"])
        before = _labels(await client.read_clients())
        if not before.get(mac):
            raise ValueError("The Hub no longer lists this MAC address among associated devices")
        if len(before[mac]) > 1:
            raise ValueError("The Hub reported ambiguous labels for this MAC address")
        if before[mac] == {label}:
            return {"status": "unchanged", "label": label, "mac": mac}

        async def verify_label():
            after = _labels(await client.read_clients())
            collateral = any(
                before[k] != after[k] for k in before.keys() & after.keys() if k != mac
            )
            if not collateral and after.get(mac) == {label}:
                return {"label": label, "mac": mac}
            return None

        return await _apply_then_read(partial(client.write_device_label, mac, label), verify_label)

    before = await _languages(client)
    if group == "portal_language_read":
        return {"status": "read", **before}
    language = changes["language"].strip().lower()
    if language not in before["available_languages"]:
        raise ValueError("This language is not offered by the Hub portal")
    if language == before["language"]:
        return {"status": "unchanged", **before}

    async def verify_language():
        after = await _languages(client)
        return after if after["language"] == language else None

    return await _apply_then_read(partial(client.write_portal_language, language), verify_language)
