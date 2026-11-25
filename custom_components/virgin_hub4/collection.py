"""Read a complete snapshot using a short-lived administrator transaction."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from functools import partial
from time import monotonic
from typing import Any

from .client import HubClient, HubError, SCRIPT_READS, SessionExpired, owned_session
from .const import HUB_MODES
from .mac_rules import read_effective_mac_rules
from .parser import Snapshot, assemble_snapshot, parse_clients, parse_script_group

CORE_GROUPS = ("home", "device", "line")


async def collect(host: str, password: str, *, extended: bool) -> Snapshot:
    """Retry one expired read transaction, never a rejected or contested login."""
    for attempt in range(2):
        # Keep the retry inside the login scope: an initial login error does
        # not trigger a second login, and writes never use this retry path.
        async with owned_session(host, password) as client:
            try:
                return await collect_owned_session(client, extended=extended)
            except SessionExpired:
                if attempt:
                    raise
    raise AssertionError("A read must either return a complete snapshot or raise")


async def collect_owned_session(
    client: HubClient,
    *,
    extended: bool,
    on_core_read: Callable[[str, float], None] | None = None,
) -> Snapshot:
    """Read required cable status first and isolate optional firmware variation."""
    sections: dict[str, dict[str, Any]] = {}
    additional: dict[str, Any] = {}
    errors = {}
    is_modem = False

    async def read_script(group: str) -> dict[str, Any]:
        return parse_script_group(group, await client.read_script(group))

    try:
        sections["mode"] = await read_script("mode")
        is_modem = HUB_MODES.get(str(sections["mode"]["RouterMode"])) == "modem"
    except SessionExpired:
        raise
    except HubError as err:
        errors["mode"] = type(err).__name__
    for group in ("device", "line") if is_modem else CORE_GROUPS:
        started = monotonic()
        sections[group] = await read_script(group)
        if group == "device":
            observed_at = datetime.now(timezone.utc)
        if on_core_read is not None:
            on_core_read(group, monotonic() - started)
    if is_modem:
        # Bridge firmware may omit router-specific home fields. Don't make
        # the actual cable, device and mode data unavailable as a result.
        try:
            sections["home"] = await read_script("home")
        except HubError as err:
            errors["home"] = type(err).__name__
        return assemble_snapshot(sections, errors=errors, observed_at=observed_at)

    async def try_add(group: str, method: Callable[[], Awaitable[Any]]) -> None:
        try:
            additional[group] = await method()
        except SessionExpired:
            raise
        except HubError as err:
            errors[group] = type(err).__name__

    async def connected() -> list[dict[str, Any]]:
        return parse_clients(await client.read_clients())

    async def try_script(group: str) -> None:
        try:
            sections[group] = await read_script(group)
        except SessionExpired:
            raise
        except HubError as err:
            errors[group] = type(err).__name__

    await try_add("clients", connected)
    for group in ("radio", "wps"):
        await try_script(group)

    if extended:
        for group in SCRIPT_READS:
            if group in CORE_GROUPS or group in ("mode", "radio", "wps"):
                continue
            await try_script(group)
        for group in ("smart_wifi", "wifi_security", "guest", "guest_expiry"):
            await try_add(group, partial(client.read_wifi, group))
        for group in (
            "forwarding_rules",
            "triggering_rules",
            "wireless_filter_list",
            "wireless_attached_devices",
            "mac_filter_attached_devices",
        ):
            await try_add(group, partial(client.read_rules, group))
        await try_add("mac_filter_rules", partial(read_effective_mac_rules, client))
        await try_add("activity", client.read_activity)
        await try_add("dhcp_server", partial(client.read_dhcp, clients=False))
        await try_add("dhcp_clients", partial(client.read_dhcp, clients=True))
        await try_add("mac_filter_schedule", partial(client.read_schedule, ip=False))
        await try_add("ip_filter_schedule", partial(client.read_schedule, ip=True))

    return assemble_snapshot(sections, additional, errors, observed_at=observed_at)
