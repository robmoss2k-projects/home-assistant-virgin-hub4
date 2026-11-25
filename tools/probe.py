"""One-shot Hub 4 probe. Read-only unless a named write test is selected."""

from __future__ import annotations

import argparse
import asyncio
from getpass import GetPassWarning, getpass
import re
import sys
import warnings

import aiohttp

from custom_components.virgin_hub4.client import HubClient, HubError, normalize_host
from custom_components.virgin_hub4.collection import collect_owned_session
from custom_components.virgin_hub4.controls import apply_owned_session
from custom_components.virgin_hub4.modem_mode import read_mode
from custom_components.virgin_hub4.parser import number, parse_script_group


async def _full(hub: HubClient) -> int:
    try:
        sample = await collect_owned_session(
            hub,
            extended=True,
            on_core_read=lambda group, elapsed: print(
                f"{group}: expected data received ({elapsed:.2f}s)", flush=True
            ),
        )
    except HubError as exc:
        print(f"Snapshot: {type(exc).__name__}: {exc}")
        return 1
    print(f"Snapshot: {len(sample.groups)} data groups, cable online: {sample.online}")
    print("Channels: " + ", ".join(f"{name}={len(rows)}" for name, rows in sample.channels.items()))
    print(f"Network log: {len(sample.groups.get('events', []))} rows")
    print(
        "Unavailable groups: "
        + (", ".join(f"{name} ({why})" for name, why in sample.errors.items()) or "none")
    )
    return int(bool(sample.errors))


async def _check_light_ring(hub: HubClient) -> int:
    value = parse_script_group("light_ring", await hub.read_script("light_ring"))
    original = number(value.get("lightring_value"), integer=True)
    if original is None or not -1 <= original <= 100:
        print("Light ring: original setting unknown; no write sent.")
        return 1
    restore = {"mode": "auto"} if original == -1 else {"mode": "manual", "brightness": original}
    temporary = 10 if original == -1 else 99 if original == 100 else original + 1
    print(f"Light ring: original {original}, testing {temporary} and restoring {original}")
    outcome: dict = {}
    restored: dict = {}
    try:
        outcome = await apply_owned_session(
            hub,
            "light_ring",
            {"mode": "manual", "brightness": temporary},
        )
        print(f"Temporary setting: {outcome['status']}, readback={outcome['readback']}")
    finally:
        restored = await apply_owned_session(hub, "light_ring", restore)
        print(f"Original setting: {restored['status']}, readback={restored['readback']}")
    return int(
        outcome.get("status") != "verified"
        or restored.get("status") not in {"unchanged", "verified"}
    )


async def probe(
    host: str,
    password: str,
    *,
    full: bool = False,
    check_light_ring: bool = False,
    operating_mode: bool = False,
) -> int:
    async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as session:
        hub = HubClient(session, host)
        try:
            await hub.login(password)
        except HubError as exc:
            print(f"Login: {type(exc).__name__}: {exc}")
            return 1
        print("Login: accepted")
        misses = 0
        try:
            if check_light_ring:
                try:
                    misses = await _check_light_ring(hub)
                except HubError as exc:
                    print(f"Light ring: {type(exc).__name__}: {exc}")
                    print(
                        "Check the original setting in the Hub UI if restoration was not reported."
                    )
                    misses = 1
            elif operating_mode:
                try:
                    print(f"Operating mode: {await read_mode(hub)}")
                except HubError as exc:
                    print(f"Operating mode: {type(exc).__name__}: {exc}")
                    misses = 1
            elif full:
                misses = await _full(hub)
            else:
                misses = await _basic(hub)
        finally:
            released = await hub.logout()
            print(f"Logout: {'Hub acknowledged' if released else 'not confirmed'}")
        return int(misses > 0 or not released)


async def _basic(hub: HubClient) -> int:
    misses = 0
    for group, marker in (
        ("home", "js_cm_reg_value"),
        ("device", "js_systemUptime"),
        ("line", "js_downStreamChannel"),
        ("mode", "js_RouterMode"),
        ("radio", "js_24g_channel"),
    ):
        try:
            body = await hub.read_script(group)
            found = re.search(rf"\bvar\s+{marker}\s*=", body) is not None
            print(f"{group}: {'expected data received' if found else 'unexpected response'}")
            misses += not found
        except HubError as exc:
            print(f"{group}: {type(exc).__name__}: {exc}")
            misses += 1
    for group, method in (
        ("clients", hub.read_clients),
        ("guest", lambda: hub.read_wifi("guest")),
        ("wifi_security", lambda: hub.read_wifi("wifi_security")),
    ):
        try:
            result = await method()
            print(f"{group}: {'data received' if result else 'empty response'}")
            misses += not result
        except HubError as exc:
            print(f"{group}: {type(exc).__name__}: {exc}")
            misses += 1
    return misses


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="192.168.0.1", type=normalize_host)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument(
        "--full", action="store_true", help="Check all read-only groups and report counts."
    )
    modes.add_argument(
        "--check-light-ring",
        action="store_true",
        help="Temporarily change and then restore the Hub's light ring.",
    )
    modes.add_argument(
        "--operating-mode", action="store_true", help="Read router or modem mode without a write."
    )
    args = parser.parse_args()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", GetPassWarning)
            password = getpass("Hub settings password (input hidden): ")
    except EOFError, GetPassWarning, KeyboardInterrupt:
        print("Run the probe in an interactive terminal that can hide password input.")
        return 2
    if not password:
        print("No password entered; no login attempted.")
        return 2
    try:
        return asyncio.run(
            probe(
                args.host,
                password,
                full=args.full,
                check_light_ring=args.check_light_ring,
                operating_mode=args.operating_mode,
            )
        )
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
