"""Admin setting changes with readback and no automatic write replay."""

from __future__ import annotations

import asyncio
from asyncio import Event
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from functools import partial
from ipaddress import IPv4Address, IPv4Network
import re
from typing import Any

from .client import (
    CannotConnect,
    HubClient,
    HubError,
    InvalidResponse,
    SessionExpired,
    owned_session,
)
from .dhcp import apply_dhcp
from .guest_schedule import GUEST_SETTINGS_CREDENTIAL_FIELDS, apply_guest_schedule
from .ip_rules import apply_ip_rule
from .mac_rules import apply_mac_rule
from .maintenance import run_maintenance
from .modem_mode import read_mode_identity, submit_mode, verify_hub_identity
from .network_tests import DIAGNOSTIC_RUNS, normalize_probe_status, run_probe, wizard
from .parser import flag, number, parse_script_group
from .port_rules import apply_port_rule
from .portal import ipv4, passphrase, require_radio, ssid
from .preferences import apply_preference
from .radio import plan_radio, read_radio
from .schedules import decode_schedule, plan_schedule
from .verification import READBACK_SECONDS, readback_samples, write_and_verify
from .wireless import apply_wireless

FIREWALL_FIELDS = {
    f"{ip}_{name}": f"{ip}{key}"
    for ip in ("v4", "v6")
    for name, key in (
        ("enabled", "Enable"),
        ("block_fragments", "FragPkts"),
        ("detect_port_scan", "PortScan"),
        ("detect_ip_flood", "IpFlood"),
    )
}
_FIREWALL_ON = {"v4Enable": "Low", "v6Enable": "Default"}
_FIREWALL_OFF = {"None", "Off", "Disabled", "false", "0"}
_GUEST_POLL_SECONDS = 1
_GUEST_READBACK_SECONDS = READBACK_SECONDS
_GUEST_FINAL_READ_SECONDS = 5
_WPS_TERMINAL_GRACE = 30


class InvalidSetting(HubError):
    """A setting cannot safely be applied or its current value is unknown."""


@dataclass(frozen=True)
class Edit:
    expected: dict[str, Any]
    write: Callable[[], Awaitable[None]]


def _require(value: Any, name: str) -> Any:
    if value is None:
        raise InvalidResponse(f"Hub did not report a usable {name}")
    return value


def _state(group: str, values: dict[str, Any]) -> dict[str, Any]:
    if group == "light_ring":
        return {
            "value": _require(
                number(values.get("lightring_value"), integer=True), "light ring mode"
            )
        }
    if group == "upnp":
        return {"enabled": _require(flag(values.get("UPnP_Status")), "UPnP state")}
    if group == "mtu":
        return {"value": _require(number(values.get("MTUSize"), integer=True), "WAN MTU")}
    if group == "wps":
        return {"enabled": _require(flag(values.get("WPSPbcEnable")), "push-button WPS state")}
    if group == "guest":
        ssid = values.get("ssid")
        if not isinstance(ssid, str):
            raise InvalidResponse("Hub did not report a usable guest Wi-Fi name")
        return {
            "enabled": _require(flag(values.get("enable")), "guest Wi-Fi state"),
            "ssid": ssid,
            "broadcast": _require(flag(values.get("broadcast")), "guest broadcast state"),
            "security": str(_require(values.get("security"), "guest Wi-Fi security mode")),
        }
    if group == "dmz":
        return {
            "enabled": _require(flag(values.get("DMZ_State")), "DMZ state"),
            "target": str(values.get("DMZ_Ip") or "0.0.0.0"),
        }
    if group == "firewall":
        result = {}
        for key in FIREWALL_FIELDS.values():
            value = values.get(key)
            if key in _FIREWALL_ON:
                if value == _FIREWALL_ON[key]:
                    value = True
                elif isinstance(value, str) and value in _FIREWALL_OFF:
                    value = False
                else:
                    value = None
            elif isinstance(value, str) and value in {"true", "false"}:
                value = value == "true"
            else:
                value = None
            result[key] = _require(flag(value), key)
        return result
    raise InvalidSetting("Unknown Hub control")


async def _read(client: HubClient, group: str) -> tuple[dict[str, Any], dict[str, Any]]:
    if group in {"mac_filter_schedule", "ip_filter_schedule"}:
        ip = group == "ip_filter_schedule"
        values = await client.read_schedule(ip=ip)
        return decode_schedule(values, ip=ip), values
    values = (
        await client.read_wifi("guest")
        if group == "guest"
        else parse_script_group(group, await client.read_script(group))
    )
    if group == "radio":
        smart = await client.read_wifi("smart_wifi")
        return read_radio(values, smart), values | {"smart_wifi": smart}
    return _state(group, values), values


def _dmz_target(target: str, values: dict[str, Any]) -> str:
    try:
        gateway = ipv4(values["LAN_Ip"])
        mask = str(values["StartLanMask"])
        if mask.startswith("$"):
            mask = str(IPv4Address(int(mask[1:], 16)))
        network = IPv4Network((str(gateway), mask), strict=False)
        ip = ipv4(target)
    except ValueError, KeyError:
        raise InvalidSetting("DMZ requires an IPv4 target and a readable Hub LAN") from None
    if (
        ip not in network
        or ip in (gateway, network.network_address, network.broadcast_address)
        or not 2 <= (int(ip) & 255) <= 254
        or (
            flag(values.get("HideCustomerDhcpLanChange")) is True
            and int(ip) >> 8 != int(gateway) >> 8
        )
    ):
        raise InvalidSetting("DMZ target must be a usable host on the Hub's LAN")
    return str(ip)


def _plan(
    client: HubClient,
    group: str,
    proposed: dict[str, Any],
    before: dict[str, Any],
    values: dict[str, Any],
) -> Edit:
    if group in {"mac_filter_schedule", "ip_filter_schedule"}:
        ip = group == "ip_filter_schedule"
        try:
            fields, expected = plan_schedule(proposed, ip=ip)
        except ValueError as exc:
            raise InvalidSetting(str(exc)) from None
        return Edit(expected, partial(client.write_schedule, fields, ip=ip))
    if group == "radio":
        try:
            fields, expected = plan_radio(proposed, before, values)
        except ValueError as exc:
            raise InvalidSetting(str(exc)) from None
        return Edit(expected, partial(client.write_radio, fields))
    if group == "light_ring":
        mode, brightness = proposed["mode"], proposed.get("brightness")
        if mode == "auto" and brightness is None:
            value = -1
        elif mode == "manual" and type(brightness) is int and 0 <= brightness <= 100:
            value = brightness
        else:
            raise InvalidSetting("Choose auto, or manual with a brightness from 0 to 100")
        return Edit({"value": value}, partial(client.write_light_ring, value))
    if group == "upnp":
        return Edit(
            {"enabled": proposed["enabled"]}, partial(client.write_upnp, proposed["enabled"])
        )
    if group == "wps":
        return Edit(
            {"enabled": proposed["enabled"]}, partial(client.write_wps, proposed["enabled"])
        )
    if group == "guest":
        if not proposed or set(proposed) - (before.keys() | {"passphrase"}):
            raise InvalidSetting("Provide at least one supported guest Wi-Fi setting")
        expected = before | {k: v for k, v in proposed.items() if k != "passphrase"}
        key = proposed.get("passphrase", values.get("passphrase"))
        if not isinstance(key, str) or (key and set(key) == {"*"}):
            raise InvalidSetting("Unable to preserve the current guest passphrase")
        if (
            expected["enabled"]
            and expected["security"] != "0"
            and not (8 <= len(key) <= 63 or re.fullmatch(r"[0-9A-Fa-f]{64}", key))
        ):
            raise InvalidSetting("The selected security mode needs an existing usable passphrase")
        fields = {
            "enable": str(int(expected["enabled"])),
            "ssid": expected["ssid"],
            "broadcast": str(int(expected["broadcast"])),
            "security": expected["security"],
            "passphrase": key,
        }
        return Edit(expected, partial(client.write_guest, fields))
    if group == "mtu":
        value = proposed["value"]
        if type(value) is not int or not 1280 <= value <= 1500:
            raise InvalidSetting("WAN MTU must be between 1280 and 1500")
        return Edit({"value": value}, partial(client.write_mtu, value))
    if group == "dmz":
        enabled, target = proposed["enabled"], proposed.get("target")
        if enabled or target is not None:
            target = _dmz_target(target or before["target"], values)
        else:
            target = before["target"]
        expected = {"enabled": enabled}
        if enabled or proposed.get("target") is not None:
            expected["target"] = target
        return Edit(expected, partial(client.write_dmz, enabled, target))
    raise InvalidSetting("Unknown Hub control")


def _matches(actual: dict[str, Any], expected: dict[str, Any]) -> bool:
    return all(actual.get(key) == value for key, value in expected.items())


async def apply_owned_session(
    client: HubClient, group: str, proposed: dict[str, Any], *, cancel: Event | None = None
) -> dict[str, Any]:
    """Apply one edit once and trust readback, not HTTP acknowledgement."""
    if group == "guest":
        return await _apply_guest_setting(client, proposed)
    if group in {"guest_schedule", "guest_schedule_read"}:
        try:
            return await apply_guest_schedule(
                client,
                {k: v for k, v in proposed.items() if k != "time_zone"},
                zone=proposed.get("time_zone", "Europe/London"),
                read_only=group == "guest_schedule_read",
            )
        except ValueError as exc:
            raise InvalidSetting(str(exc)) from None
    if group in {"maintenance_state", "maintenance_backup", "maintenance_submit"}:
        try:
            return await run_maintenance(client, group, proposed)
        except ValueError as exc:
            raise InvalidSetting(str(exc)) from None
    if group == "mode_state":
        try:
            return {
                "status": "read",
                **await read_mode_identity(client, for_switch=proposed.get("for_switch") is True),
            }
        except ValueError as exc:
            raise InvalidSetting(str(exc)) from None
    if group == "mode_submit":
        try:
            return await submit_mode(client, proposed)
        except ValueError as exc:
            raise InvalidSetting(str(exc)) from None
    if group == "diagnostic_status":
        trace = proposed["test"] == "traceroute"
        data = await client.get_probe_status(trace=trace)
        return {"status": "read", "result": normalize_probe_status(data, trace=trace)}
    if group in {"device_label", "portal_language", "portal_language_read"}:
        try:
            return await apply_preference(client, group, proposed)
        except ValueError as exc:
            raise InvalidSetting(str(exc)) from None
    if group in DIAGNOSTIC_RUNS:
        try:
            event = cancel if cancel is not None else Event()
            if group == "diagnostic_wizard":
                return await wizard(client, event, proposed)
            return await run_probe(client, proposed, trace=group == "trace_test", cancel=event)
        except ValueError as exc:
            raise InvalidSetting(str(exc)) from None
    if group in {"forwarding", "triggering"}:
        try:
            return await apply_port_rule(client, group, proposed)
        except ValueError as exc:
            raise InvalidSetting(str(exc)) from None
    if group == "mac_rules":
        try:
            return await apply_mac_rule(client, proposed)
        except ValueError as exc:
            raise InvalidSetting(str(exc)) from None
    if group == "ip_rules":
        try:
            return await apply_ip_rule(client, proposed)
        except ValueError as exc:
            raise InvalidSetting(str(exc)) from None
    if group in {"wifi_settings", "wifi_access_list"}:
        try:
            return await apply_wireless(client, group, proposed)
        except ValueError as exc:
            raise InvalidSetting(str(exc)) from None
    if group in {"dhcp_v4", "dhcp_v6", "dhcp_reservations"}:
        try:
            return await apply_dhcp(client, group, proposed)
        except ValueError as exc:
            raise InvalidSetting(str(exc)) from None
    if group == "wps_registration":
        return await _register_wps(client)
    if group in {"upnp", "dmz"} and not (await client.read_portal_provisioning()).allows(group):
        raise InvalidSetting(
            "The Hub portal hides this control in the current IP provisioning mode"
        )
    if group == "firewall":
        if not proposed or set(proposed) - FIREWALL_FIELDS.keys():
            raise InvalidSetting("Provide at least one recognised firewall setting")
        families = await client.read_ip_provisioning(firewall=True)
        if any(key[:2] not in families for key in proposed):
            raise InvalidSetting(
                "The portal hides that firewall family in the current IP provisioning mode"
            )
    before, values = await _read(client, group)
    if group == "firewall":
        expected = before | {FIREWALL_FIELDS[key]: value for key, value in proposed.items()}
        if any(
            key != f"{key[:2]}_enabled" and not expected[f"{key[:2]}Enable"] for key in proposed
        ):
            raise InvalidSetting("Enable the firewall family before editing its dependent flags")
        # Disabled/hidden controls retain their loaded booleans in the portal's form.
        wire = {
            key: int(value)
            if key[:2] in families and (key in _FIREWALL_ON or expected[f"{key[:2]}Enable"])
            else value
            for key, value in expected.items()
        }
        edit = Edit(expected, partial(client.write_firewall, wire))
    else:
        edit = _plan(client, group, proposed, before, values)
    if _matches(before, edit.expected):
        return {"status": "unchanged", "group": group, "readback": before}

    async def read_settings() -> dict[str, Any]:
        return (await _read(client, group))[0]

    checked = await write_and_verify(
        edit.write,
        read_settings,
        partial(_matches, expected=edit.expected),
    )
    result = {
        "status": "verified" if checked.verified else "unverified",
        "group": group,
        "readback": checked.latest,
    }
    if not checked.verified or checked.write_issue is not None:
        result["write_issue"] = checked.write_issue
    return result


async def _register_wps(client: HubClient) -> dict[str, Any]:
    """Start once, then look for a fresh result rather than accepting an old success."""
    setting, _ = await _read(client, "wps")
    if not setting["enabled"]:
        raise InvalidSetting("Enable push-button WPS before starting registration")
    before = await client.read_wps_result()
    in_progress = {"active", "in progress", "inprogress", "pending", "running", "started"}
    if any(value.strip().lower() in in_progress for value in before.values()):
        raise InvalidSetting("WPS registration is already in progress")
    write_issue = None
    try:
        await client.start_wps()
    except SessionExpired:
        return {
            "status": "unverified",
            "group": "wps_registration",
            "write_issue": "SessionExpired",
        }
    except HubError as exc:
        write_issue = type(exc).__name__
    active_bands: set[str] = set()
    latest = before

    async def pairing_reads():
        last = None
        expired = False

        async def read():
            nonlocal expired
            try:
                return await client.read_wps_result()
            except SessionExpired:
                expired = True
                raise

        async for last in readback_samples(read, interval=5, first_delay=5):
            yield last
        if (
            not expired
            and last is not None
            and any(v.strip().lower() in in_progress for v in last.values())
        ):
            # Finish watching the same owned registration, not a second write/session.
            async for followup in readback_samples(
                read, poll_seconds=_WPS_TERMINAL_GRACE, interval=5
            ):
                yield followup

    async for latest in pairing_reads():
        fresh = set()
        for band, value in latest.items():
            normalized = value.strip().lower()
            if normalized in in_progress:
                active_bands.add(band)
            if normalized in {"success", "failed"} and (
                normalized != before[band].strip().lower() or band in active_bands
            ):
                fresh.add(normalized)
        # The portal checks both bands for success before clearing a failure.
        if "success" in fresh:
            return {"status": "success", "group": "wps_registration", "readback": latest}
        if "failed" in fresh:
            result: dict[str, Any] = {
                "status": "failed",
                "group": "wps_registration",
                "readback": latest,
                "cleanup": "acknowledged",
            }
            try:
                await client.clear_failed_wps()
            except HubError as exc:
                # There may be no visible change to the saved result after cleanup.
                # Do not send it a second time or claim that the ring changed.
                result.update(cleanup="unverified", cleanup_issue=type(exc).__name__)
            return result
    return {
        "status": "timeout",
        "group": "wps_registration",
        "readback": latest,
        "write_issue": write_issue,
    }


def _guest_keys_preserved(before: dict[str, Any], after: dict[str, Any]) -> bool | None:
    """Compare actual values in memory; a missing or masked key proves nothing."""
    all_known = True
    for field in GUEST_SETTINGS_CREDENTIAL_FIELDS:
        original, latest = before.get(field), after.get(field)
        if any(
            not isinstance(key, str) or (key and set(key) == {"*"}) for key in (original, latest)
        ):
            all_known = False
        elif original != latest:
            return False
    return True if all_known else None


async def _apply_guest_setting(client: HubClient, proposed: dict[str, Any]) -> dict[str, Any]:
    before, original = await _read(client, "guest")
    expected_keys = original
    try:
        if "ssid" in proposed:
            ssid(proposed["ssid"])
        if "passphrase" in proposed:
            primary = tuple(original.get(field) for field in GUEST_SETTINGS_CREDENTIAL_FIELDS[1:])
            if any(
                not isinstance(value, str) or (value and set(value) == {"*"}) for value in primary
            ):
                raise ValueError("The Hub did not report verifiable primary Wi-Fi keys")
            passphrase(
                proposed["passphrase"],
                open_network=proposed.get("security", before["security"]) == "0",
                conflicting=primary,
            )
            expected_keys = original | {"passphrase": proposed["passphrase"]}
    except ValueError as exc:
        raise InvalidSetting(str(exc)) from None
    edit = _plan(client, "guest", proposed, before, original)
    rotated = expected_keys.get("passphrase") != original.get("passphrase")
    if _matches(before, edit.expected) and not rotated:
        return {"status": "unchanged", "group": "guest", "readback": before}
    if proposed.get("enabled", before["enabled"]) or set(proposed) - {"enabled"}:
        try:
            await require_radio(client)
        except ValueError as exc:
            raise InvalidSetting(str(exc)) from None
    write_issue = None
    try:
        await edit.write()
    except SessionExpired:
        return {
            "status": "outcome_unknown",
            "group": "guest",
            "readback": None,
            "write_issue": "SessionExpired",
            "message": "The Hub session expired during the write. Check the Hub; no write was retried.",
        }
    except HubError as exc:
        write_issue = type(exc).__name__

    # Allow the firmware to settle. All polls use the writer's session; an old
    # value or a lost response never results in a second write or login.
    clock = asyncio.get_running_loop().time
    started = clock()
    deadline = started + _GUEST_READBACK_SECONDS
    poll_at = min(deadline, started + _GUEST_POLL_SECONDS)
    status = "outcome_unknown"
    readback = preserved = issue = None
    while True:
        await asyncio.sleep(max(0, poll_at - clock()))
        poll_started = clock()
        final = poll_at == deadline or poll_started >= deadline
        # Reserve a normal request budget for the end-of-window read. A slow
        # earlier request must not delay that final check or overlap with it.
        read_deadline = poll_started + _GUEST_FINAL_READ_SECONDS if final else deadline
        readback = preserved = None
        try:
            async with asyncio.timeout_at(read_deadline):
                readback, latest = await _read(client, "guest")
        except TimeoutError:
            issue = "verification_timeout"
        except (CannotConnect, InvalidResponse) as exc:
            issue = type(exc).__name__
        except HubError as exc:
            # This includes an expired session; don't open a replacement.
            issue = type(exc).__name__
            break
        else:
            matches = _matches(readback, edit.expected)
            preserved = _guest_keys_preserved(expected_keys, latest)
            if matches and preserved is True:
                return {
                    "status": "verified",
                    "group": "guest",
                    "readback": readback,
                    "reported_passphrases_preserved": not rotated,
                    **({"reported_passphrase_verified": True} if rotated else {}),
                }
            if preserved is False:
                issue = "passphrase_mismatch"
            else:
                issue = "passphrases_unavailable" if matches else "settings_mismatch"
            if final and not matches:
                status = "not_applied"
        if final:
            break
        poll_at = min(deadline, poll_started + _GUEST_POLL_SECONDS)

    if status == "not_applied":
        message = "The Hub still did not report the requested guest Wi-Fi settings after readback polling."
        if preserved is False:
            message += " It also reported a changed Wi-Fi passphrase."
    elif preserved is False and rotated:
        message = "The Hub did not confirm the requested guest key and preserved primary keys."
    elif preserved is False:
        message = "The Hub reported a changed Wi-Fi passphrase."
    else:
        message = "Could not confirm both the requested settings and unchanged Wi-Fi passphrases."
    return {
        "status": status,
        "message": message + " Check the Hub before trying again; no write was retried.",
        "group": "guest",
        "readback": readback,
        "write_issue": write_issue,
        "verification_issue": issue,
        "reported_passphrases_preserved": preserved if not rotated else None,
    }


async def apply_setting(
    host: str,
    password: str,
    group: str,
    proposed: dict[str, Any],
    *,
    cancel: Event | None = None,
    expected_identity: str | None = None,
) -> dict[str, Any]:
    """Acquire and release a Hub session for one admin action."""
    if cancel is not None and cancel.is_set():
        return {"status": "canceled_before_start"}
    async with owned_session(host, password) as client:
        if expected_identity is not None:
            device = parse_script_group("device", await client.read_script("device"))
            verify_hub_identity(device, expected_identity)
        return await apply_owned_session(client, group, proposed, cancel=cancel)
