"""Single-target diagnostics originated by the Hub, not Home Assistant."""

from __future__ import annotations

from asyncio import Event, wait_for
from ipaddress import ip_address
import re
from time import monotonic
from typing import Any

from .client import HubClient, HubError, InvalidResponse, SessionExpired
from .const import HUB_MODES
from .parser import flag, number, parse_script_group
from .verification import READBACK_SECONDS

DIAGNOSTIC_RUNS = {"ping_test", "trace_test", "diagnostic_wizard"}
_RUNNING = {"requested", "running", "inprogress", "in_progress"}
_CANCELED = {"canceled", "cancelled"}
_IDLE = {"none", "idle"}
_OWNED_TERMINAL_GRACE = 30
_PING_STATS = {
    "SuccessCount": "received",
    "FailureCount": "failed",
    "mintime": "minimum_ms",
    "avgtime": "average_ms",
    "maxtime": "maximum_ms",
}
_HOST_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
_NONPRINTABLE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def _target(value: object) -> str:
    if not isinstance(value, str) or "%" in value or not 1 <= len(value) <= 253:
        raise ValueError("Enter one IP address or DNS host name")
    try:
        address = ip_address(value)
    except ValueError:
        if re.fullmatch(r"[0-9.]+", value) or not all(
            _HOST_LABEL.fullmatch(label) for label in value.removesuffix(".").split(".")
        ):
            raise ValueError("Enter one IP address or DNS host name") from None
        return value
    if address.is_unspecified or address.is_multicast or str(address) == "255.255.255.255":
        raise ValueError("Enter a single unicast target")
    return str(address)


def _integer(values: dict[str, Any], key: str, default: int, low: int, high: int) -> int:
    value = values.get(key, default)
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{key} must be a whole number from {low} to {high}")
    return value


def _probe_parameters(fields: dict[str, Any], *, trace: bool) -> tuple[dict[str, str], int]:
    host = _target(fields.get("target"))
    timeout = _integer(fields, "timeout_seconds", READBACK_SECONDS, 5, READBACK_SECONDS)
    if trace:
        hops = _integer(fields, "max_hops", 30, 1, 255)
        port = _integer(fields, "base_port", 33434, 1, 65535 - 3 * hops)
        return {
            "Host": host,
            "MaxHops": str(hops),
            "Baseport": str(port),
            "DiagnosticsState": "Requested",
        }, timeout
    count = _integer(fields, "count", 4, 1, 32)
    size = _integer(fields, "packet_size", 64, 64, 1518)
    return {
        "Host": host,
        "NoofPings": str(count),
        "PingSize": str(size),
        "settings": "Requested",
    }, timeout


def normalize_probe_status(data: dict[str, Any], *, trace: bool) -> dict[str, Any]:
    state = data.get("state" if trace else "status")
    if not isinstance(state, str) or not re.fullmatch(r"[a-zA-Z_]{1,64}", state):
        raise InvalidResponse("The Hub did not report a usable network test state")
    result: dict[str, Any] = {"hub_state": state}
    if trace:
        lines = data.get("result")
        if (
            isinstance(lines, list)
            and len(lines) <= 1024
            and all(isinstance(line, str) for line in lines)
        ):
            result["lines"] = [_NONPRINTABLE.sub("", line)[:512] for line in lines]
    else:
        for key, name in _PING_STATS.items():
            count = key.endswith("Count")
            value = number(data.get(key), integer=count)
            if value is not None and 0 <= value <= (65535 if count else 600000):
                result[name] = value
    return result


async def _status(client: HubClient, *, trace: bool) -> dict[str, Any]:
    return normalize_probe_status(await client.get_probe_status(trace=trace), trace=trace)


async def _wait(event: Event, seconds: float) -> None:
    try:
        await wait_for(event.wait(), timeout=seconds)
    except TimeoutError:
        pass


async def run_probe(
    client: HubClient, fields: dict[str, Any], *, trace: bool, cancel: Event
) -> dict[str, Any]:
    """Recognise a fresh result without trusting the old result or starting twice."""
    request, timeout = _probe_parameters(fields, trace=trace)
    if cancel.is_set():
        return {"status": "canceled_before_start"}
    if not (await client.read_portal_provisioning()).allows_target(request["Host"]):
        raise ValueError("The Hub portal does not allow that target IP family in the current mode")
    baseline = await _status(client, trace=trace)
    if baseline["hub_state"].lower() in _RUNNING:
        return {"status": "busy"}
    if cancel.is_set():
        return {"status": "canceled_before_start"}
    write_issue = None
    try:
        await client.set_probe(request, trace=trace)
    except SessionExpired:
        return {"status": "unverified", "write_issue": "SessionExpired"}
    except HubError as exc:
        write_issue = type(exc).__name__
    deadline = monotonic() + timeout
    observed_run = stop_sent = False
    latest = None
    grace = final_read = False
    while True:
        if monotonic() >= deadline:
            if (
                not grace
                and not stop_sent
                and observed_run
                and latest is not None
                and latest["hub_state"].lower() in _RUNNING
            ):
                # Keep the original action and cancel channel alive for a known run.
                grace = True
                deadline = monotonic() + _OWNED_TERMINAL_GRACE
            else:
                final_read = True
        try:
            latest = await _status(client, trace=trace)
        except SessionExpired:
            write_issue = "SessionExpired"
            latest = None
            break
        except HubError:
            latest = None
        if latest is not None:
            state = latest["hub_state"].lower()
            if state in _RUNNING:
                observed_run = True
                if cancel.is_set() and not stop_sent and not final_read:
                    stop_sent = True
                    try:
                        await client.set_probe(
                            {"DiagnosticsState" if trace else "settings": "Canceled"}, trace=trace
                        )
                    except SessionExpired:
                        write_issue = "SessionExpired"
                        break
                    except HubError as exc:
                        write_issue = type(exc).__name__
                    deadline = monotonic() + timeout
            elif stop_sent and (state in _CANCELED or state in _IDLE):
                return {"status": "canceled", "result": latest}
            elif observed_run or latest != baseline:
                if state == "complete":
                    if trace and any(line.strip() for line in latest.get("lines", [])):
                        return {"status": "complete", "target": request["Host"], "result": latest}
                    if (
                        not trace
                        and "received" in latest
                        and "failed" in latest
                        and latest["received"] + latest["failed"] == int(request["NoofPings"])
                    ):
                        return {
                            "status": "complete",
                            "target": request["Host"],
                            "result": latest | {"requested": int(request["NoofPings"])},
                        }
                elif state.startswith("error"):
                    return {"status": "error", "target": request["Host"], "result": latest}
        if final_read:
            break
        # Once requested, pace follow-up reads so a missing cancel echo does not spin.
        pace = min(0.8, max(0, deadline - monotonic()))
        await _wait(Event() if cancel.is_set() else cancel, pace)
    return {
        "status": "cancel_unverified" if cancel.is_set() else "unverified",
        "reason": "No fresh terminal result was observed",
        "hub_state": latest["hub_state"] if latest is not None else None,
        "write_issue": write_issue,
    }


async def wizard(client: HubClient, cancel: Event, fields: dict[str, Any]) -> dict[str, Any]:
    """Summarise the source wizard's checks, with link exercise only by opt-in."""
    exercise = fields.get("exercise_ethernet", False)
    if (
        type(exercise) is not bool
        or exercise
        and fields.get("confirm_link_interruption") is not True
    ):
        raise ValueError("Ethernet link exercise requires explicit interruption confirmation")
    if cancel.is_set():
        return {"status": "canceled_before_start"}
    mode = parse_script_group("mode", await client.read_script("mode"))
    if HUB_MODES.get(str(mode["RouterMode"])) != "router":
        return {
            "status": "unsupported",
            "reason": "The Hub portal offers this wizard only in router mode",
        }
    home = parse_script_group("home", await client.read_script("home"))

    def has_address(key: str) -> bool | None:
        value = home.get(key)
        if value is None:
            return None
        if not value:
            return False
        try:
            return not ip_address(value).is_unspecified
        except ValueError:
            return None

    cable_ip, ipv4, ipv6 = (has_address(k) for k in ("cm_ip", "wan_ip4", "wan_ip6"))
    checks: dict[str, Any] = {
        "cable_has_address": cable_ip,
        "wan_has_ipv4": ipv4,
        "wan_has_ipv6": ipv6,
        "wifi_24_enabled": flag(home.get("24g_stat")),
        "wifi_50_enabled": flag(home.get("5g_stat")),
    }
    provision = number(home.get("wan_ip_prov_mode"), integer=True)
    if cable_ip and ((ipv6 and provision in (2, 3)) or (ipv4 and provision in (1, 3))):
        target = "ipv6.google.com" if ipv6 and provision in (2, 3) else "google.com"
        if target == "ipv6.google.com" and not cancel.is_set():
            try:
                dns = await client.diagnostic_ipv6_dns()
            except HubError:
                checks["ipv6_dns_result"] = "unavailable"
            else:
                # Mirror the browser wizard's DNSQuery fallback on this firmware.
                state = str(dns.get("status"))
                if state == "0" or (state == "1" and dns.get("getting") == "DNSQuery"):
                    target = "google.com"
                    checks["ipv6_dns_result"] = "fell_back_to_ipv4_host"
        outcome = await run_probe(client, {"target": target}, trace=False, cancel=cancel)
        checks["broadband_ping"] = outcome
    else:
        checks["broadband_ping"] = {
            "status": "not_run",
            "reason": "No provisioned WAN address was confirmed",
        }
    fail_safe = number(home.get("fail_safe_mode"), integer=True)
    checks["thermal_fail_safe"] = fail_safe > 1 if fail_safe is not None else None
    telephone = home.get("mta_admin_state")
    checks["telephone"] = {
        "provisioning": telephone if isinstance(telephone, str) else None,
        "lines": [
            {
                "operational": flag(home.get(f"mta_line{i}_status")),
                "call_state": number(home.get(f"mta_call{i}_status"), integer=True),
            }
            for i in (1, 2)
        ],
    }
    if cancel.is_set():
        return {"status": "canceled", "checks": checks}
    try:
        links = await client.diagnostic_links()
    except HubError:
        links = {}
    statuses = links.get("LanPortStatus")
    speeds = links.get("LanPortSpeed")
    if (
        isinstance(statuses, list)
        and isinstance(speeds, list)
        and len(statuses) == len(speeds) == 4
    ):
        checks["ethernet_ports"] = [
            {"link_up": flag(status), "reported_speed": number(speed)}
            for status, speed in zip(statuses, speeds, strict=True)
        ]
    else:
        checks["ethernet_ports"] = None
    readings = links.get("WiFiClientSignal")
    checks["weak_wifi_clients"] = (
        sum(number(value) < -60 for value in readings if number(value) is not None)
        if isinstance(readings, list)
        else None
    )
    checks["ethernet_exercise"] = "not_requested"
    complete = checks["ethernet_ports"] is not None and checks["broadband_ping"]["status"] in {
        "complete",
        "error",
        "not_run",
    }
    if exercise:
        if checks["ethernet_ports"] is None:
            checks["ethernet_exercise"] = "baseline_unavailable"
            complete = False
        else:
            sent = 0
            for _ in range(3):
                if cancel.is_set():
                    break
                try:
                    await client.exercise_ethernet_links()
                except HubError:
                    break  # A transport error could be the intended link interruption.
                sent += 1
                await _wait(cancel, 10 if sent < 3 else 20)
            try:
                final = await client.diagnostic_links()
            except HubError:
                final = {}
            checks["ethernet_exercise"] = {
                "acknowledged_cycles": sent,
                "link_states_restored": final.get("LanPortStatus") == statuses,
            }
            complete = complete and sent == 3 and final.get("LanPortStatus") == statuses
    status = "canceled" if cancel.is_set() else "complete" if complete else "partial"
    return {"status": status, "checks": checks}
