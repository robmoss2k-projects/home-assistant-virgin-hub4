"""Native port-forwarding and triggering table operations."""

from __future__ import annotations

from collections import Counter
from functools import partial
from hashlib import sha256
from ipaddress import IPv4Network
import json
from typing import Any

from .client import HubClient, InvalidResponse
from .parser import flag, number, parse_script_group
from .portal import batch_edits, ipv4, validate_port_range
from .verification import write_and_verify

FORWARD = (
    ("target", "InternalClient"),
    ("local_start", "InternalPort"),
    ("local_end", "X_ARRIS_COM_InternalPortEndRange"),
    ("external_start", "ExternalPort"),
    ("external_end", "ExternalPortEndRange"),
    ("protocol", "Protocol"),
)
TRIGGER = (
    ("trigger_start", "TriggerPortStart"),
    ("trigger_end", "TriggerPortEnd"),
    ("forward_start", "ForwardPortStart"),
    ("forward_end", "ForwardPortEnd"),
    ("protocol", "TriggerProtocol"),
)
PROTOCOLS = {"TCP", "UDP", "BOTH"}
_SHAPES = {
    "forwarding": (FORWARD, "PortMappingNumberOfEntries", "ExternalPort"),
    "triggering": (TRIGGER, "PortTriggeringNumberOfEntries", "TriggerPortStart"),
}


def _get(data: dict[str, Any], field: str, index: int) -> Any:
    column = data.get(field)
    if isinstance(column, dict):
        return column.get(str(index))
    if isinstance(column, list) and index < len(column):
        return column[index]
    return None


def _identity(row: dict[str, Any]) -> str:
    raw = {k: v for k, v in row.items() if k not in {"enabled", "id"}}
    return sha256(json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:20]


def read_table(group: str, data: dict[str, Any]) -> list[dict[str, Any]]:
    """Read portal-column objects in displayed order, skipping empty sentinels."""
    columns, count_key, first = _SHAPES[group]
    count = number(_get(data, count_key, 1), integer=True)
    if count is None or not 0 <= count <= 512:
        raise InvalidResponse("The Hub did not report a valid rule count")
    rows = []
    for index in range(1, count + 1):
        source = _get(data, "RuleSource", index)
        if _get(data, first, index) == "" and source != "UPnP":
            continue  # Seen in the captured empty triggering table.
        if group == "forwarding" and (not isinstance(source, str) or not source):
            raise InvalidResponse("The Hub did not identify a forwarding rule's source")
        row: dict[str, Any] = {}
        for key, field in columns:
            value = _get(data, field, index)
            if key.endswith(("_start", "_end")):
                value = number(value, integer=True)
                # Dynamic UPnP mappings sometimes omit the range endpoint.
                if value is None and key.endswith("_end") and source == "UPnP":
                    value = row.get(key.replace("_end", "_start"))
                if value is None and key == "external_start" and source == "UPnP":
                    value = number(_get(data, "ExternalPortEndRange", index), integer=True)
            if value is None:
                raise InvalidResponse("The Hub rule table contained an incomplete row")
            row[key] = value
        row["dynamic"] = source == "UPnP"
        row["enabled"] = flag(_get(data, "Enable", index))
        if row["enabled"] is None and not row["dynamic"]:
            raise InvalidResponse("The Hub omitted a manual rule's enabled flag")
        row["id"] = _identity(row)
        rows.append(row)
    return rows


def _overlap(a: dict, b: dict, key: str) -> bool:
    return a[f"{key}_start"] <= b[f"{key}_end"] and a[f"{key}_end"] >= b[f"{key}_start"]


def _plan_add(
    group: str,
    values: dict[str, Any],
    rows: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    columns = _SHAPES[group][0]
    names = {field for field, _ in columns} | {"enabled"}
    if (
        set(values) != names
        or values["protocol"] not in PROTOCOLS
        or type(values["enabled"]) is not bool
    ):
        raise ValueError("Supply a complete rule, TCP/UDP/BOTH, and an enabled flag")
    prefixes = ("local", "external") if group == "forwarding" else ("trigger", "forward")
    for key in prefixes:
        validate_port_range(
            values[f"{key}_start"],
            values[f"{key}_end"],
            protocol=values["protocol"],
            field=key,
            restricted=True,
        )
    if group == "forwarding" and (
        values["local_end"] - values["local_start"]
        != values["external_end"] - values["external_start"]
    ):
        raise ValueError("The internal and external range lengths must match")
    new = values | {"dynamic": False}
    new["id"] = _identity(new)
    if any(row["id"] == new["id"] for row in rows):
        same = next(row for row in rows if row["id"] == new["id"])
        if new != same or sum(row["id"] == new["id"] for row in rows) != 1:
            raise ValueError("The rule already exists; use set_enabled with its ID")
        return new, {}
    if len(rows) >= 32:
        raise ValueError("The Hub portal permits up to 32 displayed port rules")
    for row in rows:
        if new["protocol"] != row["protocol"] and "BOTH" not in (new["protocol"], row["protocol"]):
            continue
        if group == "forwarding":
            conflict = _overlap(new, row, "external") or (
                new["target"] == row["target"] and _overlap(new, row, "local")
            )
        else:
            conflict = any(_overlap(new, row, key) for key in prefixes)
        if conflict:
            raise ValueError("Port range overlaps an existing rule for that protocol")
    if group == "forwarding":
        payload = {wire: values[key] for key, wire in columns}
        payload["Enable"] = int(values["enabled"])
    else:
        # The triggering form sends text inputs. This firmware silently
        # creates a zeroed row when the JSON ports are numbers instead.
        payload = {
            "TriggerStartPort": str(new["trigger_start"]),
            "TriggerEndPort": str(new["trigger_end"]),
            "TargetStartPort": str(new["forward_start"]),
            "TargetEndPort": str(new["forward_end"]),
            "Protocol": new["protocol"],
            "Enable": str(new["enabled"]).lower(),
        }
    return new, payload


async def _validate_lan_target(client: HubClient, target: str) -> str:
    values = parse_script_group("forwarding", await client.read_script("forwarding"))
    try:
        gateway = ipv4(values["StartLanIP"])
        mask = ipv4(values["PortMappingIpSMsk"])
        subnet = IPv4Network((str(ipv4(values["PortMappingIpAddrMin"])), str(mask)), strict=False)
        host, low, high = ipv4(target), ipv4(values["DhcpMinAddr"]), ipv4(values["DhcpMaxAddr"])
    except KeyError, ValueError, TypeError:
        raise ValueError("Supply a valid target IPv4 address on a readable Hub LAN") from None
    if (
        host not in subnet
        or host in (gateway, subnet.network_address, subnet.broadcast_address)
        or not low <= host <= high
    ):
        raise ValueError("Use a host address within the Hub forwarding form's advertised range")
    return str(host)


def _compare(rows: list[dict[str, Any]], *, dynamic: bool = False) -> Counter:
    return Counter((row["id"], row["enabled"]) for row in rows if row["dynamic"] == dynamic)


async def apply_port_rule(
    client: HubClient,
    group: str,
    proposed: dict[str, Any],
) -> dict[str, Any]:
    """Translate portal row indices only after resolving a fresh stable rule ID."""
    operation = proposed["operation"]
    fields = {key: value for key, value in proposed.items() if key != "operation"}
    read_group = f"{group}_rules"
    if operation != "list" and not (await client.read_portal_provisioning()).allows(group):
        raise ValueError("The Hub portal hides this port control in the current IP mode")
    if group == "forwarding" and operation == "add" and "target" in fields:
        fields["target"] = await _validate_lan_target(client, fields["target"])
    before = read_table(group, await client.read_rules(read_group))
    if operation == "list":
        if fields:
            raise ValueError("List takes no rule fields")
        return {"status": "read", "rules": before}

    if operation == "add":
        new, payload = _plan_add(group, fields, before)
        if not payload:
            return {"status": "unchanged", "rules": before}
        expected = before + [new]
    elif operation in {"delete", "set_enabled", "apply"}:
        if operation == "apply":
            if set(fields) != {"edits"}:
                raise ValueError("Supply only the row edits to apply")
            edits = batch_edits(fields["edits"], key="rule_id")
        elif operation == "delete" and set(fields) == {"rule_id"}:
            edits = batch_edits([fields | {"delete": True}], key="rule_id")
        elif operation == "set_enabled":
            edits = batch_edits([fields], key="rule_id")
        else:
            raise ValueError("Supply the rule ID and the requested operation")
        indexes = {}
        for key, value in edits.items():
            matches = [i for i, row in enumerate(before) if row["id"] == key]
            if len(matches) != 1:
                raise ValueError("Rule ID is missing or ambiguous; list the current rules again")
            index = matches[0]
            if before[index]["dynamic"]:
                raise ValueError("Dynamic UPnP mappings are not manual forwarding rules")
            indexes[index] = value
        expected = [
            row | {"enabled": indexes.get(i, row["enabled"])}
            for i, row in enumerate(before)
            if indexes.get(i, False) is not None
        ]
        if expected == before:
            return {"status": "unchanged", "rules": before}
        if group == "forwarding" and any(row["dynamic"] for row in before):
            # The captured portal gives UPnP rows a label instead of an
            # Enabled checkbox and skips Delete. Its selector indexes only
            # the manual checkboxes. No placeholder is sent for UPnP rows.
            form = parse_script_group("forwarding", await client.read_script("forwarding"))
            if form.get("UPnP_Rules") not in (True, 1, "1"):
                raise ValueError(
                    "The Hub did not confirm the mixed-table layout; no forwarding rule was changed"
                )
        checkbox_rows = [
            (i, row) for i, row in enumerate(before) if group != "forwarding" or not row["dynamic"]
        ]
        enabled = [
            checkbox_idx if (row["enabled"] if indexes.get(i) is None else indexes[i]) else -1
            for checkbox_idx, (i, row) in enumerate(checkbox_rows)
        ]
        deleted = [
            checkbox_idx if i in indexes and indexes[i] is None else -1
            for checkbox_idx, (i, _) in enumerate(checkbox_rows)
        ]
        payload = {"Enable": enabled, "Delete": deleted}
    else:
        raise ValueError("Unknown port rule operation")

    expected_set = _compare(expected)
    before_dynamic = _compare(before, dynamic=True)

    async def read() -> list[dict[str, Any]]:
        return read_table(group, await client.read_rules(read_group))

    checked = await write_and_verify(
        partial(client.write_port_rules, group, payload, add=operation == "add"),
        read,
        lambda latest: (
            _compare(latest) == expected_set and _compare(latest, dynamic=True) == before_dynamic
        ),
    )
    latest = checked.latest
    if checked.verified:
        return {"status": "verified", "rules": latest}
    outcome = {"status": "unverified", "rules": latest, "write_issue": checked.write_issue}
    if latest is not None and _compare(latest, dynamic=True) != before_dynamic:
        outcome["dynamic_mappings_changed"] = True
    return outcome
