"""Local portal MAC-rule CRUD, separate from the wireless MAC access list."""

from __future__ import annotations

from collections import Counter
from functools import partial
import re
from typing import Any

from .client import HubClient, InvalidResponse
from .parser import flag, number
from .portal import batch_edits, label
from .verification import write_and_verify


def normalise_mac(mac: str) -> str:
    """Canonicalize the common formats the portal can represent."""
    digits = re.sub("[:-]", "", mac).upper()
    if not re.fullmatch("[0-9A-F]{12}", digits):
        raise ValueError("Enter a six-octet MAC address")
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def read_mac_table(data: dict[str, Any]) -> list[dict[str, Any]]:
    count_field = data.get("numberOfMACList")
    count = number(count_field.get("1"), integer=True) if isinstance(count_field, dict) else None
    if count is None or not 0 <= count <= 512:
        raise InvalidResponse("The Hub did not return a valid MAC rule count")
    result = []
    for index in range(count):
        row = data.get(str(index))
        if not isinstance(row, list) or len(row) < 3:
            raise InvalidResponse("The Hub returned an incomplete MAC rule")
        if row[1] == "":
            continue
        try:
            mac = normalise_mac(row[1])
        except ValueError, TypeError:
            raise InvalidResponse("The Hub returned an invalid MAC rule") from None
        enabled = flag(row[2])
        if enabled is None:
            raise InvalidResponse("The Hub did not report a MAC rule's enabled state")
        result.append({"mac": mac, "name": str(row[0]), "enabled": enabled})
    return result


async def read_effective_mac_rules(client: HubClient) -> list[dict[str, Any]]:
    """Read the list the portal uses, not the empty in-page initializer."""
    return read_mac_table(await client.read_mac_rules())


def _plan(
    operation: str,
    proposed: dict[str, Any],
    rows: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    required = {
        "add": {"name", "mac"},
        "set_enabled": {"mac", "enabled"},
        "delete": {"mac"},
    }
    if operation == "add":
        if set(proposed) != required["add"]:
            raise ValueError("Supply a MAC address and device name")
        name, mac = label(proposed["name"]), normalise_mac(proposed["mac"])
        indexes = [i for i, row in enumerate(rows) if row["mac"] == mac]
        new = {"mac": mac, "name": name, "enabled": True}
        if indexes:
            if len(indexes) == 1 and rows[indexes[0]] == new:
                return {}, rows
            raise ValueError("A MAC rule for this device already exists")
        if len(rows) >= 32:
            raise ValueError("The Hub portal permits up to 32 MAC rules")
        return {
            "NewFilterDevice": [{"HostName": name, "MACAddress": mac, "Enable": "true"}]
        }, rows + [new]
    if operation == "apply" and set(proposed) == {"edits"}:
        edits = batch_edits(proposed["edits"], key="mac")
    elif operation in {"delete", "set_enabled"} and set(proposed) == required[operation]:
        edits = batch_edits(
            [proposed | ({"delete": True} if operation == "delete" else {})], key="mac"
        )
    else:
        raise ValueError("Supply the fields needed for this MAC rule operation")
    for mac in edits:
        if sum(row["mac"] == mac for row in rows) != 1:
            raise ValueError("The MAC address is missing or matches multiple rules")
    expected = [
        row | {"enabled": edits.get(row["mac"], row["enabled"])}
        for row in rows
        if edits.get(row["mac"], False) is not None
    ]
    if expected == rows:
        return {}, rows
    enable = []
    delete = []
    for i, row in enumerate(rows):
        enabled = edits.get(row["mac"], row["enabled"])
        remove = enabled is None
        enable.append(i if enabled and not remove else -1)
        delete.append(i if remove else -1)
    return (
        {"EditFilterDevice": [{"DeleteData": delete, "EnableData": enable}]},
        expected,
    )


def _fingerprint(rows: list[dict[str, Any]]) -> Counter:
    return Counter((row["mac"], row["name"], row["enabled"]) for row in rows)


async def apply_mac_rule(client: HubClient, proposed: dict[str, Any]) -> dict[str, Any]:
    operation = proposed["operation"]
    fields = {key: value for key, value in proposed.items() if key != "operation"}
    before = await read_effective_mac_rules(client)
    if operation == "list":
        if fields:
            raise ValueError("List takes no MAC rule fields")
        return {"status": "read", "rules": before}
    payload, expected = _plan(operation, fields, before)
    if not payload:
        return {"status": "unchanged", "rules": before}
    expected_rows = _fingerprint(expected)
    checked = await write_and_verify(
        partial(client.write_mac_rules, payload),
        partial(read_effective_mac_rules, client),
        lambda latest: _fingerprint(latest) == expected_rows,
    )
    if checked.verified:
        return {"status": "verified", "rules": checked.latest}
    return {"status": "unverified", "rules": checked.latest, "write_issue": checked.write_issue}
