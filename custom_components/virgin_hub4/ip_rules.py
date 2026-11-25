"""Manage the Hub's separate IPv4 and IPv6 filtering tables."""

from __future__ import annotations

from asyncio import get_running_loop
from collections import Counter
from functools import partial
from hashlib import sha256
from ipaddress import IPv4Address, IPv6Address, IPv6Network
import json
from typing import Any

from . import verification
from .client import HubClient, InvalidResponse
from .parser import flag, number, parse_script_group
from .portal import batch_edits, ipv4, validate_port_range
from .verification import write_and_verify

PROTOCOLS_V4 = ("All", "TCP", "UDP", "BOTH")
PROTOCOLS_V6 = (*PROTOCOLS_V4, "ICMPv6", "GRE", "ESP", "AH")
PORT_PROTOCOLS = {"TCP", "UDP", "BOTH"}
PORT_FIELDS = tuple(
    f"{side}_port_{bound}" for side in ("source", "destination") for bound in ("start", "end")
)
_PORT_COLUMNS = ("SrcPortStart", "SrcPortEnd", "DstPortStart", "DstPortEnd")
_V4_ANY = "0.0.0.0"
_DROPS_IPV6_PREFIX_ON_WRITE = {"01.04.092.07.23.EURO.PC20"}


def _ipv4_rule(value: str) -> tuple[str, str]:
    if value.lower() == "any":
        return _V4_ANY, _V4_ANY
    start, sep, end = value.partition("-")
    first = IPv4Address(start.strip())
    last = IPv4Address(end.strip()) if sep else None
    if last is not None and (int(last) == 0 or first > last):
        raise ValueError("IPv4 ranges must be in ascending order")
    return str(first), str(last) if last is not None else _V4_ANY


def _ipv6_rule(value: str) -> tuple[str, str]:
    if value.lower() == "any" or value == "::/0":
        return "::", "0"
    if "%" in value:
        raise ValueError("IPv6 scope IDs are not supported in filter rules")
    address, sep, length = value.partition("/")
    ip = IPv6Address(address)
    if not sep or length == "128":
        return str(ip), "0"
    prefix = number(length, integer=True)
    if prefix is None or not 64 <= prefix <= 127:
        raise ValueError("The Hub accepts IPv6 prefixes from /64 to /127, or a single address")
    return str(IPv6Network((ip, prefix), strict=False).network_address), str(prefix)


def _canonical_address(start: object, other: object, *, ip6: bool) -> str:
    if not isinstance(start, str) or "%" in start:
        raise ValueError("Invalid start address")
    if ip6:
        ip = IPv6Address(start)
        prefix = number(other, integer=True)
        if prefix is None or not 0 <= prefix <= 128:
            raise ValueError("Invalid IPv6 prefix")
        if prefix in (0, 128):
            return "any" if int(ip) == 0 and prefix == 0 else str(ip)
        return str(IPv6Network((ip, prefix), strict=False))
    first, last = IPv4Address(start), IPv4Address(other)
    if int(last) == 0:
        return "any" if int(first) == 0 else str(first)
    if first > last:
        raise ValueError("Invalid IPv4 address range")
    return str(first) if first == last else f"{first}-{last}"


def _table(values: dict[str, Any], *, ip6: bool) -> list[dict[str, Any]]:
    family = "v6" if ip6 else "v4"
    count = number(values.get(f"service_{family}_number_of_entries"), integer=True)
    columns = values.get(f"ip_{family}_filter_data")
    if count is None or not 0 <= count <= 512 or not isinstance(columns, dict):
        raise InvalidResponse("The Hub did not report a valid IP filter table")
    rows = []
    for i in range(1, count + 1):

        def get(name: str):
            column = columns.get(name)
            if isinstance(column, dict) and str(i) in column:
                return column[str(i)]
            raise InvalidResponse("The Hub IP filter table contained an incomplete row")

        key = get("KeyVal")
        protocol = get("Protocol")
        enabled = flag(get("EnableVal"))
        if (
            type(key) not in (str, int)
            or key == ""
            or not isinstance(protocol, str)
            or enabled is None
        ):
            raise InvalidResponse("An IP filter rule has no usable key, protocol or enabled state")
        row = {"protocol": "BOTH" if protocol == "UDP/TCP" else protocol, "enabled": enabled}
        try:
            row["source"] = _canonical_address(
                get("SrcStartAddr"), get("PrefixSrc" if ip6 else "SrcEndAddr"), ip6=ip6
            )
            row["destination"] = _canonical_address(
                get("DstStartAddr"), get("PrefixDst" if ip6 else "DstEndAddr"), ip6=ip6
            )
            for field, column in zip(PORT_FIELDS, _PORT_COLUMNS, strict=True):
                raw = get(column)
                port = number(raw, integer=True)
                if raw == "" and row["protocol"] not in PORT_PROTOCOLS:
                    port = 0
                if port is None or not 0 <= port <= 65535:
                    raise ValueError("Invalid port")
                row[field] = port
        except ValueError:
            raise InvalidResponse("The Hub returned an invalid IP filter address or port") from None
        if ip6:
            direction, policy = get("IPv6Direction"), get("Action")
            if direction not in ("incoming", "outgoing") or policy not in ("Allow", "Deny"):
                raise InvalidResponse("The Hub did not report an IPv6 filter direction or policy")
            row.update(direction=direction, policy=policy)
        rows.append(row | {"id": _identity(row), "_key": key})
    if len({str(row["_key"]) for row in rows}) != len(rows):
        raise InvalidResponse("The Hub returned duplicate IP filter keys")
    return rows


def _identity(row: dict[str, Any]) -> str:
    match = {k: v for k, v in row.items() if k not in {"id", "_key", "enabled"}}
    return sha256(json.dumps(match, sort_keys=True).encode()).hexdigest()[:20]


def _add(
    fields: dict[str, Any], values: dict[str, Any], *, ip6: bool
) -> tuple[dict[str, Any], dict[str, Any]]:
    required = {"protocol", "source", "destination", "enabled"}
    if ip6:
        required |= {"direction", "policy"}
    uses_ports = fields.get("protocol") in PORT_PROTOCOLS
    if uses_ports:
        required.update(PORT_FIELDS)
    if set(fields) != required:
        raise ValueError(
            "Supply address, protocol and enabled fields, and the required port ranges or IPv6 policy"
        )
    protocol = fields["protocol"]
    if (
        protocol not in (PROTOCOLS_V6 if ip6 else PROTOCOLS_V4)
        or type(fields["enabled"]) is not bool
    ):
        raise ValueError("Choose a supported protocol and explicitly set enabled")
    if not isinstance(fields["source"], str) or not isinstance(fields["destination"], str):
        raise ValueError("Supply source and destination as text")
    encode = _ipv6_rule if ip6 else _ipv4_rule
    src, src_other = encode(fields["source"])
    dst, dst_other = encode(fields["destination"])
    if not ip6:
        gateway = values.get("lan_gateway_ip")
        if isinstance(gateway, str) and gateway.startswith("$"):
            gateway = str(IPv4Address(int(gateway[1:], 16)))
        if src != _V4_ANY and src == gateway:
            raise ValueError("An IPv4 filter cannot use the Hub's own LAN address as its source")
        if src != _V4_ANY:
            try:
                low, high = ipv4(values["lan_start_dhcp"]), ipv4(values["lan_end_dhcp"])
            except KeyError, TypeError, ValueError:
                raise InvalidResponse(
                    "The Hub did not report the IPv4 filter source bounds"
                ) from None
            if (
                not low
                <= ipv4(src)
                <= (ipv4(src_other) if src_other != _V4_ANY else ipv4(src))
                <= high
            ):
                raise ValueError("IPv4 filter sources must be within the portal's advertised range")
    row = fields | {
        "source": _canonical_address(src, src_other, ip6=ip6),
        "destination": _canonical_address(dst, dst_other, ip6=ip6),
    }
    wire = {
        "Protocol": protocol,
        "SrcStartAddr": src,
        "DstStartAddr": dst,
        "Enable": int(fields["enabled"]),
    }
    if ip6:
        if fields["direction"] not in ("incoming", "outgoing") or fields["policy"] not in (
            "Allow",
            "Deny",
        ):
            raise ValueError("Choose an IPv6 direction and Allow or Deny")
        wire.update(
            PrefixSrc=src_other,
            PrefixDst=dst_other,
            IPv6Direction=fields["direction"],
            Action=fields["policy"],
        )
    else:
        wire.update(SrcEndAddr=src_other, DstEndAddr=dst_other)
    for field, column in zip(PORT_FIELDS, _PORT_COLUMNS, strict=True):
        port = fields.get(field, 0)
        if type(port) is not int or not 0 <= port <= 65535:
            raise ValueError("Use whole port numbers between 0 and 65535")
        row[field] = port
        wire[column] = str(port) if uses_ports or ip6 else ""
    if uses_ports:
        for side in ("source", "destination"):
            restricted = not ip6 or (
                side == "destination"
                and row["direction"] == "incoming"
                and row["policy"] == "Allow"
            )
            validate_port_range(
                row[f"{side}_port_start"],
                row[f"{side}_port_end"],
                protocol=protocol,
                field=side,
                restricted=restricted,
            )
    return wire, row | {"id": _identity(row)}


def _fingerprint(rows: list[dict[str, Any]]) -> Counter:
    return Counter((row["id"], row["enabled"]) for row in rows)


def _public(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{k: v for k, v in row.items() if k != "_key"} for row in rows]


def _overlap(new, row, *, ip6):
    # The captured IPv4 form checks containment, not the symmetric IPv6 overlap.
    equal = {"source", "destination", "protocol"} | ({"direction"} if ip6 else set())
    if not all(new[key] == row[key] for key in equal):
        return False
    if not ip6:
        return all(
            new[f"{side}_port_start"] <= row[f"{side}_port_start"]
            and row[f"{side}_port_end"] <= new[f"{side}_port_end"]
            for side in ("source", "destination")
        )
    return all(
        new[f"{side}_port_start"] <= row[f"{side}_port_end"]
        and row[f"{side}_port_start"] <= new[f"{side}_port_end"]
        for side in ("source", "destination")
    )


async def _read(client: HubClient) -> tuple[dict[str, Any], list, list]:
    values = parse_script_group("ip_filter", await client.read_script("ip_filter"))
    v4, v6 = read_ip_rule_tables(values)
    return values, v4, v6


def read_ip_rule_tables(
    values: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Normalize both IP filter tables from the same portal response."""
    return _table(values, ip6=False), _table(values, ip6=True)


async def apply_ip_rule(client: HubClient, proposed: dict[str, Any]) -> dict[str, Any]:
    """Resolve the current firmware key, send once and verify both tables."""
    family = proposed.get("family")
    operation = proposed.get("operation")
    if family not in ("ipv4", "ipv6") and not (family == "both" and operation == "apply"):
        raise ValueError("Select IPv4 or IPv6")
    ip6 = family == "ipv6"
    fields = {k: v for k, v in proposed.items() if k not in {"family", "operation"}}
    if operation != "list":
        families = await client.read_ip_provisioning(firewall=True)
        if family != "both" and family[-2:] not in families:
            raise ValueError(
                "The portal hides that IP filter family in the current provisioning mode"
            )
    values, v4, v6 = await _read(client)
    if operation == "apply" or operation in {"delete", "set_enabled"}:
        if operation == "apply":
            if (
                set(fields) != {"edits"}
                or not isinstance(fields["edits"], list)
                or not 1 <= len(fields["edits"]) <= 32
            ):
                raise ValueError("Supply between 1 and 32 IP filter row edits")
            if family == "both":
                if any(
                    not isinstance(edit, dict) or edit.get("family") not in ("ipv4", "ipv6")
                    for edit in fields["edits"]
                ):
                    raise ValueError("Supply a family for each edit in a mixed batch")
                by_family = {
                    version: [
                        {k: v for k, v in edit.items() if k != "family"}
                        for edit in fields["edits"]
                        if edit["family"] == version
                    ]
                    for version in ("ipv4", "ipv6")
                }
            else:
                by_family = {family: fields["edits"]}
        elif operation == "delete" and set(fields) == {"rule_id"}:
            by_family = {family: [fields | {"delete": True}]}
        elif operation == "set_enabled" and set(fields) == {"rule_id", "enabled"}:
            by_family = {family: [fields]}
        else:
            raise ValueError("Supply the rule ID and requested operation")
        tables = {"ipv4": v4, "ipv6": v6}
        writes = []
        for version, changes in by_family.items():
            if not changes:
                continue
            if version[-2:] not in families:
                raise ValueError("The portal hides an IP filter family in this batch")
            edits = batch_edits(changes, key="rule_id")
            rows = tables[version]
            for key, requested in edits.items():
                matches = [row for row in rows if row["id"] == key]
                if len(matches) != 1:
                    raise ValueError(
                        "The IP filter rule ID is missing or ambiguous; list current rules"
                    )
                target = matches[0]
                if requested is None or requested != target["enabled"]:
                    writes.append((requested is not None, version, key, requested))

        def public(rows4, rows6):
            return (
                {"ipv4_rules": _public(rows4), "ipv6_rules": _public(rows6)}
                if family == "both"
                else {"rules": _public(rows6 if ip6 else rows4)}
            )

        if not writes:
            return {"family": family, "status": "unchanged", **public(v4, v6)}

        async def read():
            _, rows4, rows6 = await _read(client)
            return rows4, rows6

        # The portal sends one request per row, deletes first. Unlike its UI,
        # resolve the next firmware key again: a deletion can renumber the table.
        clock = get_running_loop().time
        deadline = clock() + verification.READBACK_SECONDS
        ordered = sorted(writes, key=lambda item: item[:2])
        latest_rows = (v4, v6)
        issue = None
        verified = False
        for ix, (enable_edit, version, key, requested) in enumerate(ordered):
            if ix and clock() >= deadline:
                issue = "ReadbackDeadline"
                break
            current = tables[version]
            matches = [row for row in current if row["id"] == key]
            if len(matches) != 1:
                issue = "InvalidResponse"
                break
            next_rows = [
                row if row["id"] != key else row | {"enabled": requested}
                for row in current
                if row["id"] != key or enable_edit
            ]
            expected = tuple(
                _fingerprint(next_rows if name == version else tables[name])
                for name in ("ipv4", "ipv6")
            )
            checked = await write_and_verify(
                partial(
                    client.edit_ip_rule,
                    matches[0]["_key"],
                    ip6=version == "ipv6",
                    enabled=requested is True,
                    delete=not enable_edit,
                ),
                read,
                lambda observed: tuple(map(_fingerprint, observed)) == expected,
                poll_seconds=max(0, deadline - clock()),
            )
            latest_rows = checked.latest
            issue = checked.write_issue
            if not checked.verified or (issue is not None and ix < len(ordered) - 1):
                break
            if latest_rows is not None:
                tables = dict(zip(("ipv4", "ipv6"), latest_rows, strict=True))
            verified = ix == len(ordered) - 1
        latest = (
            public(*latest_rows)
            if latest_rows is not None
            else ({"ipv4_rules": None, "ipv6_rules": None} if family == "both" else {"rules": None})
        )
        return {
            "family": family,
            **latest,
            "status": "verified" if verified else "unverified",
            **({"write_issue": issue} if not verified else {}),
        }
    selected, other = (v6, v4) if ip6 else (v4, v6)
    before = {"family": family, "rules": _public(selected)}
    if operation == "list" and not fields:
        return before | {"status": "read"}
    if operation == "add":
        wire, new = _add(fields, values, ip6=ip6)
        identical = [row for row in selected if row["id"] == new["id"]]
        if identical:
            if len(identical) == 1 and identical[0]["enabled"] == new["enabled"]:
                return before | {"status": "unchanged"}
            raise ValueError("This rule already exists; use set_enabled instead")
        if not ip6 and len(selected) >= 32:
            raise ValueError("The Hub portal permits up to 32 IPv4 IP rules")
        if any(_overlap(new, row, ip6=ip6) for row in selected):
            raise ValueError(
                "This IP filter overlaps another rule for the same addresses and protocol"
            )
        if ip6 and any("/" in new[field] for field in ("source", "destination")):
            device = parse_script_group("device", await client.read_script("device"))
            if device.get("swVersion") in _DROPS_IPV6_PREFIX_ON_WRITE:
                raise ValueError(
                    "This Hub firmware drops IPv6 prefixes on write; use individual IPv6 addresses"
                )
        expected = [*selected, new]
        write = partial(client.add_ip_rule, wire, ip6=ip6)
    else:
        raise ValueError("Supply the fields for list, add, set_enabled, delete or apply")

    async def read() -> tuple[list, list]:
        _, v4, v6 = await _read(client)
        return (v6, v4) if ip6 else (v4, v6)

    expected_rows, expected_other = _fingerprint(expected), _fingerprint(other)
    checked = await write_and_verify(
        write,
        read,
        lambda latest: (
            _fingerprint(latest[0]) == expected_rows and _fingerprint(latest[1]) == expected_other
        ),
    )
    rules = _public(checked.latest[0]) if checked.latest is not None else None
    if checked.verified:
        return {"family": family, "rules": rules, "status": "verified"}
    return {
        "family": family,
        "rules": rules,
        "status": "unverified",
        "write_issue": checked.write_issue,
    }
