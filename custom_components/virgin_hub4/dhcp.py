"""DHCPv4 pool settings, DHCPv6 mode and IPv4 reservations."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from functools import partial
from ipaddress import IPv4Address, IPv4Network, ip_address
from typing import Any

from .client import HubClient, InvalidResponse, normalize_host
from .mac_rules import normalise_mac
from .parser import flag, number, parse_script_group
from .verification import write_and_verify

_V4_ENABLED = {"1": True, "true": True, "2": False, "false": False}
_V6_MODES = {"1": "stateful", "2": "stateless", "stateful": "stateful", "stateless": "stateless"}
_V4_FIELDS = {"enabled", "pool_start", "pool_end", "address_count", "lease_seconds", "subnet_mask"}


def _ipv4(raw: Any) -> IPv4Address:
    if not isinstance(raw, str):
        raise ValueError("Expected a dotted IPv4 address")
    if raw.startswith("$"):
        return IPv4Address(int(raw[1:], 16))
    return IPv4Address(raw)


@dataclass(frozen=True)
class DhcpState:
    v4: dict[str, Any]
    v6: str
    subnet_editable: bool
    subnet_table: dict[str, Any]

    def public(self) -> dict[str, Any]:
        return {"ipv4": self.v4, "ipv6_mode": self.v6, "subnet_editable": self.subnet_editable}


def decode_settings(script: dict[str, Any], data: dict[str, Any]) -> DhcpState:
    """Require the editable fields and reconcile both views of the current IPv4 LAN."""
    enabled = _V4_ENABLED.get(str(data.get("enableV4")).lower())
    v6 = _V6_MODES.get(str(data.get("typeV6")).lower())
    lease = number(data.get("leaseTimeV4"), integer=True)
    hidden = flag(script.get("hide_customer_dhcp_lan_change"))
    if enabled is None or v6 is None or lease is None or hidden is None:
        raise InvalidResponse("The Hub did not report its DHCP settings or subnet capability")
    mapping = {
        "gateway": ("subnetIp", "lan_gateway_ip"),
        "subnet_mask": ("subnetMask", "lan_subnet_mask"),
        "pool_start": ("startAddrV4", "lan_start_dhcp"),
        "pool_end": ("endAddrV4", "lan_end_dhcp"),
    }
    v4 = {"enabled": enabled, "lease_seconds": lease}
    for name, (json_key, script_key) in mapping.items():
        try:
            left, right = _ipv4(data.get(json_key)), _ipv4(script.get(script_key))
        except ValueError:
            raise InvalidResponse("The Hub did not report complete DHCP IPv4 addresses") from None
        if left != right:
            raise InvalidResponse("The two Hub pages disagree about the DHCP IPv4 configuration")
        v4[name] = str(left)
    subnet_table = script.get("lan_subnet_table")
    return DhcpState(v4, v6, not hidden, subnet_table if isinstance(subnet_table, dict) else {})


def decode_clients(data: dict[str, Any]) -> tuple[list[dict[str, str]], dict[IPv4Address, str]]:
    reservations = data.get("staticData")
    clients = data.get("clientData")
    if not isinstance(reservations, list) or not isinstance(clients, list):
        raise InvalidResponse("The Hub did not return both DHCP tables")
    rows = []
    leased: dict[IPv4Address, str] = {}
    try:
        for row in reservations:
            if not isinstance(row, list) or len(row) < 2 or not isinstance(row[0], str):
                raise ValueError
            rows.append({"mac": normalise_mac(row[0]), "address": str(_ipv4(row[1]))})
        for row in clients:
            if not isinstance(row, list) or len(row) < 6 or not isinstance(row[4], str):
                raise ValueError
            if not row[4].strip():  # Portal excludes rows with no connection type.
                continue
            address = ip_address(row[2])
            if not isinstance(address, IPv4Address) or address.is_unspecified:
                continue
            mac = normalise_mac(row[1])
            if address in leased and leased[address] != mac:
                raise ValueError
            leased[address] = mac
    except ValueError, TypeError:
        raise InvalidResponse(
            "The Hub returned an incomplete reservation or connected-device row"
        ) from None
    if len({r["address"] for r in rows}) != len(rows):
        raise InvalidResponse("The Hub returned multiple DHCP reservations for the same address")
    return rows, leased


async def _read_settings(client: HubClient) -> DhcpState:
    fragment = parse_script_group("dhcp", await client.read_script("dhcp"))
    return decode_settings(fragment, await client.read_dhcp(clients=False))


def _check_allowed_subnet(network: IPv4Network, state: DhcpState) -> None:
    normalize_host(str(network.network_address + 1))
    normalize_host(str(network.broadcast_address - 1))
    ips = state.subnet_table.get("LanAllowedSubnetIP", {})
    masks = state.subnet_table.get("LanAllowedSubnetMask", {})
    if not isinstance(ips, dict) or not isinstance(masks, dict):
        raise ValueError("The Hub's allowed subnet table is invalid")
    allowed = [
        IPv4Network((_ipv4(ip), str(_ipv4(masks[key]))), strict=False)
        for key, ip in ips.items()
        if ip and masks.get(key)
    ]
    if allowed and not any(network.subnet_of(item) for item in allowed):
        raise ValueError("This subnet is not in the Hub's allowed LAN ranges")


def _plan_v4(
    state: DhcpState,
    changes: dict[str, Any],
    rows: list[dict[str, str]],
    leases: dict[IPv4Address, str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    fields = {key: value for key, value in changes.items() if key != "confirm_network_change"}
    if not fields or set(fields) - _V4_FIELDS or {"pool_end", "address_count"} <= fields.keys():
        raise ValueError("Supply IPv4 settings; specify either pool end or address count, not both")
    before = state.v4
    applied = before | fields
    start = _ipv4(applied["pool_start"])
    count = applied.pop("address_count", None)
    if "address_count" in fields:
        if type(count) is not int or not 1 <= count <= 256:
            raise ValueError("The DHCP pool must contain 1 to 256 addresses")
        end = start + (count - 1)
    else:
        old_count = int(_ipv4(before["pool_end"])) - int(_ipv4(before["pool_start"])) + 1
        end = (
            start + (old_count - 1)
            if "pool_start" in fields and "pool_end" not in fields
            else _ipv4(applied["pool_end"])
        )
    if not 1 <= int(end) - int(start) + 1 <= 256:
        raise ValueError("The DHCP pool must contain 1 to 256 addresses in ascending order")
    mask = str(_ipv4(applied["subnet_mask"]))
    if not state.subnet_editable and mask != before["subnet_mask"]:
        raise ValueError("This firmware hides the LAN subnet mask in the admin portal")
    if start != _ipv4(before["pool_start"]) and (int(start) >> 8 & 255) in {100, 253, 254}:
        raise ValueError("The portal reserves that third octet for other functions")
    network = IPv4Network((start, mask), strict=False)
    if not 1 <= network.prefixlen <= 30:
        raise ValueError("Use a contiguous subnet mask with room for DHCP clients and the gateway")
    old_gateway = _ipv4(before["gateway"])
    old_network = IPv4Network((old_gateway, before["subnet_mask"]), strict=False)
    if not state.subnet_editable and (
        int(start) >> 16 != int(_ipv4(before["pool_start"])) >> 16
        or int(start) >> 8 != int(end) >> 8
        or (int(end) & 255) > 254
    ):
        raise ValueError("The portal fixes the first two octets and limits the pool end to .254")
    if network != old_network:
        _check_allowed_subnet(network, state)
    gateway = old_gateway if network == old_network else network.network_address + 1
    if (
        start == network.network_address
        or end not in network
        or end == network.broadcast_address
        or start <= gateway <= end
    ):
        raise ValueError(
            "The pool must fit the LAN and exclude its gateway and reserved network addresses"
        )
    enabled, lease = applied["enabled"], applied["lease_seconds"]
    if type(enabled) is not bool or type(lease) is not int or not 120 <= lease <= 604800:
        raise ValueError("Use true or false and a lease time of 120 to 604800 seconds")
    excludes_client = any(
        not start <= address <= end
        for address in leases
        if _ipv4(before["pool_start"]) <= address <= _ipv4(before["pool_end"])
    )
    excludes_reserved = any(_ipv4(row["address"]) not in network for row in rows)
    if (
        network != old_network
        or (before["enabled"] and not enabled)
        or excludes_client
        or excludes_reserved
    ) and changes.get("confirm_network_change") is not True:
        raise ValueError(
            "This may interrupt the LAN or strand a client or reservation; explicit network-change confirmation is required"
        )
    applied.update(pool_start=str(start), pool_end=str(end), gateway=str(gateway), subnet_mask=mask)
    return {
        "setting": "dhcpV4",
        "enableV4": str(enabled).lower(),
        "startAddrV4": str(start),
        "endAddrV4": str(end),
        "subnetMask": mask,
        "leaseTimeV4": str(lease),
        "lanGwAddrV4": str(gateway),
    }, applied


def _plan_reservation(
    state: DhcpState,
    fields: dict[str, Any],
    rows: list[dict[str, str]],
    leases: dict[IPv4Address, str],
) -> tuple[dict[str, Any] | None, list[dict[str, str]]]:
    operation = fields.get("operation")
    if (operation not in ("add", "delete")) or set(fields) != {"operation", "mac", "address"}:
        raise ValueError("For add or delete, specify both the IPv4 address and device MAC")
    address = _ipv4(fields["address"])
    mac = normalise_mac(fields["mac"])
    proposed = {"mac": mac, "address": str(address)}
    if operation == "delete":
        if proposed not in rows:
            raise ValueError("No matching reservation; refresh the list before deleting")
        return {"setting": "delete", "delIdx": [str(address)]}, [
            row for row in rows if row != proposed
        ]
    if proposed in rows:
        return None, rows
    gateway = _ipv4(state.v4["gateway"])
    network = IPv4Network((gateway, state.v4["subnet_mask"]), strict=False)
    if address not in network or address in (
        gateway,
        network.network_address,
        network.broadcast_address,
    ):
        raise ValueError("Reserve a usable address on the current LAN, not its gateway")
    if len(rows) >= 32:
        raise ValueError("The portal supports up to 32 DHCP reservations")
    if any(row["address"] == str(address) or row["mac"] == mac for row in rows):
        raise ValueError("That IPv4 address or MAC already has a DHCP reservation")
    if address in leases and leases[address] != mac:
        raise ValueError("That address is assigned to a different connected device")
    return {"setting": "static", "staticIP": str(address), "staticMAC": mac}, [*rows, proposed]


def _fingerprint(rows: list[dict[str, str]]) -> Counter:
    return Counter((row["mac"], row["address"]) for row in rows)


async def apply_dhcp(client: HubClient, group: str, changes: dict[str, Any]) -> dict[str, Any]:
    """Set once, then check the applicable DHCP state and reservation table."""
    if group in {"dhcp_v4", "dhcp_v6"} and group[-2:] not in await client.read_ip_provisioning(
        firewall=False
    ):
        raise ValueError("The portal hides that DHCP family in the current IP provisioning mode")
    state = await _read_settings(client)
    rows, leased = await _read_clients(client) if group != "dhcp_v6" else ([], {})
    expected_v4, expected_v6, expected_rows = state.v4, state.v6, rows
    if group == "dhcp_reservations":
        if changes == {"operation": "list"}:
            return {"status": "read", "reservations": rows}
        if changes.get("operation") == "apply" and set(changes) == {"operation", "edits"}:
            edits = changes["edits"]
            if not isinstance(edits, list) or not 1 <= len(edits) <= 32:
                raise ValueError("Supply between 1 and 32 reservation deletions")
            addresses = []
            for edit in edits:
                if (
                    not isinstance(edit, dict)
                    or set(edit) != {"mac", "address", "delete"}
                    or edit["delete"] is not True
                ):
                    raise ValueError(
                        "A reservation edit requires its MAC, address and delete: true"
                    )
                delete, expected_rows = _plan_reservation(
                    state,
                    {"operation": "delete", "mac": edit["mac"], "address": edit["address"]},
                    expected_rows,
                    leased,
                )
                addresses.extend(delete["delIdx"])
            payload = {"setting": "delete", "delIdx": addresses}
        else:
            payload, expected_rows = _plan_reservation(state, changes, rows, leased)
    elif group == "dhcp_v4":
        payload, expected_v4 = _plan_v4(state, changes, rows, leased)
        if expected_v4 == state.v4:
            payload = None
    else:
        if set(changes) != {"mode"} or changes["mode"] not in ("stateful", "stateless"):
            raise ValueError("Choose stateful or stateless IPv6 autoconfiguration")
        expected_v6 = changes["mode"]
        payload = (
            {"setting": "dhcpV6", "typeV6": expected_v6.capitalize()}
            if expected_v6 != state.v6
            else None
        )
    response = state.public() | ({"reservations": rows} if group != "dhcp_v6" else {})
    if payload is None:
        return {"status": "unchanged", **response}
    requested_gateway = (
        expected_v4["gateway"] if expected_v4["gateway"] != state.v4["gateway"] else None
    )

    async def read() -> dict[str, Any]:
        after = await _read_settings(client)
        current_rows, _ = await _read_clients(client) if group != "dhcp_v6" else ([], {})
        return after.public() | ({"reservations": current_rows} if group != "dhcp_v6" else {})

    expected = {"ipv4": expected_v4, "ipv6_mode": expected_v6}
    expected_reservations = _fingerprint(expected_rows)
    checked = await write_and_verify(
        partial(client.write_dhcp, payload),
        read,
        lambda latest: (
            all(latest[key] == value for key, value in expected.items())
            and _fingerprint(latest.get("reservations", [])) == expected_reservations
        ),
        reject_reply=lambda reply: reply is not None,
    )
    if checked.reply is not None:
        return {"status": "rejected", "reason": checked.reply, "readback": None}
    if checked.verified and checked.latest is not None:
        return {"status": "verified", **checked.latest}
    return {
        "status": "unverified",
        "reason": checked.write_issue if checked.write_issue is not None else checked.reply,
        "readback": checked.latest,
        **({"requested_gateway": requested_gateway} if requested_gateway else {}),
    }


async def _read_clients(client: HubClient) -> tuple[list[dict[str, str]], dict[IPv4Address, str]]:
    return decode_clients(await client.read_dhcp(clients=True))
