"""Validation rules shared by the captured router forms."""

from dataclasses import dataclass
from ipaddress import IPv4Address, ip_address
import re
from typing import Any

_MANAGED_SSIDS = frozenset(
    "libertyglobal telenet virginmedia ziggo horizonwi-free telenethomespot telenetwifree "
    "telenetsecure upcwifispots upcwi-free unitymediawifispot unitymediapublicwifispot vtr libertypr".split()
)
_MARKUP = ("<script", "</script>", "<iframe", "</iframe>", ".src")
_LABEL = re.compile(r"[A-Za-z0-9_-](?!.* {2})[A-Za-z0-9 _-]{0,63}\Z")
_RESTRICTED_UDP = frozenset({53, 135, 137, 139, 161, 162})
_RESTRICTED_TCP = _RESTRICTED_UDP | {25, 138, 445, 1080}


@dataclass(frozen=True)
class Provisioning:
    mode: str
    dslite: str | None

    def families(self, *, dhcp: bool = False) -> frozenset[str]:
        if self.mode == "1":
            return frozenset({"v4"})
        if self.mode == "2" and not (dhcp and self.dslite == "1"):
            return frozenset({"v6"})
        return frozenset({"v4", "v6"})

    def allows(self, group: str) -> bool:
        if group == "upnp":
            return self.mode != "2"
        if group == "mode_submit":
            return self.dslite != "1"
        if group in {"forwarding", "triggering", "dmz"}:
            return self.mode != "2" and self.dslite != "1"
        raise ValueError("Unknown provisioned action")

    def allows_target(self, host: str) -> bool:
        try:
            version = ip_address(host).version
        except ValueError:
            return True  # The Hub resolves host names.
        return not (
            (version == 6 and self.mode == "1")
            or (version == 4 and self.mode == "2" and self.dslite == "2")
        )


def ssid(value: Any) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("Use a non-empty Wi-Fi name with no leading or trailing whitespace")
    folded = re.sub(r"\s+", "", value).lower()
    if (
        len(value.encode("utf-8", errors="replace")) > 32
        or any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in value)
        or folded in _MANAGED_SSIDS
        or any(marker in folded for marker in _MARKUP)
    ):
        raise ValueError("Use a Wi-Fi name within 32 UTF-8 bytes that the Hub portal permits")
    return value


def passphrase(value: Any, *, open_network: bool, conflicting: tuple[str, ...]) -> str:
    if value == "" and open_network:
        return value
    lower = sum("a" <= c <= "z" for c in value) if isinstance(value, str) else 0
    upper = sum("A" <= c <= "Z" for c in value) if isinstance(value, str) else 0
    if (
        open_network
        or not isinstance(value, str)
        or not re.fullmatch(r"[!-~]{10,63}", value)
        or not (
            lower
            and upper
            and any(c.isdigit() for c in value)
            or len(value) >= 30
            and lower >= 3
            and upper >= 3
        )
        or any(marker in value for marker in _MARKUP)
    ):
        raise ValueError("Use a portal-valid Wi-Fi passphrase, or an empty key for an open network")
    if value in conflicting:
        raise ValueError("Main and guest Wi-Fi must not share the same passphrase")
    return value


def label(value: Any) -> str:
    if not isinstance(value, str) or not _LABEL.fullmatch(value):
        raise ValueError(
            "Use a portal-valid device name: letters, numbers, spaces, hyphens or underscores"
        )
    return value


def ipv4(value: Any) -> IPv4Address:
    if isinstance(value, str) and value.startswith("$"):
        return IPv4Address(int(value[1:].replace(" ", ""), 16))
    return IPv4Address(value)


def validate_port_range(
    start: Any, end: Any, *, protocol: str, field: str, restricted: bool
) -> None:
    """Apply the portal's range rules only where its form enables them."""
    if type(start) is not int or type(end) is not int or not 1 <= start <= end <= 65535:
        raise ValueError(f"Invalid {field} port range; use 1 through 65535 in ascending order")
    if restricted:
        blocked = _RESTRICTED_UDP if protocol == "UDP" else _RESTRICTED_TCP
        ports = sorted(port for port in blocked if start <= port <= end)
        if ports:
            raise ValueError(f"The Hub portal blocks {protocol} ports {ports} in the {field} range")


async def require_radio(client: Any) -> None:
    from .parser import flag, parse_script_group

    info = parse_script_group("radio", await client.read_script("radio"))
    states = [
        False if str(info.get(key)).lower() == "lowerlayerdown" else flag(info.get(key))
        for key in ("24g_stat", "5g_stat")
    ]
    if True not in states:
        raise ValueError("The Hub portal needs at least one active radio to edit Wi-Fi settings")


def batch_edits(raw: Any, *, key: str, delete_only: bool = False) -> dict[str, bool | None]:
    """Resolve input syntax before any mutation; None denotes deletion."""
    if not isinstance(raw, list) or not 1 <= len(raw) <= 32:
        raise ValueError("Supply between 1 and 32 row edits")
    edits = {}
    for item in raw:
        if not isinstance(item, dict) or not isinstance(item.get(key), str):
            raise ValueError("Each row edit needs its identifier")
        item_id = item[key]
        if key == "mac":
            # Import here to avoid a dependency cycle with the MAC table planner.
            from .mac_rules import normalise_mac

            item_id = normalise_mac(item_id)
        if item_id in edits:
            raise ValueError("An identifier may appear only once in a batch")
        if set(item) == {key, "delete"} and item["delete"] is True:
            edits[item_id] = None
        elif not delete_only and set(item) == {key, "enabled"} and type(item["enabled"]) is bool:
            edits[item_id] = item["enabled"]
        else:
            raise ValueError("For each row supply delete: true or one enabled value")
    return edits
