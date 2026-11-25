"""Parse the Hub's data-only fragments without executing JavaScript."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import re
from typing import Any

from .client import InvalidResponse

_VARIABLE = re.compile(r"^[ \t]*var[ \t]+js_(\w{1,75})[ \t]*=[ \t]*", re.M)
_JS_STRING = re.compile(r"""(['"])((?:\\[\s\S]|(?!\1)[^\\\r\n])*)\1""")
_ESCAPE = re.compile(r"\\(?:u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2})|([\s\S]))")
_SECRET = re.compile(
    r"pass(?:word|phrase)|preshared|psk|(?:wps|device).*pin|encryptedblob"
    r"|authdata|nonce|(?:^|_)salt$|^iv$|credential|^24psa$|^50psa$",
    re.I,
)
_DURATION = re.compile(r"(\d+) days? (\d+)h:(\d+)m:(\d+)s\Z")
_DOCSIS_DATE = re.compile(r"^[A-Za-z]{3} \d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}$")
_GATEWAY_DATE = re.compile(r"^[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}$")
_ADDRESS = re.compile(
    r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}|"
    r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])|"
    r"(?<![\w:])(?:[0-9a-f]{0,4}:){2,}[0-9a-f]{0,4}(?![\w:])",
    re.I,
)
_JSON = json.JSONDecoder()

REQUIRED_MARKERS: dict[str, tuple[str, ...]] = {
    "home": ("cm_reg_value", "cm_oper_value"),
    "device": ("swVersion", "systemUptime"),
    "line": ("provisioningState", "downStreamChannel", "upStreamChannel"),
    "mode": ("RouterMode",),
    "client_network": ("ipv6_prefix", "lan_subnet_mask"),
    "radio": ("24g_stat", "5g_stat"),
    "wps": ("WPSPbcEnable",),
    "firewall": ("v4Enable", "v6Enable"),
    "mac_filter": ("macFilterList",),
    "ip_filter": ("ip_v4_filter_data", "ip_v6_filter_data"),
    "forwarding": ("PortMappingData",),
    "triggering": ("PortTriggeringData",),
    "dmz": ("DMZ_State",),
    "dhcp": ("lan_subnet_mask",),
    "upnp": ("UPnP_Status",),
    "mtu": ("MTUSize",),
    "light_ring": ("lightring_value",),
    "ping_config": ("dataBlockSize", "numberOfRepititions"),
    "trace_config": ("MaxHopCount",),
}

# Column order checked against the Hub's device_networkstatus.js, not assumed
# from observed values. In particular DOCSIS 3.1 fields are not 3.0 fields.
CHANNEL_COLUMNS = {
    ("downStreamChannel", "downstream_sc_qam"): (
        "channel_id",
        "frequency_hz",
        "power_dbmv",
        "snr_db",
        "modulation",
        "lock",
        "rxmer_db",
        "pre_rs_errors",
        "post_rs_errors",
    ),
    ("downStreamChannel31", "downstream_ofdm"): (
        "channel_id",
        "width_mhz",
        "fft_type",
        "active_subcarriers",
        "modulation",
        "first_active_subcarrier_raw",
        "lock",
        "rxmer_db",
        "plc_power_dbmv",
        "corrected_active_profile",
        "uncorrectable_active_profile",
    ),
    ("upStreamChannel", "upstream_sc_qam"): (
        "channel_id",
        "frequency_hz",
        "power_dbmv",
        "symbol_rate_reported",
        "modulation",
        "channel_type",
        "t1_timeouts",
        "t2_timeouts",
        "t3_timeouts",
        "t4_timeouts",
    ),
    ("upStreamChannel31", "upstream_ofdma"): (
        "channel_id",
        "width_mhz",
        "power_dbmv",
        "fft_type",
        "modulation",
        "channel_type",
        "active_subcarriers",
        "first_active_subcarrier_raw",
        "t3_timeouts",
        "t4_timeouts",
    ),
}


def _unescape(value: str) -> str:
    translations = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}

    def replace(match: re.Match[str]) -> str:
        unicode, hexa, simple = match.groups()
        if unicode or hexa:
            return chr(int(unicode or hexa, 16))
        if simple in ("\n", "\r"):
            return ""
        return translations.get(simple, simple)

    return _ESCAPE.sub(replace, value)


def parse_assignments(body: str) -> dict[str, Any]:
    """Read literal assignments only; never interpret arbitrary scripts."""
    parsed: dict[str, Any] = {}
    for match in _VARIABLE.finditer(body):
        key = match.group(1)
        if key in parsed:
            raise InvalidResponse("Duplicate variable in Hub data")
        offset = match.end()
        if (quoted := _JS_STRING.match(body, offset)) is not None:
            value = _unescape(quoted.group(2))
            end = quoted.end()
        else:
            try:
                value, end = _JSON.raw_decode(body, offset)
            except ValueError:
                continue
        # Never accept expressions like an assignment followed by +, a call,
        # or a concatenation. Nothing in this parser runs the response.
        if re.match(r"[ \t]*;", body[end:]) is None:
            continue
        parsed[key] = value
    if not parsed:
        raise InvalidResponse("No Hub data literals found")
    return parsed


def _decode_structure(value: Any) -> Any:
    if isinstance(value, str) and value.strip().startswith(("[", "{")):
        try:
            return json.loads(value)
        except ValueError:
            pass
    return value


def clean(value: Any) -> Any:
    """Remove secrets from Hub data before it enters a snapshot."""
    if isinstance(value, dict):
        return {key: clean(item) for key, item in value.items() if not _SECRET.search(key)}
    if isinstance(value, list):
        return [clean(item) for item in value]
    return value


def number(value: Any, *, integer: bool = False) -> int | float | None:
    if isinstance(value, bool) or value in (None, ""):
        return None
    if not re.fullmatch(r"[+-]?\d+(?:\.\d+)?", str(value).strip()):
        return None
    try:
        return int(value) if integer else float(value)
    except TypeError, ValueError, OverflowError:
        return None


def flag(value: object) -> bool | None:
    if value is None:
        return None
    lowered = str(value).lower()
    if lowered in {"true", "1", "up", "on", "enabled", "allowed", "locked"}:
        return True
    if lowered in {"false", "0", "down", "off", "disabled", "denied", "unlocked"}:
        return False
    return None


def seconds(value: object) -> int | None:
    if match := _DURATION.fullmatch(str(value).strip()):
        days, hours, minutes, secs = map(int, match.groups())
        return days * 86400 + hours * 3600 + minutes * 60 + secs
    return None


def parse_script_group(group: str, body: str) -> dict[str, Any]:
    values = parse_assignments(body)
    if not all(key in values for key in REQUIRED_MARKERS[group]):
        raise InvalidResponse(f"Incomplete {group} payload")
    if group in {"ip_filter", "forwarding", "triggering", "dhcp", "mac_filter"}:
        values = {key: _decode_structure(value) for key, value in values.items()}
    return clean(values)


def parse_channels(line: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    channels = {}
    for (key, family), columns in CHANNEL_COLUMNS.items():
        rows = line.get(key)
        if rows is None:
            continue
        if not isinstance(rows, list):
            raise InvalidResponse(f"Expected a channel list for {family}")
        result = []
        seen = set()
        for row in rows:
            if not isinstance(row, list) or len(row) != len(columns):
                raise InvalidResponse(f"Unexpected channel schema for {family}")
            channel = dict(zip(columns, row, strict=True))
            channel_id = str(channel["channel_id"])
            if not re.fullmatch(r"\d{1,5}", channel_id) or channel_id in seen:
                raise InvalidResponse(f"Invalid or repeated channel ID for {family}")
            seen.add(channel_id)
            channel["channel_id"] = channel_id
            for field in columns:
                if field.endswith(("_errors", "_timeouts", "_profile")) or field in {
                    "frequency_hz",
                    "active_subcarriers",
                }:
                    channel[field] = number(channel[field], integer=True)
                elif field.endswith(("_db", "_dbmv", "_mhz")):
                    channel[field] = number(channel[field])
            result.append(channel)
        channels[family] = result
    return channels


def parse_clients(data: dict[str, Any]) -> list[dict[str, Any]]:
    count = number(data.get("numHostEnt"), integer=True)
    if count is None or not 0 <= count <= 1024:
        raise InvalidResponse("Missing or invalid associated-device count")
    columns = {
        "hostName": "hostname",
        "phyAddress": "mac",
        "ipAddress": "ipv4",
        "ipv6Address": "ipv6",
        "layer1Interface": "interface",
        "active": "active",
        "FriendlyName": "friendly_name",
        "SSID": "ssid",
        "maxBitRate": "link_rate",
        "lastDownLinkRate": "downlink_rate",
        "HotSpot": "hotspot",
    }
    result = []
    for index in range(count):
        record = {}
        for original, key in columns.items():
            values = data.get(original)
            if isinstance(values, list) and index < len(values):
                value = values[index]
            elif count == 1 and isinstance(values, (str, int, float)):
                value = values
            else:
                continue
            if key in {"active", "hotspot"}:
                value = flag(value)
            if value not in ("", "EMPTY", None):
                record[key] = value
        if record:
            result.append(record)
    if len(result) != count:
        raise InvalidResponse("Associated-device count disagrees with the response")
    return result


def parse_logs(rows: Any) -> list[dict[str, Any]]:
    """Preserve timestamps and priority without publishing sensitive log text."""
    if not isinstance(rows, list):
        raise InvalidResponse("Expected a Hub event list")
    result = []
    for row in rows:
        if not (isinstance(row, list) and len(row) == 3 and all(isinstance(x, str) for x in row)):
            raise InvalidResponse("Unexpected Hub event format")
        clock, priority, text = row
        docsis = _DOCSIS_DATE.fullmatch(clock)
        gateway = _GATEWAY_DATE.fullmatch(clock)
        source = "docsis" if docsis else "gateway" if gateway else "unknown"
        if "sw download" in text.lower():
            category = (
                "firmware_download_succeeded"
                if "successful" in text.lower()
                else "firmware_download_started"
                if "init" in text.lower()
                else "firmware_download"
            )
        elif match := re.search(r"\b(T[1-4])\s+time[ -]?out", text, re.I):
            category = match.group(1).lower() + "_timeout"
        else:
            category = "other_docsis_event" if docsis else "gateway_notice"
        message = (
            "[credential detail omitted]"
            if _SECRET.search(text)
            else _ADDRESS.sub("[address]", text)
        )
        result.append(
            {
                "router_time": clock,
                "priority": priority,
                "source": source,
                "category": category,
                "message": message[:1200],
                "_fingerprint": sha256(json.dumps(row).encode()).hexdigest(),
            }
        )
    return result


@dataclass(frozen=True)
class Snapshot:
    """One collection, with incomplete secondary sections explicitly identified."""

    groups: dict[str, Any]
    errors: dict[str, str]
    observed_at: datetime

    @property
    def uptime(self) -> int | None:
        return seconds(self.groups["device"].get("systemUptime"))

    @property
    def online(self) -> bool | None:
        state = number(self.groups["line"].get("provisioningState"), integer=True)
        return state >= 6 if state is not None else None

    @property
    def channels(self) -> dict[str, list[dict[str, Any]]]:
        return self.groups["channels"]


def parse_snapshot(
    sections: dict[str, str],
    additional: dict[str, Any] | None = None,
    errors: dict[str, str] | None = None,
    *,
    observed_at: datetime | None = None,
) -> Snapshot:
    """Build a snapshot from raw fragments, for offline capture analysis."""
    parsed = {name: parse_script_group(name, body) for name, body in sections.items()}
    return assemble_snapshot(parsed, additional, errors, observed_at=observed_at)


def assemble_snapshot(
    sections: dict[str, dict[str, Any]],
    additional: dict[str, Any] | None = None,
    errors: dict[str, str] | None = None,
    *,
    observed_at: datetime | None = None,
) -> Snapshot:
    """Assemble already-validated script data and sanitize additional groups."""
    line = sections["line"].copy()
    groups = sections | {"line": line, "channels": parse_channels(line)}
    if "networkData" in line:
        groups["events"] = parse_logs(line.pop("networkData"))
    for key, _family in CHANNEL_COLUMNS:
        line.pop(key, None)
    groups.update(clean(additional or {}))
    return Snapshot(groups, errors or {}, observed_at or datetime.now(timezone.utc))
