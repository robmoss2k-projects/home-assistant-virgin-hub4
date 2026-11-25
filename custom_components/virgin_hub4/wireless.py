"""Main Wi-Fi settings and the Wi-Fi-only MAC access list."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from functools import partial
import re
from typing import Any

from .client import HubClient, InvalidResponse
from .mac_rules import normalise_mac
from .parser import flag
from .portal import batch_edits, label, passphrase, require_radio, ssid
from .verification import write_and_verify

SECURITY = {"0": "None", "4": "WPA2-Personal", "5": "WPA-WPA2-Personal"}
POLICY = {"disabled": 1, "allow_list": 2, "deny_list": 3}
BANDS = ("band24", "band50")
_ESCAPES = {"&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"', "&#039;": "'"}


def _unescape(value: str) -> str:
    # Match the Hub's decoder exactly; do not HTML-decode arbitrary text/entities.
    return re.sub(r"&amp;|&lt;|&gt;|&quot;|&#039;", lambda m: _ESCAPES[m[0]], value)


@dataclass(frozen=True, repr=False)
class _State:
    config: dict[str, Any]
    passphrases: tuple[str, str]
    rules: list[dict[str, Any]]
    raw_rules: list[dict[str, Any]]


def _decode(data: dict[str, Any], raw_rules: Any) -> _State:
    config = data.get("Configuration")
    mac = data.get("MACFilter")
    if isinstance(config, dict):
        config = [config.get("0"), config.get("1")]
    if isinstance(mac, dict):
        mac = [mac.get("0"), mac.get("1")]
    if (
        not isinstance(config, list)
        or len(config) != 2
        or not all(isinstance(band, dict) for band in config)
        or not isinstance(mac, list)
        or not mac
        or not isinstance(mac[0], dict)
        or not isinstance(raw_rules, list)
        or len(raw_rules) > 32
    ):
        raise InvalidResponse("The Hub did not return both Wi-Fi bands and the access list")
    policies = {str(value): key for key, value in POLICY.items()}
    policy = policies.get(str(mac[0].get("BssAccessModeGrp")))
    if policy is None:
        raise InvalidResponse("The Hub did not report a supported Wi-Fi access policy")
    if len(mac) > 1 and isinstance(mac[1], dict) and "BssAccessModeGrp" in mac[1]:
        if policies.get(str(mac[1]["BssAccessModeGrp"])) != policy:
            raise InvalidResponse("The two bands report different Wi-Fi access policies")
    safe: dict[str, Any] = {"policy": policy}
    credentials = []
    by_label = {value: key for key, value in SECURITY.items()}
    for band, source in zip(BANDS, config, strict=True):
        ssid = source.get("SSID")
        broadcast = flag(source.get("SecuritySSIDBroadcastGrp"))
        security = str(source.get("SecurityModeGrp"))
        security = by_label.get(security, security)
        secret = source.get("Passphrase")
        if not isinstance(ssid, str) or broadcast is None or security not in SECURITY:
            raise InvalidResponse("The Hub did not return a supported Wi-Fi configuration")
        if not isinstance(secret, str):
            raise InvalidResponse("The Hub did not report the existing Wi-Fi passphrase")
        safe.update(
            {
                f"{band}_ssid": _unescape(ssid),
                f"{band}_broadcast": broadcast,
                f"{band}_security": security,
            }
        )
        credentials.append(_unescape(secret))
    rules = []
    for entry in raw_rules:
        if not isinstance(entry, dict):
            raise InvalidResponse("The Hub returned an invalid wireless MAC access entry")
        name, mac_address = entry.get("DeviceName"), entry.get("MACAddress")
        band = str(entry.get("SSIDIndex"))
        if not isinstance(name, str) or not isinstance(mac_address, str) or band not in ("1", "2"):
            raise InvalidResponse("The Hub returned an incomplete wireless MAC access entry")
        try:
            rules.append(
                {"name": name, "mac": normalise_mac(mac_address), "band": BANDS[int(band) - 1]}
            )
        except ValueError:
            raise InvalidResponse("The Hub returned an invalid wireless MAC address") from None
    if len({(row["mac"], row["band"]) for row in rules}) != len(rules):
        raise InvalidResponse("The Hub returned duplicate wireless MAC access entries")
    return _State(safe, (credentials[0], credentials[1]), rules, raw_rules)


async def _read(client: HubClient) -> _State:
    config = await client.read_wifi("wifi_security")
    table = await client.read_rules("wireless_filter_list")
    return _decode(config, table.get("WirelessFilterList"))


def _check_keys(config: dict[str, Any], keys: tuple[str, str]) -> None:
    for band, secret in zip(BANDS, keys, strict=True):
        if config[f"{band}_security"] == "0" and not secret:
            continue
        # A blank or masked value is not evidence of a usable preserved key.
        if not (
            (8 <= len(secret) <= 63 and set(secret) != {"*"})
            or re.fullmatch(r"[0-9A-Fa-f]{64}", secret)
        ):
            raise ValueError(
                "The existing Wi-Fi passphrase is missing or masked; this write cannot preserve it"
            )


def _full_payload(
    state: _State, config: dict[str, Any], *, delete: list[int], keys: tuple[str, str] | None = None
) -> dict[str, Any]:
    keys = state.passphrases if keys is None else keys
    _check_keys(config, keys)
    if config["band24_ssid"] == config["band50_ssid"] and (
        keys[0] != keys[1]
        or config["band24_security"] != config["band50_security"]
        or config["band24_broadcast"] != config["band50_broadcast"]
    ):
        raise ValueError(
            "The Hub links matching SSIDs; reconcile the two bands without changing either passphrase"
        )
    fields: dict[str, Any] = {"BssAccessModeGrp": POLICY[config["policy"]]}
    for band, suffix, secret in zip(BANDS, ("", "50"), keys, strict=True):
        fields.update(
            {
                f"SSID{suffix}": config[f"{band}_ssid"],
                f"SecuritySSIDBroadcastGrp{suffix}": int(config[f"{band}_broadcast"]),
                f"SecurityModeGrp{suffix}": SECURITY[config[f"{band}_security"]],
                f"bssIdxWPAPresharedKey{suffix}": secret,
            }
        )
    return {
        "RemoveMacFilterDevice": delete,
        "WirelessFilterList": state.raw_rules,
        "Configuration": fields,
    }


async def _plan_settings(
    client: HubClient, state: _State, changes: dict[str, Any]
) -> dict[str, Any]:
    if not changes or set(changes) - state.config.keys():
        raise ValueError("Provide supported main Wi-Fi settings")
    config = state.config | changes
    if config["policy"] not in POLICY:
        raise ValueError("Choose disabled, allow-list or deny-list")
    for band in BANDS:
        if f"{band}_ssid" in changes:
            ssid(config[f"{band}_ssid"])
        if (
            type(config[f"{band}_broadcast"]) is not bool
            or config[f"{band}_security"] not in SECURITY
        ):
            raise ValueError("Use a supported security mode and a true or false broadcast setting")
    if config["band24_ssid"] == config["band50_ssid"]:
        for field in ("broadcast", "security"):
            left, right = f"band24_{field}", f"band50_{field}"
            if right in changes and changes[right] != config[left]:
                raise ValueError("Matching SSIDs share the 2.4 GHz security and broadcast settings")
            if left in changes or "band24_ssid" in changes or "band50_ssid" in changes:
                config[right] = config[left]
    if any(config[f"{band}_broadcast"] != state.config[f"{band}_broadcast"] for band in BANDS):
        smart = await client.read_wifi("smart_wifi")
        admin, active = flag(smart.get("sonAdminStatus")), flag(smart.get("sonOperationalStatus"))
        if admin is None or active is None:
            raise ValueError(
                "Cannot confirm whether Wi-Fi optimisation locks the broadcast settings"
            )
        if admin and active:
            raise ValueError(
                "The Hub portal locks broadcast settings while Wi-Fi optimisation is active"
            )
    return config


async def _plan_keys(client, before, config, changes):
    if not changes:
        return before.passphrases, None
    guest = await client.read_wifi("guest")
    enabled = flag(guest.get("enable"))
    guest_key = guest.get("passphrase")
    if enabled is None or not isinstance(guest_key, str) or (guest_key and set(guest_key) == {"*"}):
        raise ValueError("The Hub did not report a verifiable guest key")
    protected_guest = (enabled, guest_key)
    keys = dict(zip(BANDS, before.passphrases, strict=True))
    for band, value in changes.items():
        keys[band] = passphrase(
            value,
            open_network=config[f"{band}_security"] == "0",
            conflicting=(guest_key,) if enabled else (),
        )
    if config["band24_ssid"] == config["band50_ssid"]:
        if "band50" in changes and keys["band50"] != keys["band24"]:
            raise ValueError("Matching SSIDs share the primary Wi-Fi passphrase")
        if "band24" in changes:
            keys["band50"] = keys["band24"]
    return (keys["band24"], keys["band50"]), protected_guest


def _rules_plan(
    state: _State, changes: dict[str, Any]
) -> tuple[dict[str, Any] | None, list[dict[str, Any]], bool]:
    operation = changes.get("operation")
    if operation == "apply" and set(changes) == {"operation", "edits"}:
        edits = batch_edits(changes["edits"], key="rule_id", delete_only=True)
        identities = {f"{r['band']}:{r['mac']}": i for i, r in enumerate(state.rules)}
        if not edits.keys() <= identities.keys():
            raise ValueError("A wireless MAC rule is no longer in the table")
        indexes = sorted(identities[key] for key in edits)
        return (
            _full_payload(state, state.config, delete=indexes),
            [row for i, row in enumerate(state.rules) if i not in indexes],
            False,
        )
    if operation not in ("add", "delete"):
        raise ValueError("Choose list, add, delete or apply")
    if set(changes) != (
        {"operation", "band", "mac", "name"} if operation == "add" else {"operation", "band", "mac"}
    ):
        raise ValueError("Supply the MAC address and band, plus the device name when adding")
    mac = normalise_mac(changes["mac"])
    band = changes["band"]
    if band not in (*BANDS, "both"):
        raise ValueError("Choose 2.4 GHz, 5 GHz or both bands")
    bands = BANDS if band == "both" else (band,)
    matched = {
        index
        for index, rule in enumerate(state.rules)
        if rule["mac"] == mac and rule["band"] in bands
    }
    if operation == "delete":
        if not matched:
            return None, state.rules, False
        remaining = [row for i, row in enumerate(state.rules) if i not in matched]
        return _full_payload(state, state.config, delete=sorted(matched)), remaining, False
    name = label(changes["name"])
    existing = {state.rules[i]["band"] for i in matched}
    new = [{"name": name, "mac": mac, "band": b} for b in bands if b not in existing]
    if not new:
        return None, state.rules, True
    if len(state.rules) + len(new) > 32:
        raise ValueError("The portal accepts up to 32 wireless MAC access entries")
    return (
        {
            "WirelessFilterList": [
                {
                    "DeviceName": raw["DeviceName"],
                    "MACAddress": raw["MACAddress"],
                    "SSIDIndex": int(raw["SSIDIndex"]),
                }
                for raw in state.raw_rules
            ],
            "NewFilterDevice": [
                {
                    "DeviceName": row["name"],
                    "MACAddress": row["mac"],
                    "SSIDIndex": BANDS.index(row["band"]) + 1,
                }
                for row in new
            ],
        },
        state.rules + new,
        True,
    )


def _fingerprint(rows: list[dict[str, Any]]) -> Counter:
    return Counter((r["band"], r["mac"], r["name"]) for r in rows)


def _public(state: _State) -> dict[str, Any]:
    return {
        "settings": state.config,
        "rules": [row | {"rule_id": f"{row['band']}:{row['mac']}"} for row in state.rules],
    }


async def apply_wireless(client: HubClient, group: str, changes: dict[str, Any]) -> dict[str, Any]:
    """Send a portal write once and independently confirm settings, list and retained keys."""
    before = await _read(client)
    if group == "wifi_access_list" and changes == {"operation": "list"}:
        return {"status": "read", **_public(before)}
    expected, rules, add_filter = before.config, before.rules, False
    keys, protected_guest = before.passphrases, None
    if group == "wifi_access_list":
        payload, rules, add_filter = _rules_plan(before, changes)
    else:
        key_changes = {
            band: changes[f"{band}_passphrase"] for band in BANDS if f"{band}_passphrase" in changes
        }
        public_changes = {
            key: value
            for key, value in changes.items()
            if key not in {f"{band}_passphrase" for band in BANDS}
        }
        if not public_changes and not key_changes:
            raise ValueError("Provide at least one main Wi-Fi setting")
        if public_changes:
            expected = await _plan_settings(client, before, public_changes)
        if key_changes or any(key != "policy" for key in public_changes):
            await require_radio(client)
        keys, protected_guest = await _plan_keys(client, before, expected, key_changes)
        payload = (
            _full_payload(before, expected, delete=[], keys=keys)
            if expected != before.config or keys != before.passphrases
            else None
        )
    if payload is None:
        return {"status": "unchanged", **_public(before)}
    expected_rules = _fingerprint(rules)

    async def read():
        latest = await _read(client)
        if protected_guest is not None:
            guest = await client.read_wifi("guest")
            if (flag(guest.get("enable")), guest.get("passphrase")) != protected_guest:
                return None
        return latest

    checked = await write_and_verify(
        partial(client.write_wifi_settings, payload, add_filter=add_filter),
        read,
        lambda latest: (
            latest.config == expected
            and _fingerprint(latest.rules) == expected_rules
            and latest.passphrases == keys
        ),
    )
    latest = checked.latest
    if checked.verified and latest is not None:
        return {
            "status": "verified",
            **_public(latest),
            **({"write_issue": checked.write_issue} if checked.write_issue else {}),
        }
    return {
        "status": "unverified",
        "write_issue": checked.write_issue,
        "passphrases_preserved": latest.passphrases == before.passphrases
        if latest is not None
        else None,
        **(_public(latest) if latest is not None else {}),
    }
