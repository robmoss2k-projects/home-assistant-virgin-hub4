"""Read a local HAR, reporting only coverage and non-identifying counts."""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
from urllib.parse import urlsplit

from custom_components.virgin_hub4.client import SCRIPT_READS
from custom_components.virgin_hub4.dhcp import decode_clients, decode_settings
from custom_components.virgin_hub4.ip_rules import read_ip_rule_tables
from custom_components.virgin_hub4.mac_rules import read_mac_table
from custom_components.virgin_hub4.parser import flag, parse_clients, parse_snapshot
from custom_components.virgin_hub4.port_rules import read_table as read_port_rule_table
from custom_components.virgin_hub4.preferences import decode_languages


def audit(path: Path) -> dict:
    with path.open(encoding="utf-8-sig") as stream:
        entries = json.load(stream)["log"]["entries"]
    paths = {value[0]: group for group, value in SCRIPT_READS.items()}
    groups = {}
    clients = None
    dhcp_replies = {}
    port_tables = {}
    mac_filter_rules = None
    language_fields = {}
    ddns_enabled = None
    json_reads = {
        "/php/associated_devices_data.php",
        "/php/ajaxGet_dhcp_setting_data.php",
        "/php/ajaxGet_portforwarding_data.php",
        "/php/ajaxGet_porttriggering_data.php",
        "/php/ajaxGet_macfilter_data.php",
        "/php/ajaxGet_macfilter_list_data.php",
        "/php/mac_blocktime.php",
        "/php/ip_blocktime.php",
        "/php/ajaxGet_wifi_settings_data.php",
        "/php/ajaxGet_guest_settings.php",
        "/php/wifi_data.php",
    }
    structured = set()
    encrypted = set()
    for entry in entries:
        request = entry["request"]
        url = urlsplit(request["url"])
        response = entry["response"]
        if (
            url.hostname not in ("192.168.0.1", "192.168.100.1")
            or request["method"] != "POST"
            or response["status"] != 200
        ):
            continue
        body = response["content"].get("text")
        if not body:
            continue
        if url.path in paths:
            groups[paths[url.path]] = body
        if url.path == "/php/user_data.php":
            try:
                reply = json.loads(body)
            except ValueError:
                reply = None  # Some user-data requests are signed out.
            if isinstance(reply, dict):
                language_fields.update(
                    {k: reply[k] for k in ("lang", "availableLang") if k in reply}
                )
                if "ddnsEnable" in reply:
                    ddns_enabled = flag(reply["ddnsEnable"])
        if url.path in json_reads:
            data = json.loads(body)
            if not isinstance(data, dict):
                raise ValueError("Expected a structured status response")
            structured.add(url.path)
            if "encryptedBlob" in data:
                encrypted.add(url.path)
            if url.path == "/php/associated_devices_data.php":
                clients = parse_clients(data)
            if url.path == "/php/ajaxGet_portforwarding_data.php":
                port_tables["forwarding"] = read_port_rule_table("forwarding", data)
            if url.path == "/php/ajaxGet_porttriggering_data.php":
                port_tables["triggering"] = read_port_rule_table("triggering", data)
            if url.path == "/php/ajaxGet_macfilter_list_data.php":
                mac_filter_rules = read_mac_table(data)
            if url.path == "/php/ajaxGet_dhcp_setting_data.php" and data.get("getting") in (
                "dhcpInfo",
                "clientTbl",
            ):
                dhcp_replies[data["getting"]] = data
    snapshot = parse_snapshot(groups, {"clients": clients})
    filter_counts = None
    if "ip_filter" in snapshot.groups:
        v4, v6 = read_ip_rule_tables(snapshot.groups["ip_filter"])
        filter_counts = {"ipv4": len(v4), "ipv6": len(v6)}
    dhcp = None
    if "dhcp" in snapshot.groups and dhcp_replies.keys() >= {"dhcpInfo", "clientTbl"}:
        settings = decode_settings(snapshot.groups["dhcp"], dhcp_replies["dhcpInfo"])
        reservations, clients_v4 = decode_clients(dhcp_replies["clientTbl"])
        dhcp = {
            "subnet_editable": settings.subnet_editable,
            "ipv4_clients": len(clients_v4),
            "reservations": len(reservations),
        }
    return {
        "script_groups": len(groups),
        "structured_read_routes": len(structured),
        "encrypted_read_routes": len(encrypted),
        "customer_devices": len(clients) if clients is not None else None,
        "client_network_fields": sorted(snapshot.groups.get("client_network", {})),
        "ddns_feature_flag": ddns_enabled,
        "ip_filter_rules": filter_counts,
        "mac_filter_rule_count": len(mac_filter_rules) if mac_filter_rules is not None else None,
        "port_rule_counts": {
            group: {
                "manual": sum(not row["dynamic"] for row in rows),
                "upnp": sum(row["dynamic"] for row in rows),
            }
            for group, rows in port_tables.items()
        },
        "dhcp": dhcp,
        "portal_language_choices": (
            len(decode_languages(language_fields, language_fields)["available_languages"])
            if language_fields.keys() >= {"lang", "availableLang"}
            else None
        ),
        "channels": {group: len(rows) for group, rows in snapshot.channels.items()},
        "log_sources": dict(Counter(row["source"] for row in snapshot.groups.get("events", []))),
        "cable_online": snapshot.online,
        "firmware": snapshot.groups["device"]["swVersion"],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("har", type=Path)
    print(json.dumps(audit(parser.parse_args().har), indent=2))
