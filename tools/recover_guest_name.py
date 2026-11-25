"""Recover just the guest SSID from a pre-change local Hub 4 capture, offline."""

from __future__ import annotations

import argparse
from getpass import GetPassWarning, getpass
import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
import warnings

from custom_components.virgin_hub4.client import HubError, SessionCrypto, _encode_password

_ROUTE = "/php/ajaxGet_guest_settings.php"
_HOSTS = {"192.168.0.1", "192.168.100.1"}


def recover(entries: list[dict], password: str) -> str:
    """Use the last guest-settings read only; never emit or retain any other field."""
    for entry in reversed(entries):
        request, response = entry["request"], entry["response"]
        url = urlsplit(request["url"])
        if (
            request["method"] != "POST"
            or url.hostname not in _HOSTS
            or url.path != _ROUTE
            or response["status"] != 200
        ):
            continue
        raw = response["content"].get("text", "").strip()
        if not raw or raw in {"0", '"0"'}:
            continue
        reply = json.loads(raw)
        sent = json.loads(parse_qs(request["postData"]["text"])["gnData"][0])
        if sent.get("authData") != "getGuestNetworkData":
            raise ValueError("Not a guest settings read")
        crypto = SessionCrypto.from_password(_encode_password(password), salt=sent["salt"])
        guest = crypto.open_response(reply, sent)
        name = guest.get("ssid")
        if not isinstance(name, str) or not 1 <= len(name.encode()) <= 32 or not name.isprintable():
            raise ValueError("Guest name is not usable")
        return name
    raise ValueError("Capture does not contain a guest settings read")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path, help="Pre-change HAR already on this computer")
    args = parser.parse_args()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", GetPassWarning)
            password = getpass("Hub settings password (input hidden; stays local): ")
    except EOFError, GetPassWarning, KeyboardInterrupt:
        print("Use an interactive terminal that can hide input.")
        return 2
    if not password:
        print("No password entered.")
        return 2
    try:
        entries = json.loads(args.capture.read_text(encoding="utf-8-sig"))["log"]["entries"]
        name = recover(entries, password)
    except OSError, ValueError, KeyError, TypeError, HubError:
        print("Could not recover the guest name. Check the settings password and pre-change file.")
        return 1
    print("Original guest Wi-Fi name: " + json.dumps(name, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
