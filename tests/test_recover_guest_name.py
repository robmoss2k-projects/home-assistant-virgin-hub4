"""Synthetic, offline checks for narrowly scoped guest-name recovery."""

import json
from urllib.parse import urlencode

import pytest

from custom_components.virgin_hub4.client import InvalidResponse, SessionCrypto, _encode_password
from tools.recover_guest_name import recover


def test_recover_reads_only_the_guest_name_and_authenticates_the_capture():
    password = "synthetic<hub>&password"
    session = SessionCrypto.from_password(_encode_password(password))
    reply = session.encrypt(
        {"ssid": "Fixture Guest", "passphrase": "synthetic-private-wifi-key"},
        "getGuestNetworkData",
    )
    request = {key: value for key, value in reply.items() if key != "encryptedBlob"}
    entries = [
        {
            "request": {
                "method": "POST",
                "url": "http://192.168.0.1/php/ajaxGet_guest_settings.php",
                "postData": {"text": urlencode({"gnData": json.dumps(request)})},
            },
            "response": {"status": 200, "content": {"text": json.dumps(reply)}},
        }
    ]
    assert recover(entries, password) == "Fixture Guest"
    with pytest.raises(InvalidResponse):
        recover(entries, "not-the-settings-password")
