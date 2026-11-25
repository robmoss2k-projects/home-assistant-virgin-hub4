"""Backup export only: permit the observed session-bound download route."""

import json

import pytest

from custom_components.virgin_hub4.client import HubClient, InvalidResponse
from test_client import FakeHttp, FakeResponse, LOGIN, MODE

HANDLER = "/php/trigger_download.php/"
NONCE = "synthetic-nonce"


class BackupHttp(FakeHttp):
    def __init__(self, href):
        super().__init__(MODE, LOGIN, json.dumps({"url": href}), "")
        self.downloads = []

    def get(self, url, **kwargs):
        self.downloads.append((url, kwargs))
        reply = FakeResponse("<?xml version='1.0'?><synthetic-config />")
        reply.content_type = "application/octet-stream"
        return reply


async def test_backup_follows_exact_handler_bound_to_current_session():
    http = BackupHttp(f"{HANDLER.lstrip('/')}?HTTP_CSRF_NONCE={NONCE}")
    hub = HubClient(http, "192.168.0.1")
    await hub.login("fixture-password")
    content, extension = await hub.download_configuration()
    assert extension == ".xml" and content.startswith(b"<?xml")
    assert await hub.logout()
    assert http.requests[2][0] == "/php/user_data.php"
    assert http.requests[2][1]["data"] == {"userData": '{"backup":""}', "opType": "READ"}
    [(url, options)] = http.downloads
    assert url == f"http://192.168.0.1{HANDLER}?HTTP_CSRF_NONCE={NONCE}"
    assert options["headers"]["CSRF_NONCE"] == NONCE
    assert not options["allow_redirects"]


@pytest.mark.parametrize(
    "href",
    [
        HANDLER,
        f"{HANDLER}?HTTP_CSRF_NONCE=stale-session",
        f"{HANDLER}?HTTP_CSRF_NONCE={NONCE}&file=other.cfg",
        f"{HANDLER}?HTTP_CSRF_NONCE={NONCE}&HTTP_CSRF_NONCE=other-nonce",
        f"{HANDLER}?HTTP_CSRF_NONCE={NONCE}#fragment",
        f"http://192.168.0.2{HANDLER}?HTTP_CSRF_NONCE={NONCE}",
        f"/php/other_download.php/?HTTP_CSRF_NONCE={NONCE}",
    ],
)
async def test_other_handlers_or_nonce_shapes_are_rejected_without_get(href):
    http = BackupHttp(href)
    hub = HubClient(http, "192.168.0.1")
    await hub.login("fixture-password")
    with pytest.raises(InvalidResponse, match="outside the local backup routes"):
        await hub.download_configuration()
    assert await hub.logout()
    assert not http.downloads
