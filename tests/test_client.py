"""Test the read-only network contract without talking to a Hub."""

import json
from urllib.parse import urlsplit
from unittest.mock import AsyncMock

from cryptography.hazmat.primitives.ciphers.aead import AESCCM
import pytest

from custom_components.virgin_hub4.client import (
    AuthenticationError,
    CannotConnect,
    HubClient,
    InvalidResponse,
    SessionBusy,
    SessionCrypto,
    SessionExpired,
    normalize_host,
)
from custom_components.virgin_hub4.portal import Provisioning
from test_parser import js


class FakeContent:
    def __init__(self, body):
        self.body = body

    async def iter_chunked(self, _length):
        yield self.body.encode()


class FakeResponse:
    def __init__(self, body):
        self.status = 200
        self.content = FakeContent(body)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None


class FakeHttp:
    def __init__(self, *responses):
        self.requests = []
        self.responses = iter(responses)

    def post(self, url, **kwargs):
        self.requests.append((urlsplit(url).path, kwargs))
        reply = next(self.responses)
        return FakeResponse(reply(kwargs["data"]) if callable(reply) else reply)


MODE = '{"loginCSRMode":0}'
LOGIN = '{"p_status":"Match","nonce":"synthetic-nonce"}'
DUAL_STACK = '{"deviceMode":"3","dsliteMode":"0"}'
RADIOS = js(**{"24g_stat": "Up", "5g_stat": "Up"})


def fixture_hub(*, spec=None):
    hub = AsyncMock(spec=spec)
    hub.read_portal_provisioning.return_value = Provisioning("3", "0")
    hub.read_ip_provisioning.return_value = frozenset({"v4", "v6"})
    hub.read_script.return_value = RADIOS
    return hub


def encrypted_reply(fields):
    """Synthetic firmware: bind each encrypted reply to its request metadata."""

    def respond(form):
        if "wifiData[iv]" in form:
            meta = {k: form[f"wifiData[{k}]"] for k in ("salt", "iv", "authData")}
        else:
            meta = json.loads(form.get("wifiData") or form["gnData"])
        crypto = SessionCrypto.from_password("fixture-pass", salt=meta["salt"], iv=meta["iv"])
        return json.dumps(crypto.encrypt(fields, meta["authData"]))

    return respond


@pytest.mark.asyncio
async def test_login_uses_normal_password_check_then_reads_and_releases_owned_session():
    session = FakeHttp(MODE, LOGIN, "<script>var js_swVersion = '1';</script>", "")
    hub = HubClient(session, "192.168.0.1")
    await hub.login("fixture-pass")
    assert "swVersion" in await hub.read_script("device")
    assert await hub.logout()
    assert [path for path, _ in session.requests] == [
        "/php/user_data.php",
        "/php/ajaxSet_Password.php",
        "/php/device_status_data.php",
        "/php/logout.php",
    ]
    args = session.requests[1][1]
    envelope = json.loads(args["data"]["configInfo"])
    crypto = SessionCrypto.from_password("fixture-pass", salt=envelope["salt"], iv=envelope["iv"])
    plaintext = AESCCM(crypto.key, tag_length=16).decrypt(
        bytes.fromhex(envelope["iv"]), bytes.fromhex(envelope["encryptedBlob"]), b"encryptData"
    )
    fields = json.loads(plaintext)
    assert fields["ChangePassword"] == "false"
    assert fields["oldPassword"] == fields["newPassword"] == "fixture-pass"
    assert session.requests[2][1]["headers"]["CSRF_NONCE"] == "synthetic-nonce"
    assert not args["allow_redirects"]
    assert not await hub.logout()


@pytest.mark.asyncio
async def test_active_browser_session_is_not_taken_over():
    session = FakeHttp(MODE, '{"p_status":"Active_session"}')
    hub = HubClient(session, "192.168.0.1")
    with pytest.raises(SessionBusy):
        await hub.login("fixture-pass")
    assert not await hub.logout()
    assert len(session.requests) == 2


@pytest.mark.asyncio
async def test_bad_password_not_retried():
    session = FakeHttp(MODE, '{"p_status":"Mismatch"}')
    hub = HubClient(session, "192.168.0.1")
    with pytest.raises(AuthenticationError):
        await hub.login("fixture-pass")
    assert not await hub.logout()
    assert len(session.requests) == 2


@pytest.mark.asyncio
async def test_http_200_empty_is_not_data():
    session = FakeHttp(MODE, LOGIN, "\n\n", "")
    hub = HubClient(session, "192.168.0.1")
    await hub.login("fixture-pass")
    with pytest.raises(SessionExpired):
        await hub.read_script("line")
    assert await hub.logout()


@pytest.mark.asyncio
async def test_only_network_status_gets_the_longer_timeout():
    session = FakeHttp(MODE, LOGIN, "home report", "DOCSIS and network log report", "")
    hub = HubClient(session, "192.168.0.1")
    await hub.login("fixture-pass")
    assert await hub.read_script("home") == "home report"
    assert await hub.read_script("line") == "DOCSIS and network log report"
    assert await hub.logout()
    assert [request["timeout"].total for _, request in session.requests] == [5, 5, 5, 20, 5]
    assert all(request["timeout"].connect == 4 for _, request in session.requests)


@pytest.mark.asyncio
async def test_timeout_reports_the_failing_route_without_retrying():
    class TimeoutResponse(FakeResponse):
        async def __aenter__(self):
            raise TimeoutError("should not leak implementation details")

    def route_timeout(url, **kwargs):
        path = urlsplit(url).path
        if path == "/php/device_networkstatus_data.php":
            session.requests.append((path, kwargs))
            return TimeoutResponse("")
        return original(url, **kwargs)

    session = FakeHttp(MODE, LOGIN, "")
    original = session.post
    session.post = route_timeout
    hub = HubClient(session, "192.168.0.1")
    await hub.login("fixture-pass")
    with pytest.raises(CannotConnect, match=r"/php/device_networkstatus_data\.php: timed out"):
        await hub.read_script("line")
    assert await hub.logout()
    assert [path for path, _ in session.requests].count("/php/device_networkstatus_data.php") == 1


def test_authenticated_settings_response_rejects_invalid_tag_or_action():
    crypto = SessionCrypto.from_password("fixture-pass")
    good = crypto.encrypt({"enable": "true"}, "getGuestNetworkData")
    assert crypto.open_response(good, good)["enable"] == "true"
    with pytest.raises(InvalidResponse):
        crypto.open_response(good, good | {"authData": "anotherAction"})
    with pytest.raises(InvalidResponse):
        crypto.open_response(good | {"encryptedBlob": "00" * 32}, good)


@pytest.mark.asyncio
async def test_encrypted_reads_and_writes_do_not_reuse_login_or_any_other_iv():
    fake = FakeHttp(
        MODE,
        LOGIN,
        encrypted_reply({"EnableGuest": "true"}),
        encrypted_reply({"enable": "true"}),
        '"OK"',
        '"OK"',
        encrypted_reply({"sonAdminStatus": "true"}),
        "",
    )
    hub = HubClient(fake, "192.168.0.1")
    await hub.login("fixture-pass")
    assert (await hub.read_wifi("guest_expiry"))["EnableGuest"] == "true"
    assert (await hub.read_wifi("guest"))["enable"] == "true"
    await hub.write_guest({"enable": "1"})
    await hub.write_radio({"Enable24g": "true"})
    assert (await hub.read_wifi("smart_wifi"))["sonAdminStatus"] == "true"
    assert await hub.logout()
    metadata = []
    for _, options in fake.requests[1:-1]:
        values = options["data"]
        if "wifiData[iv]" in values:
            metadata.append({k: values[f"wifiData[{k}]"] for k in ("salt", "iv")})
        else:
            metadata.append(json.loads(next(v for k, v in values.items() if k != "opType")))
    assert len({m["salt"] for m in metadata}) == 1
    assert len({m["iv"] for m in metadata}) == 6


@pytest.mark.asyncio
async def test_plaintext_and_replayed_settings_replies_are_refused():
    previous = None

    def first(form):
        nonlocal previous
        previous = encrypted_reply({"enable": "true"})(form)
        return previous

    fake = FakeHttp(MODE, LOGIN, first, lambda _: previous, '{"enable":"true"}', "")
    hub = HubClient(fake, "192.168.0.1")
    await hub.login("fixture-pass")
    assert (await hub.read_wifi("guest"))["enable"] == "true"
    for _ in range(2):
        with pytest.raises(InvalidResponse, match="decode Hub settings"):
            await hub.read_wifi("guest")
    assert await hub.logout()


@pytest.mark.parametrize("raw", ["https://192.168.0.1/", "8.8.8.8", "192.168.0.1:8080"])
def test_only_private_management_ip_is_supported(raw):
    with pytest.raises(ValueError):
        normalize_host(raw)
