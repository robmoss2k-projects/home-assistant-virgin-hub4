"""Read a realistic Hub fixture over loopback with real HTTP and cookies."""

from collections import Counter
from asyncio import Lock, to_thread
from hashlib import sha256
import json
import os
from pathlib import Path
from types import SimpleNamespace

from aiohttp import web
from aiohttp.test_utils import TestServer
import pytest

from custom_components.virgin_hub4 import collection, controls, coordinator, parser
from custom_components.virgin_hub4 import client as transport
from custom_components.virgin_hub4.client import (
    SCRIPT_READS,
    HubClient,
    InvalidResponse,
    SessionBusy,
    SessionCrypto,
)
from custom_components.virgin_hub4.modem_mode import hub_identity
from custom_components.virgin_hub4.const import CONF_MAINTENANCE, CONF_MANAGEMENT
from custom_components.virgin_hub4.parser import REQUIRED_MARKERS
from test_parser import js, snapshot_inputs
from tools import probe

HOST = "192.168.0.1"  # Validation path only; requests go to the loopback fixture.
PASSWORD = "synthetic-settings-password"
KEY = "synthetic-wifi-secret"
COOKIE = "hub_test_session"
MODE = "/php/user_data.php"
LOGIN = "/php/ajaxSet_Password.php"
LOGOUT = "/php/logout.php"
LIGHT_RING_READ = "/php/lightring_data.php"
LIGHT_RING_WRITE = "/php/ajaxSet_lightring_data.php"
DEVICE_MAC = "02:00:00:00:00:12"
GUEST_READ = "/php/ajaxGet_guest_settings.php"
GUEST_WRITE = "/php/ajaxSet_guest_settings.php"
BACKUP_DOWNLOAD = "/php/trigger_download.php/"
BACKUP_BYTES = b"<?xml version='1.0'?><synthetic-config />"
GUEST = {
    "enable": "0",
    "ssid": "Guest fixture",
    "broadcast": "1",
    "security": "4",
    "passphrase": KEY,
    "24Passphrase": "synthetic-2ghz-key",
    "50Passphrase": "synthetic-5ghz-key",
}


class HubFixture:
    def __init__(
        self, *, expire_once=False, browser_busy=False, light_ring=None, lost_write_ack=False
    ):
        self.expire_once = expire_once
        self.owner = "browser" if browser_busy else None
        self.light_ring = light_ring
        self.lost_write_ack = lost_write_ack
        self.light_ring_writes = []
        self.attempts = Counter()
        self.requests = []
        self.wire_violations = []
        self.envelopes = {}
        seed = snapshot_inputs() | {
            "mode": js(RouterMode="5"),
            "radio": js(**{"24g_stat": "Up", "5g_stat": "Up"}),
            "device": js(
                swVersion="test-firmware", systemUptime="1 days 2h:3m:4s", cmMac=DEVICE_MAC
            ),
            "client_network": js(ipv6_prefix="2001:db8:1234::/64", lan_subnet_mask="255.255.255.0"),
        }
        self.scripts = {
            path: seed.get(group) or js(**dict.fromkeys(REQUIRED_MARKERS[group], "fixture"))
            for group, (path, _) in SCRIPT_READS.items()
        }

    def _reject(self, reason):
        self.wire_violations.append(reason)
        return web.Response(status=400)

    async def handle(self, request):
        form = await request.post()
        path = request.path
        self.requests.append(path)
        csrf = request.headers.get("CSRF_NONCE")
        cookie = request.cookies.get(COOKIE)
        if path == MODE and "loginCSRMode" in json.loads(form.get("userData", "{}")):
            if cookie is not None or csrf != "undefined" or form.get("opType") != "READ":
                return self._reject("Unexpected login preflight state")
            return web.json_response({"loginCSRMode": 0})
        if path == LOGIN:
            return self._login(form, cookie, csrf)
        if self.owner is None or cookie != self.owner or csrf != f"csrf-{self.owner}":
            # An expired cookie may reach the normal logout call. It cannot
            # terminate a browser's or any subsequent transaction's session.
            if path == LOGOUT:
                self.attempts["stale_logout"] += 1
                return web.Response(status=403)
            return self._reject("Post-login request had no matching cookie and CSRF header")
        if path == LOGOUT:
            self.owner = None
            self.attempts["logout"] += 1
            return web.Response()
        if self.light_ring is not None:
            if path == LIGHT_RING_READ and not form:
                return web.Response(text=js(lightring_value=str(self.light_ring)))
            if path == LIGHT_RING_WRITE:
                payload = json.loads(form.get("lightRing", "{}"))
                value = payload.get("lightRing")
                if set(form) != {"lightRing", "opType"} or form["opType"] != "WRITE":
                    return self._reject("Unexpected light-ring form")
                if (
                    set(payload) != {"lightRing"}
                    or type(value) is not int
                    or not -1 <= value <= 100
                ):
                    return self._reject("Unexpected light-ring value")
                self.light_ring = value
                self.light_ring_writes.append(value)
                if self.lost_write_ack and len(self.light_ring_writes) == 1:
                    return web.Response(status=503)
                return web.Response()
        if form.get("opType") == "WRITE":
            return self._reject("Read-only collection attempted a settings write")
        if self.expire_once and path == SCRIPT_READS["line"][0]:
            self.expire_once = False
            self.owner = None
            return web.Response(text="\n\n")
        if path in self.scripts:
            if path == "/php/device_connection_data.php" and (
                form
                or not request.headers.get("Referer", "").endswith(
                    "/?device_connection&mid=ConnectedDevices"
                )
            ):
                return self._reject("Unexpected connected-device network status request")
            return web.Response(text=self.scripts[path], content_type="text/html")
        if path == MODE:
            user_data = json.loads(form.get("userData", "{}"))
            return web.json_response(
                {"lang": "en", "availableLang": "en,fr"}
                | ({"ddnsEnable": "false"} if "ddnsEnable" in user_data else {})
                | ({"deviceMode": "3", "dsliteMode": "0"} if "deviceMode" in user_data else {})
            )
        if "wifiData[iv]" in form:
            meta = {k: form[f"wifiData[{k}]"] for k in ("authData", "salt", "iv")}
            value = (
                {"EnableGuest": "false", "GuestWizPassphrase": KEY, "ActiveTimeout": ""}
                if "wifiData[ActiveTimeout]" in form
                else {"sonAdminStatus": "false", "sonOperationalStatus": "false"}
            )
            return self._encrypted(meta, value)
        if path == "/php/ajaxGet_guest_settings.php":
            return self._encrypted(json.loads(form["gnData"]), {"enable": "0", "passphrase": KEY})
        if path == "/php/ajaxGet_wifi_settings_data.php":
            payload = json.loads(form["wifiData"])
            if isinstance(payload.get("iv"), str):
                return self._encrypted(
                    payload, {"Configuration": [{"Passphrase": KEY}], "MACFilter": []}
                )
            if set(payload) in ({"AttachedDevices"}, {"WirelessFilterList"}):
                return web.json_response({k: [] for k in payload})
            return self._reject("Unknown Wi-Fi table request")
        if path == "/php/ajaxGet_dhcp_setting_data.php":
            getting = form["dhcpData[getting]"]
            return web.json_response({"getting": getting})
        if path in JSON_READS:
            return web.json_response(JSON_READS[path])
        return self._reject("Unknown HTTP route in read-only fixture")

    def _login(self, form, cookie, csrf):
        self.attempts["login"] += 1
        if cookie is not None or csrf != "undefined":
            return self._reject("Fresh login inherited an old cookie or CSRF value")
        if self.owner is not None:
            return web.json_response({"p_status": "Active_session"})
        env = json.loads(form["configInfo"])
        crypto = SessionCrypto.from_password(PASSWORD, salt=env["salt"], iv=env["iv"])
        fields = crypto.open_response(env, env)
        if not (
            fields["oldPassword"] == fields["newPassword"] == PASSWORD
            and fields["ChangePassword"] == "false"
        ):
            return self._reject("Unexpected login operation")
        self.owner = f"fixture-{self.attempts['login']}"
        self.envelopes[self.owner] = (env["salt"], {env["iv"]})
        reply = web.json_response({"p_status": "Match", "nonce": f"csrf-{self.owner}"})
        reply.set_cookie(COOKIE, self.owner, httponly=True)
        return reply

    def _encrypted(self, meta, payload):
        salt, seen = self.envelopes[self.owner]
        if meta["salt"] != salt or meta["iv"] in seen:
            return self._reject("Encrypted read reused an IV or changed salt")
        seen.add(meta["iv"])
        crypto = SessionCrypto.from_password(PASSWORD, salt=salt, iv=meta["iv"])
        return web.json_response(crypto.encrypt(payload, meta["authData"]))


class GuestFixture(HubFixture):
    def __init__(self, condition):
        super().__init__()
        self.condition = condition
        self.guest = GUEST.copy()
        self.pending = None
        self.settling_reads = 0
        self.writes = []
        self.read_sessions = []

    async def handle(self, request):
        path = request.path
        if path not in {GUEST_READ, GUEST_WRITE}:
            return await super().handle(request)
        self.requests.append(path)
        if path == GUEST_READ:
            self.read_sessions.append(request.cookies.get(COOKIE))
            if self.condition == "expired" and self.writes:
                return web.Response(status=403)
        if (
            not self.owner
            or request.cookies.get(COOKIE) != self.owner
            or request.headers.get("CSRF_NONCE") != f"csrf-{self.owner}"
        ):
            return self._reject("Guest request lacks a valid session")
        env = json.loads((await request.post())["gnData"])
        if path == GUEST_READ:
            if self.condition == "offline" and self.writes or self.settling_reads == 2:
                if self.settling_reads == 2:
                    self.settling_reads -= 1
                self.attempts["unreachable"] += 1
                return web.Response(status=503)
            if self.settling_reads:
                self.settling_reads -= 1
            elif self.pending is not None:
                self.guest.update(self.pending)
                self.pending = None
            return self._encrypted(env, self.guest)
        salt, seen = self.envelopes[self.owner]
        if env["salt"] != salt or env["iv"] in seen:
            return self._reject("Guest write reused an IV or changed salt")
        seen.add(env["iv"])
        crypto = SessionCrypto.from_password(PASSWORD, salt=salt, iv=env["iv"])
        decoded = crypto.open_response(env, env)
        fields = {
            key: value for key, value in decoded.items() if key not in {"salt", "iv", "authData"}
        }
        preserved = {k: self.guest[k] for k in ("enable", "broadcast", "security", "passphrase")}
        if not isinstance(fields.get("ssid"), str) or fields != preserved | {
            "ssid": fields["ssid"]
        }:
            return self._reject("Guest write altered fields besides the name")
        self.writes.append(fields["ssid"])
        if self.condition == "stale":
            return web.Response()
        if self.condition == "recover":
            self.pending = fields
            self.settling_reads = 2  # First poll fails, next still reports the old name.
            return web.Response(status=503)
        self.guest.update(fields)
        if self.condition in {"passphrase", "24Passphrase", "50Passphrase"}:
            self.guest[self.condition] = "unexpected-replacement-key"
        if self.condition == "masked":
            self.guest["50Passphrase"] = "********"
        if self.condition == "missing":
            del self.guest["50Passphrase"]
        if self.condition == "missing_ssid":
            del self.guest["ssid"]
        if self.condition == "expired":
            self.owner = "browser"
        return web.Response(status=503)


class BackupFixture(HubFixture):
    async def handle(self, request):
        backup_request = request.path == MODE and json.loads(
            (await request.post()).get("userData", "{}")
        ) == {"backup": ""}
        if not backup_request and request.path != BACKUP_DOWNLOAD:
            return await super().handle(request)
        self.requests.append(request.path)
        if (
            not self.owner
            or request.cookies.get(COOKIE) != self.owner
            or request.headers.get("CSRF_NONCE") != f"csrf-{self.owner}"
        ):
            return self._reject("Backup request lacks a valid session")
        if backup_request:
            return web.json_response(
                {"url": f"{BACKUP_DOWNLOAD}?HTTP_CSRF_NONCE=csrf-{self.owner}"}
            )
        if request.method != "GET" or request.query.get("HTTP_CSRF_NONCE") != f"csrf-{self.owner}":
            return self._reject("Backup was not fetched by the login which issued it")
        return web.Response(body=BACKUP_BYTES, content_type="application/octet-stream")


JSON_READS = {
    "/php/associated_devices_data.php": {"numHostEnt": 0},
    "/php/ajaxGet_portforwarding_data.php": {"PortMappingNumberOfEntries": {"1": 0}},
    "/php/ajaxGet_porttriggering_data.php": {"PortTriggeringNumberOfEntries": {"1": 0}},
    "/php/ajaxGet_macfilter_data.php": {"AttachedDevices": []},
    "/php/ajaxGet_macfilter_list_data.php": {"numberOfMACList": {"1": 0}},
    "/php/mac_blocktime.php": {"blockTimeType": "Always", "timeSchedules": "F" * 42 + "7F"},
    "/php/ip_blocktime.php": {"blockTimeType": 0, "timeSchedules": [2147483647] * 7},
}


async def _run_with_fixture(monkeypatch, fixture, run, **options):
    app = web.Application()
    app.router.add_post("/{name:.*}", fixture.handle)
    app.router.add_get(BACKUP_DOWNLOAD, fixture.handle)
    async with TestServer(app, host="127.0.0.1") as server:
        origin = str(server.make_url("/").origin())

        class FixtureClient(HubClient):
            def __init__(self, session, host):
                super().__init__(session, host)
                self._origin = origin

        monkeypatch.setattr(transport, "HubClient", FixtureClient)
        monkeypatch.setattr(probe, "HubClient", FixtureClient)
        return await run(HOST, PASSWORD, **options)


async def _collect_with_fixture(monkeypatch, fixture, *, extended):
    return await _run_with_fixture(monkeypatch, fixture, collection.collect, extended=extended)


@pytest.mark.asyncio
async def test_all_read_groups_use_real_http_and_never_publish_secrets(monkeypatch):
    fixture = HubFixture()
    sample = await _collect_with_fixture(monkeypatch, fixture, extended=True)
    assert sample.online and not sample.errors
    assert len(sample.groups) == 37
    assert sample.groups["client_network"] == {
        "ipv6_prefix": "2001:db8:1234::/64",
        "lan_subnet_mask": "255.255.255.0",
    }
    assert sample.groups["activity"]["ddnsEnable"] == "false"
    assert sample.groups["mac_filter_rules"] == []
    assert sample.groups["wifi_security"]["Configuration"] == [{}]
    assert sample.groups["guest"]["enable"] == "0"
    assert KEY not in repr(sample)
    assert fixture.attempts == {"login": 1, "logout": 1}
    assert sum(len(values) for _, values in fixture.envelopes.values()) == 5
    assert not fixture.wire_violations
    assert fixture.owner is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("extended", "fragments", "groups", "requests"), [(False, 6, 9, 10), (True, 19, 37, 38)]
)
async def test_snapshot_parses_each_script_once(monkeypatch, extended, fragments, groups, requests):
    calls = Counter()
    original = parser.parse_script_group

    def tracked(group, body):
        calls[group] += 1
        return original(group, body)

    monkeypatch.setattr(collection, "parse_script_group", tracked)
    monkeypatch.setattr(parser, "parse_script_group", tracked)
    fixture = HubFixture()
    sample = await _collect_with_fixture(monkeypatch, fixture, extended=extended)
    assert len(calls) == fragments and set(calls.values()) == {1}
    assert len(fixture.requests) == requests
    assert len(sample.groups) == groups and not sample.errors
    assert KEY not in repr(sample)
    assert not fixture.wire_violations


@pytest.mark.asyncio
@pytest.mark.parametrize("expected_mac", [DEVICE_MAC, "02:00:00:00:00:13"])
async def test_backup_service_checks_identity_and_exports_in_one_session(
    monkeypatch, tmp_path, expected_mac
):
    fixture = BackupFixture()
    (tmp_path / ".storage").mkdir()  # Core creates this parent before the integration runs.

    async def run(host, password):
        hub = object.__new__(coordinator.HubCoordinator)
        hub._connection = {"host": host, "password": password}
        hub._entry = SimpleNamespace(
            data=hub._connection,
            options={CONF_MANAGEMENT: True, CONF_MAINTENANCE: True},
            unique_id=hub_identity({"cmMac": expected_mac}),
            entry_id="fixture-entry",
        )
        hub._closing = False
        hub._session_lock = Lock()
        hub.hass = SimpleNamespace(
            config=SimpleNamespace(path=tmp_path.joinpath), async_add_executor_job=to_thread
        )
        return await hub.async_apply_setting("maintenance_backup", {})

    request = _run_with_fixture(monkeypatch, fixture, run)
    if expected_mac == DEVICE_MAC:
        receipt = await request
        assert set(receipt) == {"status", "location", "filename", "size", "sha256"}
        assert receipt["status"] == "saved"
        path = Path(receipt["location"]) / receipt["filename"]
        assert path.parent == tmp_path / ".storage" / "virgin_hub4_configurations" / "fixture-entry"
        assert path.read_bytes() == BACKUP_BYTES
        assert path.stat().st_size == receipt["size"]
        assert receipt["sha256"] == sha256(BACKUP_BYTES).hexdigest()
        if os.name != "nt":
            assert path.stat().st_mode & 0o777 == 0o600
        assert fixture.requests == [
            MODE,
            LOGIN,
            SCRIPT_READS["device"][0],
            MODE,
            BACKUP_DOWNLOAD,
            LOGOUT,
        ]
    else:
        with pytest.raises(controls.InvalidSetting, match="did not identify the configured Hub"):
            await request
        assert fixture.requests == [MODE, LOGIN, SCRIPT_READS["device"][0], LOGOUT]
        assert not (tmp_path / ".storage" / "virgin_hub4_configurations").exists()
    assert fixture.attempts == {"login": 1, "logout": 1}
    assert fixture.owner is None and not fixture.wire_violations


async def _set_guest(monkeypatch, fixture, name):
    monkeypatch.setattr(controls, "_GUEST_POLL_SECONDS", 0.01)
    monkeypatch.setattr(controls, "_GUEST_READBACK_SECONDS", 0.2)
    return await _run_with_fixture(
        monkeypatch,
        fixture,
        controls.apply_setting,
        group="guest",
        proposed={"ssid": name},
        expected_identity=hub_identity({"cmMac": DEVICE_MAC}),
    )


@pytest.mark.asyncio
async def test_guest_rename_and_restore_recover_from_a_lost_ack_and_stale_read(monkeypatch):
    fixture = GuestFixture("recover")
    temporary = "Temporary Guest"
    for name in (temporary, GUEST["ssid"]):
        output = await _set_guest(monkeypatch, fixture, name)
        assert output == {
            "status": "verified",
            "group": "guest",
            "reported_passphrases_preserved": True,
            "readback": {"enabled": False, "ssid": name, "broadcast": True, "security": "4"},
        }
        assert all(
            GUEST[field] not in repr(output)
            for field in ("passphrase", "24Passphrase", "50Passphrase")
        )
        assert fixture.owner is None
    assert fixture.guest == GUEST
    assert fixture.writes == [temporary, GUEST["ssid"]]
    assert fixture.read_sessions == ["fixture-1"] * 4 + ["fixture-2"] * 4
    assert fixture.attempts == {"login": 2, "logout": 2, "unreachable": 2}
    assert fixture.requests.count(SCRIPT_READS["device"][0]) == 2
    assert not fixture.wire_violations


@pytest.mark.asyncio
async def test_guest_no_op_does_not_write_or_open_a_second_session(monkeypatch):
    fixture = GuestFixture("recover")
    assert (await _set_guest(monkeypatch, fixture, GUEST["ssid"]))["status"] == "unchanged"
    assert fixture.attempts == {"login": 1, "logout": 1}
    assert not fixture.writes


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("condition", "status", "issue", "keys", "has_readback"),
    [
        ("offline", "outcome_unknown", "CannotConnect", None, False),
        ("stale", "not_applied", "settings_mismatch", True, True),
        ("expired", "outcome_unknown", "SessionExpired", None, False),
        ("passphrase", "outcome_unknown", "passphrase_mismatch", False, True),
        ("24Passphrase", "outcome_unknown", "passphrase_mismatch", False, True),
        ("50Passphrase", "outcome_unknown", "passphrase_mismatch", False, True),
        ("masked", "outcome_unknown", "passphrases_unavailable", None, True),
        ("missing", "outcome_unknown", "passphrases_unavailable", None, True),
        ("missing_ssid", "outcome_unknown", "InvalidResponse", None, False),
    ],
)
async def test_guest_non_confirmation_does_not_trigger_a_second_write_or_login(
    monkeypatch, condition, status, issue, keys, has_readback
):
    fixture = GuestFixture(condition)
    result = await _set_guest(monkeypatch, fixture, "Temporary Guest")
    assert result["status"] == status
    assert result["verification_issue"] == issue
    assert result["reported_passphrases_preserved"] is keys
    assert (result["readback"] is not None) == has_readback
    assert result["write_issue"] == (None if condition == "stale" else "CannotConnect")
    assert fixture.writes == ["Temporary Guest"]
    assert fixture.attempts["login"] == 1
    assert set(fixture.read_sessions) == {"fixture-1"}
    if condition == "expired":
        assert len(fixture.read_sessions) == 2
        assert fixture.owner == "browser"
    else:
        assert len(fixture.read_sessions) > 2
        assert fixture.attempts["logout"] == 1
        assert fixture.owner is None
    if condition == "stale":
        assert result["readback"]["ssid"] == GUEST["ssid"]
    if condition == "offline":
        assert fixture.attempts["unreachable"] == len(fixture.read_sessions) - 1
    assert not fixture.wire_violations
    assert all(
        GUEST[field] not in repr(result) for field in ("passphrase", "24Passphrase", "50Passphrase")
    )
    assert "unexpected-replacement-key" not in repr(result)


@pytest.mark.asyncio
async def test_expired_wire_session_uses_new_cookie_jar_then_completes(monkeypatch):
    fixture = HubFixture(expire_once=True)
    sample = await _collect_with_fixture(monkeypatch, fixture, extended=False)
    assert sample.online and not sample.errors
    assert fixture.attempts == {"login": 2, "logout": 1, "stale_logout": 1}
    assert not fixture.wire_violations


@pytest.mark.asyncio
async def test_busy_browser_session_is_not_replaced_over_http(monkeypatch):
    fixture = HubFixture(browser_busy=True)
    with pytest.raises(SessionBusy):
        await _collect_with_fixture(monkeypatch, fixture, extended=False)
    assert fixture.owner == "browser"
    assert fixture.requests == [MODE, LOGIN]
    assert not fixture.wire_violations


@pytest.mark.asyncio
@pytest.mark.parametrize(("original", "temporary", "lost_ack"), [(-1, 10, False), (100, 99, True)])
async def test_light_ring_probe_changes_and_restores_without_resending(
    monkeypatch, capsys, original, temporary, lost_ack
):
    fixture = HubFixture(light_ring=original, lost_write_ack=lost_ack)
    result = await _run_with_fixture(monkeypatch, fixture, probe.probe, check_light_ring=True)
    assert result == 0
    assert fixture.light_ring == original
    assert fixture.light_ring_writes == [temporary, original]
    assert fixture.attempts == {"login": 1, "logout": 1}
    assert fixture.owner is None
    assert not fixture.wire_violations
    output = capsys.readouterr().out
    assert f"Temporary setting: verified, readback={{'value': {temporary}}}" in output
    assert f"Original setting: verified, readback={{'value': {original}}}" in output


@pytest.mark.asyncio
@pytest.mark.parametrize("expected_mac", [DEVICE_MAC, "02:00:00:00:00:13"])
async def test_live_action_confirms_configured_hub_in_the_same_session(monkeypatch, expected_mac):
    fixture = HubFixture(light_ring=10)
    request = _run_with_fixture(
        monkeypatch,
        fixture,
        controls.apply_setting,
        group="light_ring",
        proposed={"mode": "manual", "brightness": 11},
        expected_identity=hub_identity({"cmMac": expected_mac}),
    )
    if expected_mac == DEVICE_MAC:
        assert (await request)["status"] == "verified"
        assert fixture.light_ring_writes == [11]
        assert fixture.requests.index(SCRIPT_READS["device"][0]) < fixture.requests.index(
            LIGHT_RING_WRITE
        )
    else:
        with pytest.raises(InvalidResponse, match="does not identify the configured Hub") as error:
            await request
        assert expected_mac not in str(error.value) and DEVICE_MAC not in str(error.value)
        assert fixture.light_ring_writes == []
        assert fixture.requests == [MODE, LOGIN, SCRIPT_READS["device"][0], LOGOUT]
    assert fixture.attempts == {"login": 1, "logout": 1}
    assert not fixture.wire_violations
