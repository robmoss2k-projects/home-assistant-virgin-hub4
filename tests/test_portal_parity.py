"""Browser-contract regressions with synthetic Hub state and loopback HTTP only."""

import json

import pytest
from aiohttp import web

from custom_components.virgin_hub4 import controls, verification
from custom_components.virgin_hub4.client import HubClient, InvalidResponse, SessionCrypto
from custom_components.virgin_hub4.modem_mode import hub_identity
from test_client import LOGIN as AUTH_REPLY
from test_client import MODE as AUTH_PRECHECK
from test_client import FakeHttp
from test_dhcp import SETTINGS, clients, fragment
from test_http_session import (
    COOKIE,
    DEVICE_MAC,
    MODE,
    PASSWORD,
    HubFixture,
    _run_with_fixture,
)
from test_parser import js

DHCP_SCRIPT = "/php/dhcp_setting_data.php"
DHCP_READ = "/php/ajaxGet_dhcp_setting_data.php"
DHCP_WRITE = "/php/ajaxSet_dhcp_setting_data.php"
MTU_READ = "/php/tool_mtu_data.php"
MTU_WRITE = "/php/ajaxSet_mtu_size.php"
FIREWALL_READ = "/php/firewall_data.php"
FIREWALL_WRITE = "/php/ajaxSet_Firewall.php"
FIREWALL_BASELINE = {
    "v4Enable": "Low",
    "v6Enable": "Default",
    "v4FragPkts": "false",
    "v6FragPkts": "false",
    "v4PortScan": "true",
    "v6PortScan": "true",
    "v4IpFlood": "true",
    "v6IpFlood": "true",
}


class ParityHub(HubFixture):
    """An independent browser-shaped form decoder; never forwards a request."""

    def __init__(self):
        super().__init__()
        self.mode = "3"
        self.dslite = "0"
        self.dhcp = SETTINGS.copy()
        self.mtu = 1500
        self.firewall = FIREWALL_BASELINE.copy()
        self.writes = []
        self.prep = "{}"
        self.reply = ""
        self.prep_status = 200
        self.reply_status = 200
        self.local = "f"
        self.mtu_delay = 0
        self.pending_mtu = None
        self.mtu_write_status = 200

    def _login(self, form, cookie, csrf):
        result = super()._login(form, cookie, csrf)
        body = json.loads(result.text)
        if self.local is not None and body.get("p_status") == "Match":
            result.text = json.dumps(body | {"gwWan": self.local})
        return result

    async def handle(self, request):
        path = request.path
        form = await request.post()
        payload = json.loads(form.get("userData", "{}")) if path == MODE else {}
        maintenance = path == MODE and form.get("opType") == "WRITE"
        if not (
            "deviceMode" in payload
            or maintenance
            or path
            in {
                DHCP_SCRIPT,
                DHCP_READ,
                DHCP_WRITE,
                MTU_READ,
                MTU_WRITE,
                FIREWALL_READ,
                FIREWALL_WRITE,
            }
        ):
            return await super().handle(request)
        self.requests.append(path)
        nonce = f"csrf-{self.owner}"
        if not self.owner or request.cookies.get(COOKIE) != self.owner:
            return self._reject("The operation did not use the owned cookie")
        if request.headers.get("CSRF_NONCE") != nonce:
            return self._reject("The operation lost its XHR nonce")
        if "deviceMode" in payload:
            return web.json_response({"deviceMode": self.mode, "dsliteMode": self.dslite})
        if path == DHCP_SCRIPT:
            return web.Response(text=fragment(**self.dhcp))
        if path == DHCP_READ:
            return web.json_response(
                self.dhcp if form["dhcpData[getting]"] == "dhcpInfo" else clients()
            )
        if path == DHCP_WRITE:
            value = json.loads(form["DhcpData"])
            self.writes.append(("dhcp", value))
            if value["setting"] == "dhcpV6":
                assert set(value) == {"setting", "typeV6"}
                self.dhcp["typeV6"] = {"Stateful": 1, "Stateless": 2}[value["typeV6"]]
            else:
                assert set(value) == {
                    "setting",
                    "enableV4",
                    "startAddrV4",
                    "endAddrV4",
                    "leaseTimeV4",
                    "subnetMask",
                    "lanGwAddrV4",
                }
                self.dhcp.update(
                    {k: value[k] for k in ("startAddrV4", "endAddrV4", "leaseTimeV4", "subnetMask")}
                )
                self.dhcp.update(
                    subnetIp=value["lanGwAddrV4"],
                    enableV4={"true": 1, "false": 2}[value["enableV4"]],
                )
            return web.Response()
        if path == MTU_READ:
            if self.pending_mtu is not None:
                if self.mtu_delay:
                    self.mtu_delay -= 1
                else:
                    self.mtu, self.pending_mtu = self.pending_mtu, None
            return web.Response(text=js(MTUSize=str(self.mtu)))
        if path == MTU_WRITE:
            env = json.loads(form["MTUData"])
            salt, used_ivs = self.envelopes[self.owner]
            assert env["salt"] == salt and env["iv"] not in used_ivs
            used_ivs.add(env["iv"])
            decoded = SessionCrypto.from_password(PASSWORD, salt=salt, iv=env["iv"]).open_response(
                env, env
            )
            value = {k: v for k, v in decoded.items() if k not in {"iv", "salt", "authData"}}
            assert set(value) == {"WANMTUSize"} and type(value["WANMTUSize"]) is int
            self.writes.append(("mtu", value))
            self.pending_mtu = value["WANMTUSize"]
            return web.Response(status=self.mtu_write_status)
        if path == FIREWALL_READ:
            return web.Response(text=js(**self.firewall))
        if path == FIREWALL_WRITE:
            value = json.loads(form["firewallData"])
            assert value.pop("csrf_nonce") == nonce
            assert set(value) == set(FIREWALL_BASELINE)
            self.writes.append(("firewall", value))
            for key, flag in value.items():
                self.firewall[key] = (
                    (FIREWALL_BASELINE[key] if flag else "Off")
                    if key.endswith("Enable")
                    else str(bool(flag)).lower()
                )
            return web.Response()
        if "Browse" in form:
            assert set(form) == {"Browse", "csrfNonce", "opType"} and form["csrfNonce"] == nonce
            part = form["Browse"]
            self.writes.append(("upload", (part.filename, part.file.read())))
        else:
            assert set(form) == {"userData", "opType"}
            self.writes.append(("maintenance", payload))
            if payload == {"Ignore": ""}:
                return web.Response(text=self.prep, status=self.prep_status)
        return web.Response(text=self.reply, status=self.reply_status)


async def setting(monkeypatch, fixture, group, **proposed):
    return await _run_with_fixture(
        monkeypatch,
        fixture,
        controls.apply_setting,
        group=group,
        proposed=proposed,
        expected_identity=hub_identity({"cmMac": DEVICE_MAC}),
    )


@pytest.mark.parametrize(
    ("mode", "dslite", "firewall", "expected"),
    [
        ("1", None, True, {"v4"}),
        ("1", "0", False, {"v4"}),
        ("2", "0", False, {"v6"}),
        ("2", "1", False, {"v4", "v6"}),
        ("2", "1", True, {"v6"}),
        ("3", "0", False, {"v4", "v6"}),
        ("3", "0", True, {"v4", "v6"}),
        ("99", "0", True, None),
        ("2", None, False, None),
    ],
)
@pytest.mark.asyncio
async def test_provisioned_families(mode, dslite, firewall, expected):
    http = FakeHttp(
        AUTH_PRECHECK, AUTH_REPLY, json.dumps({"deviceMode": mode, "dsliteMode": dslite})
    )
    hub = HubClient(http, "192.168.0.1")
    await hub.login("fixture-password")
    if expected is None:
        with pytest.raises(InvalidResponse, match="IP provisioning"):
            await hub.read_ip_provisioning(firewall=firewall)
    else:
        assert await hub.read_ip_provisioning(firewall=firewall) == expected
    assert json.loads(http.requests[-1][1]["data"]["userData"]) == {
        "deviceMode": "",
        "dsliteMode": "",
    }


@pytest.mark.asyncio
async def test_dhcp_pool_and_server_round_trips(monkeypatch):
    hub = ParityHub()
    before = hub.dhcp.copy()
    for change in (
        {"pool_end": "192.168.0.108"},
        {"address_count": 100},
        {"enabled": False, "confirm_network_change": True},
        {"enabled": True},
    ):
        assert (await setting(monkeypatch, hub, "dhcp_v4", **change))["status"] == "verified"
    assert hub.dhcp == before and len(hub.writes) == 4
    assert not hub.wire_violations


@pytest.mark.asyncio
async def test_hidden_mask_still_allows_readdress_with_confirmation(monkeypatch):
    hub = ParityHub()
    with pytest.raises(controls.InvalidSetting, match="network-change confirmation"):
        await setting(monkeypatch, hub, "dhcp_v4", pool_start="192.168.1.20", address_count=10)
    for start in ("192.169.1.20", "192.168.100.20", "192.168.253.20", "192.168.254.20"):
        with pytest.raises(controls.InvalidSetting, match="portal"):
            await setting(
                monkeypatch,
                hub,
                "dhcp_v4",
                pool_start=start,
                address_count=10,
                confirm_network_change=True,
            )
    assert not hub.writes
    result = await setting(
        monkeypatch,
        hub,
        "dhcp_v4",
        pool_start="192.168.1.20",
        address_count=10,
        confirm_network_change=True,
    )
    assert result["status"] == "verified"
    assert result["ipv4"]["gateway"] == "192.168.1.1"
    assert result["ipv4"]["pool_end"] == "192.168.1.29"
    assert len(hub.writes) == 1 and not hub.wire_violations


@pytest.mark.asyncio
async def test_ipv6_mode_round_trip_and_hidden_actions(monkeypatch):
    hub = ParityHub()
    hub.mode = "1"
    for group, changes in (("dhcp_v6", {"mode": "stateful"}), ("firewall", {"v6_enabled": False})):
        with pytest.raises(controls.InvalidSetting, match="portal hides"):
            await setting(monkeypatch, hub, group, **changes)
    assert not hub.writes
    hub.mode = "2"
    for expected, wire in (("stateful", "Stateful"), ("stateless", "Stateless")):
        assert (await setting(monkeypatch, hub, "dhcp_v6", mode=expected))["ipv6_mode"] == expected
        assert hub.writes[-1] == ("dhcp", {"setting": "dhcpV6", "typeV6": wire})
    with pytest.raises(controls.InvalidSetting, match="portal hides"):
        await setting(monkeypatch, hub, "dhcp_v4", lease_seconds=90000)
    assert len(hub.writes) == 2 and not hub.wire_violations


@pytest.mark.asyncio
async def test_mtu_encrypted_write_lost_ack_stale_read_and_restore(monkeypatch):
    hub = ParityHub()
    hub.mtu_delay = 1
    hub.mtu_write_status = 503
    monkeypatch.setattr(verification, "READBACK_SECONDS", 2)
    first = await setting(monkeypatch, hub, "mtu", value=1280)
    assert first["status"] == "verified" and first["write_issue"] == "CannotConnect"
    assert first["readback"] == {"value": 1280}
    hub.mtu_write_status = 200
    restore = await setting(monkeypatch, hub, "mtu", value=1500)
    assert restore["status"] == "verified" and hub.mtu == 1500
    assert hub.writes == [("mtu", {"WANMTUSize": 1280}), ("mtu", {"WANMTUSize": 1500})]
    assert hub.attempts["login"] == hub.attempts["logout"] == 2
    assert not hub.wire_violations


@pytest.mark.asyncio
async def test_firewall_every_flag_round_trip_and_exact_inactive_types(monkeypatch):
    hub = ParityHub()
    for key, wire in controls.FIREWALL_FIELDS.items():
        initial = FIREWALL_BASELINE[wire] != "false"
        for requested in (not initial, initial):
            result = await setting(monkeypatch, hub, "firewall", **{key: requested})
            assert result["status"] == "verified"
            assert result["readback"][wire] is requested
    assert hub.firewall == FIREWALL_BASELINE and len(hub.writes) == 16
    hub.mode = "1"
    await setting(monkeypatch, hub, "firewall", v4_enabled=False)
    wire = hub.writes[-1][1]
    assert type(wire["v4Enable"]) is int
    assert all(type(value) is bool for key, value in wire.items() if key != "v4Enable")
    with pytest.raises(controls.InvalidSetting, match="dependent flags"):
        await setting(monkeypatch, hub, "firewall", v4_detect_port_scan=False)
    await setting(monkeypatch, hub, "firewall", v4_enabled=True, v4_detect_port_scan=False)
    assert type(hub.writes[-1][1]["v4PortScan"]) is int
    hub.firewall["v4Enable"] = "Default"
    with pytest.raises(InvalidResponse, match="v4Enable"):
        await setting(monkeypatch, hub, "firewall", v4_enabled=False)
    assert len(hub.writes) == 18 and not hub.wire_violations


@pytest.mark.parametrize(
    ("prep", "reply", "status", "upload"),
    [
        ('"0"', "", "session_expired", False),
        ('{"error":"refused"}', "", "rejected", False),
        ("<html><body></body></html>", "", "preparation_unverified", False),
        ("{}", "", "submitted", True),
        ("{}", "<html><body></body></html>", "submitted", True),
        ("{}", "<html><body>FILE_ERROR</body></html>", "file_rejected", True),
        ("{}", "<pre></pre>", "submission_uncertain", True),
        ("{}", "<html><body>Sign in</body></html>", "submission_uncertain", True),
        (
            "{}",
            "<html><head><title>Sign in</title></head><body></body></html>",
            "submission_uncertain",
            True,
        ),
    ],
)
@pytest.mark.asyncio
async def test_restore_upload_contract(monkeypatch, prep, reply, status, upload):
    hub = ParityHub()
    hub.prep, hub.reply = prep, reply
    filename = "synthetic.xml" if not reply else "synthetic.cfg"
    result = await setting(
        monkeypatch,
        hub,
        "maintenance_submit",
        operation="restore",
        identity=hub_identity({"cmMac": DEVICE_MAC}),
        firmware="test-firmware",
        filename=filename,
        content=b"not a real backup",
    )
    assert result["status"] == status
    assert result["verification_required"] == (status in {"submitted", "submission_uncertain"})
    assert hub.writes == [("maintenance", {"Ignore": ""})] + (
        [("upload", (filename, b"not a real backup"))] if upload else []
    )
    assert not hub.wire_violations


@pytest.mark.parametrize(
    ("prep_status", "reply_status", "expected", "number_of_sends"),
    [
        (403, 200, "session_expired", 1),
        (503, 200, "preparation_unverified", 1),
        (200, 503, "submission_uncertain", 2),
    ],
)
@pytest.mark.asyncio
async def test_restore_lost_reply_does_not_replay_or_upload_on_failed_prep(
    monkeypatch, prep_status, reply_status, expected, number_of_sends
):
    hub = ParityHub()
    hub.prep_status, hub.reply_status = prep_status, reply_status
    result = await setting(
        monkeypatch,
        hub,
        "maintenance_submit",
        operation="restore",
        identity=hub_identity({"cmMac": DEVICE_MAC}),
        firmware="test-firmware",
        filename="fixture.cfg",
        content=b"synthetic",
    )
    assert result["status"] == expected
    assert len(hub.writes) == number_of_sends
    assert hub.attempts["login"] == 1 and not hub.wire_violations


@pytest.mark.parametrize(
    ("operation", "local", "reply", "http_status", "status"),
    [
        ("reboot", "f", '"0"', 200, "submission_uncertain"),
        ("reboot", "f", "<html>Sign in</html>", 200, "submission_uncertain"),
        ("reboot", "f", '{"error":"refused"}', 200, "rejected"),
        ("reboot", "f", "", 503, "submission_uncertain"),
        ("factory_reset", "f", "", 200, "submission_uncertain"),
        ("factory_reset", "t", "", 200, None),
        ("factory_reset", None, "", 200, None),
    ],
)
@pytest.mark.asyncio
async def test_reboot_and_reset_are_not_completed_by_a_reply(
    monkeypatch, operation, local, reply, http_status, status
):
    hub = ParityHub()
    hub.local, hub.reply, hub.reply_status = local, reply, http_status
    run = setting(
        monkeypatch,
        hub,
        "maintenance_submit",
        operation=operation,
        identity=hub_identity({"cmMac": DEVICE_MAC}),
        firmware="test-firmware",
    )
    if status is None:
        with pytest.raises(InvalidResponse, match="local admin session"):
            await run
        assert not hub.writes
    else:
        assert (await run)["status"] == status
        assert hub.writes == [
            (
                "maintenance",
                {"reboot": "restart"} if operation == "reboot" else {"factoryReset": "reset"},
            )
        ]
    assert not hub.wire_violations


@pytest.mark.asyncio
async def test_real_ha_actions_and_cold_restart_from_saved_entry(monkeypatch, tmp_path):
    pytest.importorskip("homeassistant.core")
    import shutil
    from pathlib import Path

    from homeassistant import auth, loader
    from homeassistant.bootstrap import async_load_base_functionality
    from homeassistant.config_entries import ConfigEntries, ConfigEntryState
    from homeassistant.core import Context, HomeAssistant
    from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
    from homeassistant.helpers import device_registry, entity_registry

    from custom_components.virgin_hub4 import maintenance
    from custom_components.virgin_hub4.const import (
        CONF_EXTENDED,
        CONF_INTERVAL,
        CONF_MAINTENANCE,
        CONF_MANAGEMENT,
        DOMAIN,
    )

    package = Path(controls.__file__).parent
    shutil.copytree(
        package,
        tmp_path / "custom_components" / DOMAIN,
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    hub = ParityHub()
    tick = [100.0]
    monkeypatch.setattr(maintenance, "monotonic", lambda: tick[0])

    async def boot():
        hass = HomeAssistant(str(tmp_path))
        hass.config.skip_pip = True
        hass.config_entries = ConfigEntries(hass, {})
        loader.async_setup(hass)
        await loader.async_get_custom_components(hass)
        assert await async_load_base_functionality(hass)
        hass.auth = await auth.auth_manager_from_config(hass, [], [])
        return hass

    def registry_ids(hass, entry_id):
        return (
            {
                e.entity_id
                for e in entity_registry.async_entries_for_config_entry(
                    entity_registry.async_get(hass),
                    entry_id,
                )
            },
            {
                d.id
                for d in device_registry.async_entries_for_config_entry(
                    device_registry.async_get(hass),
                    entry_id,
                )
            },
        )

    async def call(hass, user, name, **fields):
        return await hass.services.async_call(
            DOMAIN,
            name,
            fields,
            blocking=True,
            return_response=True,
            context=Context(user_id=user.id),
        )

    async def run(host, password):
        first = await boot()
        try:
            created = await first.config_entries.flow.async_init(
                DOMAIN,
                context={"source": "user"},
                data={"host": host, "password": password},
            )
            assert created["type"] == "create_entry"
            await first.async_block_till_done()
            entry = created["result"]
            assert entry.state is ConfigEntryState.LOADED
            await first.async_start()
            entry_id, unique_id = entry.entry_id, entry.unique_id
            setup_ids = registry_ids(first, entry_id)
            assert all(setup_ids)
            admin = await first.auth.async_create_user(
                "Synthetic Owner", group_ids=["system-admin"]
            )
            guest = await first.auth.async_create_user("Synthetic User", group_ids=["system-users"])
            with pytest.raises(ServiceValidationError, match="read-only"):
                await call(first, admin, "set_wan_mtu", value=1492)
            with pytest.raises(ServiceValidationError, match="administrator"):
                await call(first, guest, "set_wan_mtu", value=1492)
            with pytest.raises(ServiceValidationError, match="exactly one"):
                await call(first, admin, "set_wan_mtu", value=1492, config_entry_id="wrong")
            assert not hub.writes
            options = {
                CONF_MANAGEMENT: True,
                CONF_MAINTENANCE: True,
                CONF_EXTENDED: True,
                CONF_INTERVAL: 7,
            }
            first.config_entries.async_update_entry(entry, options=options)
            await first.async_block_till_done()
            for name, settings in (
                ("set_wan_mtu", {"value": 1492}),
                ("set_dhcp_ipv4", {"address_count": 99}),
                ("set_dhcp_ipv6", {"mode": "stateful"}),
                ("set_firewall", {"v4_block_fragments": True}),
            ):
                logins = hub.attempts["login"]
                result = await call(first, admin, name, **settings)
                assert result["status"] == "verified"
                assert hub.attempts["login"] == logins + 1
            assert len(hub.writes) == 4
            folder = tmp_path / ".storage" / f"{DOMAIN}_configurations" / entry_id
            folder.mkdir(parents=True)
            backup = folder / "fixture.cfg"
            backup.write_bytes(b"synthetic config")

            async def prepare(operation, **fields):
                return await call(
                    first, admin, "prepare_hub_maintenance", operation=operation, **fields
                )

            async def apply(plan, *, confirmed=True):
                return await call(
                    first,
                    admin,
                    "apply_hub_maintenance",
                    plan_id=plan["plan_id"],
                    confirm_local_recovery=confirmed,
                )

            plan = await prepare("restore", filename=backup.name)
            with pytest.raises(ServiceValidationError, match="recover access"):
                await apply(plan, confirmed=False)
            backup.write_bytes(b"changed after prepare")
            with pytest.raises(ServiceValidationError, match="file changed"):
                await apply(plan)
            with pytest.raises(ServiceValidationError, match="No Hub maintenance"):
                await apply(plan)

            plan = await prepare("reboot")
            tick[0] += maintenance.PLAN_TTL + 1
            with pytest.raises(ServiceValidationError, match="missing, stale"):
                await apply(plan)
            assert len(hub.writes) == 4

            device_route = "/php/device_status_data.php"
            original = hub.scripts[device_route]
            for firmware, mac in (
                ("changed-firmware", DEVICE_MAC),
                ("test-firmware", "02:00:00:00:00:77"),
            ):
                plan = await prepare("restore", filename=backup.name)
                hub.scripts[device_route] = js(
                    swVersion=firmware,
                    systemUptime="1 days 2h:3m:4s",
                    cmMac=mac,
                )
                with pytest.raises(HomeAssistantError, match="identity or firmware changed"):
                    await apply(plan)
                hub.scripts[device_route] = original
            hub.local = "t"
            with pytest.raises(HomeAssistantError, match="local admin session"):
                await prepare("factory_reset")
            hub.local = "f"
            assert len(hub.writes) == 4

            plan = await prepare("restore", filename=backup.name)
            assert (await apply(plan))["status"] == "submitted"
            assert hub.writes[-1] == ("upload", (backup.name, b"changed after prepare"))
            for operation, wire in (
                ("reboot", {"reboot": "restart"}),
                ("factory_reset", {"factoryReset": "reset"}),
            ):
                plan = await prepare(operation)
                result = await apply(plan)
                assert (
                    result["status"] == "submission_uncertain" and result["verification_required"]
                )
                assert hub.writes[-1] == ("maintenance", wire)
                with pytest.raises(ServiceValidationError, match="No Hub maintenance"):
                    await apply(plan)
            pending = await prepare("reboot")
            count_before_restart = len(hub.writes)
            admin_id = admin.id
        finally:
            await first.async_stop(force=True)

        second = await boot()
        try:
            restored = second.config_entries.async_get_entry(entry_id)
            assert restored is not entry and restored.unique_id == unique_id
            assert dict(restored.options) == options
            assert await second.config_entries.async_setup(entry_id)
            await second.async_start()
            await second.async_block_till_done()
            assert restored.runtime_data is not entry.runtime_data
            assert registry_ids(second, entry_id) == setup_ids
            assert restored.runtime_data.update_interval.total_seconds() == 420
            admin = await second.auth.async_get_user(admin_id)
            assert admin is not None
            with pytest.raises(ServiceValidationError, match="No Hub maintenance"):
                await call(
                    second,
                    admin,
                    "apply_hub_maintenance",
                    plan_id=pending["plan_id"],
                    confirm_local_recovery=True,
                )
            assert len(hub.writes) == count_before_restart
            assert not hub.wire_violations
        finally:
            await second.async_stop(force=True)

    await _run_with_fixture(monkeypatch, hub, run)
