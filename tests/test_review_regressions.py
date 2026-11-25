"""Adversarial portal/HA contract regressions; no household Hub dependency."""

import pytest

from custom_components.virgin_hub4.client import SessionExpired
from custom_components.virgin_hub4.controls import InvalidSetting, apply_owned_session
from custom_components.virgin_hub4.ip_rules import _add
from custom_components.virgin_hub4.port_rules import _plan_add
from test_client import fixture_hub
from test_guest_schedule import WIFI
from test_port_rules import FORWARD_ONE, TRIGGER_ONE


@pytest.mark.parametrize(
    ("group", "form", "range_name"),
    [("forwarding", FORWARD_ONE, "external"), ("triggering", TRIGGER_ONE, "trigger")],
)
def test_port_forms_reject_a_restricted_port_inside_range_not_just_at_endpoint(
    group, form, range_name
):
    change = form | {f"{range_name}_start": 52, f"{range_name}_end": 54}
    if group == "forwarding":
        change["local_end"] += 1  # Preserve the portal's equal-length requirement.
    with pytest.raises(ValueError, match=r"blocks .*\[53\]"):
        _plan_add(group, change, [])


def test_port_forms_distinguish_udp_from_tcp_and_both():
    change = TRIGGER_ONE | {"trigger_start": 24, "trigger_end": 26}
    assert _plan_add("triggering", change, [])[1]
    for protocol in ("TCP", "BOTH"):
        with pytest.raises(ValueError, match=r"blocks .*\[25\]"):
            _plan_add("triggering", change | {"protocol": protocol}, [])


def test_ip_filter_port_restrictions_follow_direction_policy_and_family():
    common = {
        "source": "any",
        "destination": "any",
        "protocol": "BOTH",
        "enabled": True,
        "source_port_start": 1000,
        "source_port_end": 1001,
        "destination_port_start": 52,
        "destination_port_end": 54,
    }
    with pytest.raises(ValueError, match=r"blocks .*\[53\]"):
        _add(common, {}, ip6=False)
    for direction, policy in (("outgoing", "Allow"), ("incoming", "Deny")):
        wire, _ = _add(common | {"direction": direction, "policy": policy}, {}, ip6=True)
        assert wire["DstPortEnd"] == "54"
    with pytest.raises(ValueError, match=r"blocks .*\[53\]"):
        _add(common | {"direction": "incoming", "policy": "Allow"}, {}, ip6=True)
    with pytest.raises(ValueError, match="1 through 65535"):
        _add(common | {"source_port_start": 0}, {}, ip6=False)


async def test_guest_setting_does_not_read_after_definite_session_expiry():
    hub = fixture_hub()
    hub.read_wifi.return_value = WIFI
    hub.write_guest.side_effect = SessionExpired("expired during submission")
    reply = await apply_owned_session(hub, "guest", {"ssid": "New fixture name"})
    assert reply["status"] == "outcome_unknown"
    assert reply["write_issue"] == "SessionExpired" and reply["readback"] is None
    hub.read_wifi.assert_awaited_once_with("guest")
    hub.write_guest.assert_awaited_once()


async def test_trigger_action_cannot_bypass_range_validation():
    hub = fixture_hub()
    hub.read_rules.return_value = {"PortTriggeringNumberOfEntries": {"1": 0}}
    with pytest.raises(InvalidSetting, match=r"blocks .*\[53\]"):
        await apply_owned_session(
            hub,
            "triggering",
            TRIGGER_ONE | {"operation": "add", "trigger_start": 52, "trigger_end": 54},
        )
    hub.write_port_rules.assert_not_awaited()
