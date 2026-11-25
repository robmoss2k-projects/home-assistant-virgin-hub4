"""Synthetic regressions. Do not add private router data to fixtures."""

from datetime import datetime, timezone
import json

import pytest

from custom_components.virgin_hub4.client import InvalidResponse
from custom_components.virgin_hub4.parser import (
    clean,
    parse_assignments,
    parse_channels,
    parse_clients,
    parse_logs,
    parse_snapshot,
)


def js(**fields) -> str:
    return (
        "<script>\n"
        + "\n".join(f"var js_{key} = {json.dumps(value)};" for key, value in fields.items())
        + "\n</script>"
    )


def snapshot_inputs() -> dict[str, str]:
    return {
        "home": js(cm_reg_value="6", cm_oper_value="3", **{"24g_stat": "Up"}),
        "device": js(swVersion="test-firmware", systemUptime="1 days 2h:3m:4s"),
        "line": js(
            provisioningState="6",
            downStreamChannel=[["25", "330750000", 4.2, 39, "QAM256", "Locked", "38.9", "0", "2"]],
            upStreamChannel=[
                ["5", "36000000", 42, "2560 KSym/sec", "QAM64", "ATDMA", "1", "2", "3", "4"]
            ],
            downStreamChannel31=[
                ["159", "192", "4K", "3736", "QAM4096", "759", "Locked", "42", 6.3, "655", "0"]
            ],
            upStreamChannel31=[
                ["6", "10.0", "45.7", "2K", "QAM128", "OFDMA", "200", "53.9", "0", "0"]
            ],
            networkData=[
                ["Mon 23/11/2026 00:43:18", "6", "SW download Successful - Via NMS"],
                ["Nov 23 12:34:56 2026", "Notice", "Gateway status"],
            ],
        ),
    }


def test_all_four_channel_schemas_and_uptime():
    now = datetime(2026, 11, 23, 12, tzinfo=timezone.utc)
    sample = parse_snapshot(snapshot_inputs(), observed_at=now)
    assert sample.observed_at == now
    assert sample.online is True
    assert sample.uptime == 93784
    assert {name: len(rows) for name, rows in sample.channels.items()} == {
        "downstream_sc_qam": 1,
        "upstream_sc_qam": 1,
        "downstream_ofdm": 1,
        "upstream_ofdma": 1,
    }
    assert sample.channels["downstream_sc_qam"][0]["post_rs_errors"] == 2
    assert sample.channels["upstream_sc_qam"][0]["t4_timeouts"] == 4
    assert sample.channels["downstream_ofdm"][0]["corrected_active_profile"] == 655
    assert sample.channels["upstream_ofdma"][0]["first_active_subcarrier_raw"] == "53.9"


def test_no_javascript_execution_and_string_escape_support():
    fragment = """<script>
var js_value = 'Router\'s name';
var js_attack = alert(1);
var js_concat = "prefix" + read();
var js_number = 42;
</script>""".replace("Router's", "Router\\'s")
    assert parse_assignments(fragment) == {"value": "Router's name", "number": 42}
    with pytest.raises(InvalidResponse):
        parse_assignments("<html>Sign in</html>")


def test_missing_and_invalid_data_is_not_a_healthy_zero():
    with pytest.raises(InvalidResponse):
        parse_snapshot(snapshot_inputs() | {"line": js(provisioningState="6")})
    with pytest.raises(InvalidResponse):
        parse_channels({"downStreamChannel": [["25", 123]]})
    with pytest.raises(InvalidResponse):
        parse_clients({"numHostEnt": "1"})


def test_clients_handle_parallel_columns_and_missing_optional_values():
    data = {
        "numHostEnt": "2",
        "hostName": ["test-one", "test-two"],
        "phyAddress": ["02:00:00:00:00:01", "02:00:00:00:00:02"],
        "active": ["true", "false"],
        "ipv6Address": ["EMPTY"],
    }
    result = parse_clients(data)
    assert len(result) == 2
    assert result[0]["active"] is True and result[1]["active"] is False
    assert all("ipv6" not in client for client in result)


def test_secrets_are_not_exported():
    data = {
        "Configuration": [{"Passphrase": "do-not-store", "SSID": "demo-ssid"}],
        "WPSDevicePIN": "00000000",
        "enable": True,
    }
    assert clean(data) == {"Configuration": [{"SSID": "demo-ssid"}], "enable": True}


def test_log_categories_and_address_redaction():
    rows = [
        ["Mon 23/11/2026 00:43:18", "6", "SW download Successful - Via NMS"],
        ["Mon 23/11/2026 00:43:19", "3", "T3 time-out CM-MAC=02:00:00:00:00:01"],
        ["Nov 23 12:34:56 2026", "Notice", "Password changed"],
    ]
    first, second, third = parse_logs(rows)
    assert first["category"] == "firmware_download_succeeded"
    assert second["category"] == "t3_timeout"
    assert "02:00:00:00:00:01" not in second["message"]
    assert third["source"] == "gateway"
    assert third["message"] == "[credential detail omitted]"
