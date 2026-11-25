"""On-demand inspection of cached detail, including the full DOCSIS tables."""

from __future__ import annotations

from typing import Any

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant, ServiceCall, SupportsResponse
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
import voluptuous as vol

from .client import HubError
from .const import CONF_MANAGEMENT, DOMAIN
from .controls import FIREWALL_FIELDS, InvalidSetting
from .ip_rules import PORT_FIELDS, PROTOCOLS_V6
from .maintenance import OPERATIONS
from .port_rules import FORWARD, PROTOCOLS, TRIGGER
from .radio import PORTAL_STANDARDS, PORTAL_WIDTHS
from .schedules import MODES
from .wireless import BANDS, POLICY, SECURITY

_TARGET = vol.Optional("config_entry_id")
_SCHEDULE_FIELDS = {vol.Required("mode"): vol.In(MODES), vol.Optional("periods"): list}
_RADIO_FIELDS: dict = {vol.Optional("optimisation"): bool, vol.Optional("confirm_dfs"): bool}
_RULE_OPERATIONS = ("list", "add", "set_enabled", "delete", "apply")
_EDITS = vol.Optional("edits")
for _band, _standards in PORTAL_STANDARDS.items():
    _RADIO_FIELDS.update(
        {
            vol.Optional(f"{_band}_enabled"): bool,
            vol.Optional(f"{_band}_automatic"): bool,
            vol.Optional(f"{_band}_channel"): int,
            vol.Optional(f"{_band}_standard"): vol.In(_standards),
            vol.Optional(f"{_band}_width"): vol.In(PORTAL_WIDTHS[_band]),
        }
    )


def _port_fields(columns):
    return {
        vol.Required("operation"): vol.In(_RULE_OPERATIONS),
        _EDITS: list,
        vol.Optional("rule_id"): str,
        vol.Optional("enabled"): bool,
        **{
            vol.Optional(key): vol.In(PROTOCOLS)
            if key == "protocol"
            else str
            if key == "target"
            else vol.All(int, vol.Range(min=1, max=65535))
            for key, _ in columns
        },
    }


_ACTIONS = {
    "export_hub_configuration": ("maintenance_backup", {}),
    "prepare_hub_maintenance": (
        "maintenance_prepare",
        {vol.Required("operation"): vol.In(OPERATIONS), vol.Optional("filename"): str},
    ),
    "apply_hub_maintenance": (
        "maintenance_execute",
        {vol.Required("plan_id"): str, vol.Required("confirm_local_recovery"): bool},
    ),
    "get_operating_mode": ("mode_state", {}),
    "prepare_operating_mode_change": (
        "mode_prepare",
        {
            vol.Required("mode"): vol.In(("modem", "router")),
            vol.Optional("router_management_address"): str,
        },
    ),
    "apply_operating_mode_change": (
        "mode_execute",
        {vol.Required("plan_id"): str, vol.Required("confirm_local_recovery"): bool},
    ),
    "set_connected_device_name": (
        "device_label",
        {vol.Required("mac"): str, vol.Required("label"): str},
    ),
    "get_portal_language": ("portal_language_read", {}),
    "set_portal_language": ("portal_language", {vol.Required("language"): str}),
    "run_ping": (
        "ping_test",
        {
            vol.Required("target"): str,
            vol.Optional("packet_size"): vol.All(int, vol.Range(min=64, max=1518)),
            vol.Optional("count"): vol.All(int, vol.Range(min=1, max=32)),
            vol.Optional("timeout_seconds"): vol.All(int, vol.Range(min=5, max=120)),
        },
    ),
    "run_traceroute": (
        "trace_test",
        {
            vol.Required("target"): str,
            vol.Optional("max_hops"): vol.All(int, vol.Range(min=1, max=255)),
            vol.Optional("base_port"): vol.All(int, vol.Range(min=1, max=65535)),
            vol.Optional("timeout_seconds"): vol.All(int, vol.Range(min=5, max=120)),
        },
    ),
    "get_network_test_status": (
        "diagnostic_status",
        {vol.Required("test"): vol.In(("ping", "traceroute"))},
    ),
    "cancel_network_diagnostic": ("cancel_diagnostic", {}),
    "run_diagnostics_wizard": (
        "diagnostic_wizard",
        {vol.Optional("exercise_ethernet"): bool, vol.Optional("confirm_link_interruption"): bool},
    ),
    "set_dhcp_ipv4": (
        "dhcp_v4",
        {
            vol.Optional("enabled"): bool,
            vol.Optional("pool_start"): str,
            vol.Optional("pool_end"): str,
            vol.Optional("address_count"): vol.All(int, vol.Range(min=1, max=256)),
            vol.Optional("lease_seconds"): vol.All(int, vol.Range(min=120, max=604800)),
            vol.Optional("subnet_mask"): str,
            vol.Optional("confirm_network_change"): bool,
        },
    ),
    "set_dhcp_ipv6": ("dhcp_v6", {vol.Required("mode"): vol.In(("stateful", "stateless"))}),
    "dhcp_reservation": (
        "dhcp_reservations",
        {
            vol.Required("operation"): vol.In(("list", "add", "delete", "apply")),
            _EDITS: list,
            vol.Optional("mac"): str,
            vol.Optional("address"): str,
        },
    ),
    "set_wifi_security": (
        "wifi_settings",
        {
            vol.Optional("policy"): vol.In(POLICY),
            **{
                vol.Optional(f"{band}_{setting}"): validator
                for band in BANDS
                for setting, validator in (
                    ("ssid", str),
                    ("security", vol.In(SECURITY)),
                    ("broadcast", bool),
                    ("passphrase", str),
                )
            },
        },
    ),
    "wifi_mac_access_rule": (
        "wifi_access_list",
        {
            vol.Required("operation"): vol.In(("list", "add", "delete", "apply")),
            _EDITS: list,
            vol.Optional("band"): vol.In((*BANDS, "both")),
            vol.Optional("mac"): str,
            vol.Optional("name"): str,
        },
    ),
    "ip_filter_rule": (
        "ip_rules",
        {
            vol.Required("family"): vol.In(("ipv4", "ipv6", "both")),
            vol.Required("operation"): vol.In(_RULE_OPERATIONS),
            _EDITS: list,
            vol.Optional("rule_id"): str,
            vol.Optional("enabled"): bool,
            vol.Optional("protocol"): vol.In(PROTOCOLS_V6),
            vol.Optional("source"): str,
            vol.Optional("destination"): str,
            vol.Optional("direction"): vol.In(("incoming", "outgoing")),
            vol.Optional("policy"): vol.In(("Allow", "Deny")),
            **{vol.Optional(key): vol.All(int, vol.Range(min=1, max=65535)) for key in PORT_FIELDS},
        },
    ),
    "set_mac_filter_schedule": ("mac_filter_schedule", _SCHEDULE_FIELDS),
    "set_ip_filter_schedule": ("ip_filter_schedule", _SCHEDULE_FIELDS),
    "mac_filter_rule": (
        "mac_rules",
        {
            vol.Required("operation"): vol.In(_RULE_OPERATIONS),
            _EDITS: list,
            vol.Optional("mac"): str,
            vol.Optional("name"): str,
            vol.Optional("enabled"): bool,
        },
    ),
    "set_wifi_radio": ("radio", _RADIO_FIELDS),
    "port_forwarding_rule": ("forwarding", _port_fields(FORWARD)),
    "port_triggering_rule": ("triggering", _port_fields(TRIGGER)),
    "set_light_ring": (
        "light_ring",
        {
            vol.Required("mode"): vol.In(("auto", "manual")),
            vol.Optional("brightness"): vol.All(int, vol.Range(min=0, max=100)),
        },
    ),
    "set_upnp": ("upnp", {vol.Required("enabled"): bool}),
    "set_push_button_wps": ("wps", {vol.Required("enabled"): bool}),
    "start_wps_registration": ("wps_registration", {}),
    "set_guest_wifi": (
        "guest",
        {
            vol.Optional("enabled"): bool,
            vol.Optional("broadcast"): bool,
            vol.Optional("ssid"): str,
            vol.Optional("security"): vol.In(("0", "4", "5")),
            vol.Optional("passphrase"): str,
        },
    ),
    "get_guest_wifi_schedule": ("guest_schedule_read", {}),
    "set_guest_wifi_schedule": (
        "guest_schedule",
        {
            vol.Required("mode"): vol.In(("always", "until")),
            vol.Optional("expires_at"): str,
            vol.Optional("enable_if_off"): bool,
            vol.Optional("ssid"): str,
            vol.Optional("passphrase"): str,
        },
    ),
    "set_wan_mtu": ("mtu", {vol.Required("value"): vol.All(int, vol.Range(min=1280, max=1500))}),
    "set_firewall": ("firewall", {vol.Optional(key): bool for key in FIREWALL_FIELDS}),
    "set_dmz": ("dmz", {vol.Required("enabled"): bool, vol.Optional("target"): str}),
}


def register_actions(hass: HomeAssistant) -> None:
    """Register cached data and specific admin settings actions."""

    async def get_entry(call: ServiceCall, *, canceling_diagnostic: bool = False):
        user = (
            await hass.auth.async_get_user(call.context.user_id) if call.context.user_id else None
        )
        if user is None or not user.is_admin:
            raise ServiceValidationError(
                "Hub details and settings require a Home Assistant administrator"
            )
        entries = [
            entry
            for entry in hass.config_entries.async_entries(DOMAIN)
            if entry.state is ConfigEntryState.LOADED
            or (
                canceling_diagnostic
                and entry.state is ConfigEntryState.UNLOAD_IN_PROGRESS
                and hasattr(entry, "runtime_data")
            )
        ]
        entry_id = call.data.get("config_entry_id")
        if entry_id is not None:
            entries = [entry for entry in entries if entry.entry_id == entry_id]
        if len(entries) != 1:
            raise ServiceValidationError("Select exactly one loaded Virgin Media Hub 4")
        return entries[0]

    async def get_snapshot(call: ServiceCall) -> dict[str, Any]:
        entry = await get_entry(call)
        coordinator = entry.runtime_data
        data = coordinator.data
        group = call.data.get("group")
        if group is not None and group not in data.groups:
            raise ServiceValidationError("The selected Hub detail group has no data")
        groups = {group: data.groups[group]} if group else dict(data.groups)
        if "events" in groups:
            groups["events"] = [
                {key: value for key, value in row.items() if not key.startswith("_")}
                for row in groups["events"]
            ]
        return {
            "sampled_at_utc": data.observed_at.isoformat(),
            "poll_successful": coordinator.last_update_success,
            "management_enabled": entry.options.get(CONF_MANAGEMENT, False),
            "group_errors": data.errors,
            "data": groups,
        }

    hass.services.async_register(
        DOMAIN,
        "get_snapshot",
        get_snapshot,
        schema=vol.Schema({vol.Optional("config_entry_id"): str, vol.Optional("group"): str}),
        supports_response=SupportsResponse.ONLY,
    )

    def settings_handler(group: str):
        async def edit(call: ServiceCall) -> dict[str, Any]:
            coordinator = (
                await get_entry(call, canceling_diagnostic=group == "cancel_diagnostic")
            ).runtime_data
            changes = {key: value for key, value in call.data.items() if key != "config_entry_id"}
            try:
                return await coordinator.async_apply_setting(group, changes)
            except InvalidSetting as exc:
                raise ServiceValidationError(str(exc)) from None
            except HubError as exc:
                raise HomeAssistantError(str(exc)) from None

        return edit

    for name, (group, fields) in _ACTIONS.items():
        hass.services.async_register(
            DOMAIN,
            name,
            settings_handler(group),
            schema=vol.Schema({_TARGET: str, **fields}),
            supports_response=SupportsResponse.OPTIONAL,
        )
