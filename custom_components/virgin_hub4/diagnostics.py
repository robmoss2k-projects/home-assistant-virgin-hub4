"""Shareable support summary, with private router topology excluded."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant


async def async_get_config_entry_diagnostics(hass: HomeAssistant, entry: ConfigEntry) -> dict:
    """Return an allowlisted schema; do not attach credentials or raw replies."""
    coordinator = entry.runtime_data
    data = coordinator.data
    return {
        "sampled_at_utc": data.observed_at.isoformat(),
        "poll_successful": coordinator.last_update_success,
        "hardware_revision": data.groups["device"].get("hwVersion"),
        "firmware": data.groups["device"].get("swVersion"),
        "docsis": data.groups["line"].get("docsisVersion"),
        "online": data.online,
        "uptime_seconds": data.uptime,
        "available_groups": sorted(data.groups),
        "unavailable_groups": data.errors,
        "channels_by_family": {group: len(rows) for group, rows in data.channels.items()},
        "log_row_count": len(data.groups.get("events", [])),
    }
