"""Local Home Assistant integration for the Virgin Media Hub 4."""

from __future__ import annotations

from typing import TYPE_CHECKING

from homeassistant.helpers.config_validation import config_entry_only_config_schema

from .const import DOMAIN

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant

CONFIG_SCHEMA = config_entry_only_config_schema(DOMAIN)
PLATFORMS = ("binary_sensor", "sensor")


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Register integration actions; issue no device command."""
    from .actions import register_actions

    register_actions(hass)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up a config entry after a successful local collection."""
    from .coordinator import HubCoordinator

    coordinator = HubCoordinator(hass, entry)
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(_async_options_updated))
    return True


async def _async_options_updated(hass: HomeAssistant, entry: ConfigEntry) -> None:
    if (coordinator := getattr(entry, "runtime_data", None)) is not None:
        await coordinator.async_update_options()


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Release the operation owner before Core can set up a replacement."""
    coordinator = entry.runtime_data
    if not await coordinator.async_drain():
        return False
    unloaded = False
    try:
        unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
        return unloaded
    finally:
        if not unloaded:
            coordinator.resume_operations()
