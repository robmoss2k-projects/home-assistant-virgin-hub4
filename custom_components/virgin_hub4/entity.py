"""Shared Home Assistant entity identity."""

from __future__ import annotations

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import HubCoordinator


class HubEntity(CoordinatorEntity[HubCoordinator]):
    """A read-only entity on the registered Hub."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: HubCoordinator, key: str) -> None:
        super().__init__(coordinator)
        entry = coordinator.config_entry
        self._attr_unique_id = f"{entry.unique_id or entry.entry_id}_{key}"
        device = coordinator.data.groups["device"]
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.unique_id or entry.entry_id)},
            name="Virgin Media Hub 4",
            manufacturer="ARRIS / Virgin Media",
            model="TG3492LG",
            hw_version=device.get("hwVersion"),
            sw_version=device.get("swVersion"),
        )
