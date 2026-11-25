"""Current Hub states. Modem online is intentionally not Internet reachable."""

from __future__ import annotations

from collections.abc import Callable

from homeassistant.components.binary_sensor import BinarySensorDeviceClass, BinarySensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .coordinator import HubCoordinator
from .entity import HubEntity
from .parser import flag


def _flag(group: str, key: str) -> Callable[[HubCoordinator], bool | None]:
    return lambda c: flag(c.data.groups.get(group, {}).get(key))


class HubBinarySensor(HubEntity, BinarySensorEntity):
    """A reported boolean status."""

    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        coordinator: HubCoordinator,
        key: str,
        name: str,
        value: Callable[[HubCoordinator], bool | None],
        *,
        connectivity: bool = False,
    ) -> None:
        super().__init__(coordinator, key)
        self._attr_name = name
        self._value = value
        if connectivity:
            self._attr_device_class = BinarySensorDeviceClass.CONNECTIVITY

    @property
    def is_on(self) -> bool | None:
        return self._value(self.coordinator)

    @property
    def available(self) -> bool:
        return super().available and self.is_on is not None


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: HubCoordinator = entry.runtime_data
    async_add_entities(
        [
            HubBinarySensor(
                coordinator,
                "cable_online",
                "Cable modem online",
                lambda c: c.data.online,
                connectivity=True,
            ),
            HubBinarySensor(
                coordinator,
                "downstream_lock",
                "Primary downstream locked",
                _flag("line", "acquiredDownstreamChannelStatus"),
            ),
            HubBinarySensor(
                coordinator,
                "upstream_lock",
                "Primary upstream ranged",
                _flag("line", "rangedUpstreamChannelStatus"),
            ),
            HubBinarySensor(
                coordinator,
                "network_access",
                "Network access allowed",
                _flag("line", "networkAccess"),
            ),
            HubBinarySensor(coordinator, "wifi_24", "2.4 GHz Wi-Fi", _flag("home", "24g_stat")),
            HubBinarySensor(coordinator, "wifi_5", "5 GHz Wi-Fi", _flag("home", "5g_stat")),
            HubBinarySensor(
                coordinator, "guest_enabled", "Guest Wi-Fi", _flag("home", "24g_guest")
            ),
            HubBinarySensor(
                coordinator, "wps_enabled", "Push-button WPS", _flag("wps", "WPSPbcEnable")
            ),
            HubBinarySensor(
                coordinator, "upnp_enabled", "UPnP enabled", _flag("upnp", "UPnP_Status")
            ),
        ]
    )
