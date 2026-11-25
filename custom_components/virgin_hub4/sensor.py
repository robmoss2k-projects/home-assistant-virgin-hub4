"""Hub and cable measurements plus optional per-channel diagnostics."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity, SensorStateClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import HUB_MODES
from .coordinator import HubCoordinator
from .entity import HubEntity
from .parser import flag, number


def _value(group: str, key: str, *, numeric: bool = False):
    def value(c: HubCoordinator) -> Any:
        raw = c.data.groups.get(group, {}).get(key)
        return number(raw, integer=True) if numeric else raw or None

    return value


def _mode(c: HubCoordinator) -> str | None:
    raw = c.data.groups.get("mode", {}).get("RouterMode")
    return HUB_MODES.get(str(raw))


def _client_count(c: HubCoordinator) -> int | None:
    if (clients := c.data.groups.get("clients")) is not None:
        return sum(client.get("active") is True for client in clients)
    return None


def _firmware_event(c: HubCoordinator) -> str | None:
    return next(
        (
            event["router_time"]
            for event in c.data.groups.get("events", [])
            if event["category"] == "firmware_download_succeeded"
        ),
        None,
    )


def _extreme(family: str, key: str, operation: Callable):
    def value(c: HubCoordinator) -> float | None:
        rows = c.data.channels.get(family, ())
        samples = [row[key] for row in rows if row.get(key) is not None]
        return operation(samples) if samples else None

    return value


def _locked(c: HubCoordinator) -> int | None:
    if (rows := c.data.channels.get("downstream_sc_qam")) is not None:
        return sum(flag(row.get("lock")) is True for row in rows)
    return None


@dataclass(frozen=True)
class Metric:
    key: str
    label: str
    value: Callable[[HubCoordinator], Any]
    unit: str | None = None
    device_class: SensorDeviceClass | None = None
    measurement: bool = False
    enabled: bool = True


METRICS = (
    Metric("firmware", "Firmware", _value("device", "swVersion")),
    Metric("docsis", "DOCSIS version", _value("line", "docsisVersion")),
    Metric(
        "last_boot", "Last boot", lambda c: c.boot_time, device_class=SensorDeviceClass.TIMESTAMP
    ),
    Metric(
        "uptime", "Uptime", lambda c: c.data.uptime, "s", SensorDeviceClass.DURATION, enabled=False
    ),
    Metric("mode", "Mode", _mode),
    Metric("clients", "Active directly connected devices", _client_count),
    Metric(
        "provisioning_state",
        "DOCSIS provisioning code",
        _value("line", "provisioningState", numeric=True),
    ),
    Metric("locked_sc_qam", "Locked SC-QAM downstream channels", _locked),
    Metric(
        "minimum_snr",
        "Worst SC-QAM downstream SNR",
        _extreme("downstream_sc_qam", "snr_db", min),
        "dB",
        measurement=True,
    ),
    Metric(
        "minimum_rx_power",
        "Lowest SC-QAM downstream power",
        _extreme("downstream_sc_qam", "power_dbmv", min),
        "dBmV",
        measurement=True,
    ),
    Metric(
        "maximum_rx_power",
        "Highest SC-QAM downstream power",
        _extreme("downstream_sc_qam", "power_dbmv", max),
        "dBmV",
        measurement=True,
    ),
    Metric(
        "minimum_tx_power",
        "Lowest SC-QAM upstream power",
        _extreme("upstream_sc_qam", "power_dbmv", min),
        "dBmV",
        measurement=True,
    ),
    Metric(
        "maximum_tx_power",
        "Highest SC-QAM upstream power",
        _extreme("upstream_sc_qam", "power_dbmv", max),
        "dBmV",
        measurement=True,
    ),
    Metric("last_firmware_download", "Last firmware download (Hub clock)", _firmware_event),
    Metric("wan_mtu", "WAN MTU", _value("mtu", "MTUSize", numeric=True), "B", enabled=False),
    Metric(
        "channel_24",
        "2.4 GHz Wi-Fi channel",
        _value("radio", "24g_channel", numeric=True),
        enabled=False,
    ),
    Metric(
        "channel_5",
        "5 GHz Wi-Fi channel",
        _value("radio", "5g_channel", numeric=True),
        enabled=False,
    ),
)

_CHANNEL_METRICS = {
    "power_dbmv": ("Power", "dBmV", True),
    "plc_power_dbmv": ("PLC power", "dBmV", True),
    "snr_db": ("SNR", "dB", True),
    "rxmer_db": ("RxMER", "dB", True),
    "pre_rs_errors": ("Pre-RS errors", None, False),
    "post_rs_errors": ("Post-RS errors", None, False),
    "corrected_active_profile": ("Active profile corrected", None, False),
    "uncorrectable_active_profile": ("Active profile uncorrectable", None, False),
    "t1_timeouts": ("T1 timeouts", None, False),
    "t2_timeouts": ("T2 timeouts", None, False),
    "t3_timeouts": ("T3 timeouts", None, False),
    "t4_timeouts": ("T4 timeouts", None, False),
}
_FAMILIES = {
    "downstream_sc_qam": "Downstream SC-QAM",
    "upstream_sc_qam": "Upstream SC-QAM",
    "downstream_ofdm": "Downstream OFDM",
    "upstream_ofdma": "Upstream OFDMA",
}


class HubSensor(HubEntity, SensorEntity):
    """A current measurement or reported firmware datum."""

    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: HubCoordinator, metric: Metric) -> None:
        super().__init__(coordinator, metric.key)
        self._metric = metric
        self._attr_name = metric.label
        self._attr_device_class = metric.device_class
        self._attr_native_unit_of_measurement = metric.unit
        self._attr_state_class = SensorStateClass.MEASUREMENT if metric.measurement else None
        self._attr_entity_registry_enabled_default = metric.enabled

    @property
    def native_value(self) -> Any:
        return self._metric.value(self.coordinator)

    @property
    def available(self) -> bool:
        return super().available and self.native_value is not None


def _read_channel(family: str, identity: str, field: str) -> Callable:
    def value(c: HubCoordinator) -> Any:
        return next(
            (
                row.get(field)
                for row in c.data.channels.get(family, ())
                if row["channel_id"] == identity
            ),
            None,
        )

    return value


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Publish summary sensors and discover stable channel diagnostic IDs."""
    coordinator: HubCoordinator = entry.runtime_data
    async_add_entities([HubSensor(coordinator, metric) for metric in METRICS])
    discovered: set[str] = set()

    @callback
    def add_channels() -> None:
        entities = []
        for family, rows in coordinator.data.channels.items():
            for row in rows:
                identity = row["channel_id"]
                for field, (label, unit, measurement) in _CHANNEL_METRICS.items():
                    key = f"{family}_{identity}_{field}"
                    if field not in row or key in discovered:
                        continue
                    discovered.add(key)
                    metric = Metric(
                        key,
                        f"{_FAMILIES[family]} {identity} {label}",
                        _read_channel(family, identity, field),
                        unit,
                        measurement=measurement,
                        enabled=False,
                    )
                    entities.append(HubSensor(coordinator, metric))
        if entities:
            async_add_entities(entities)

    add_channels()
    entry.async_on_unload(coordinator.async_add_listener(add_channels))
