"""Home Assistant polling and availability for a Hub 4 config entry."""

from __future__ import annotations

from asyncio import Event, Lock, timeout
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import timedelta
from hashlib import sha256
import logging
from pathlib import Path
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PASSWORD
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .client import AuthenticationError, HubError, SessionBusy, SessionExpired
from .collection import collect
from .const import (
    CONF_EXTENDED,
    CONF_INTERVAL,
    CONF_MAINTENANCE,
    CONF_MANAGEMENT,
    DEFAULT_EXTENDED,
    DEFAULT_INTERVAL,
    DOMAIN,
)
from .controls import InvalidSetting, apply_setting
from .maintenance import (
    PLAN_TTL,
    MaintenancePlan,
    read_configuration_file,
    write_configuration_file,
)
from .modem_mode import PLAN_SECONDS, ModePlan, verify_hub_identity
from .network_tests import DIAGNOSTIC_RUNS
from .parser import Snapshot
from .permissions import requires_management

_LOGGER = logging.getLogger(__name__)
_UNLOAD_WAIT_SECONDS = 120


class HubCoordinator(DataUpdateCoordinator[Snapshot]):
    """One polling transaction shared by all Hub entities."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            config_entry=entry,
            update_interval=timedelta(minutes=entry.options.get(CONF_INTERVAL, DEFAULT_INTERVAL)),
        )
        self._entry = entry
        self._connection = entry.data
        self._extended = entry.options.get(CONF_EXTENDED, DEFAULT_EXTENDED)
        self.boot_time = None
        self._seen_events: set[str] | None = None
        self._session_lock = Lock()
        self._closing = False
        self._diagnostic_cancel: Event | None = None
        self._mode_plan: ModePlan | None = None
        self._maintenance_plan: MaintenancePlan | None = None

    async def async_update_options(self) -> None:
        """Apply live policy without replacing the owner of Hub operations."""
        self._mode_plan = self._maintenance_plan = None
        interval = timedelta(minutes=self._entry.options.get(CONF_INTERVAL, DEFAULT_INTERVAL))
        extended = self._entry.options.get(CONF_EXTENDED, DEFAULT_EXTENDED)
        changed = self.update_interval != interval or self._extended != extended
        self.update_interval = interval
        self._extended = extended
        if changed and not self._closing and self._entry.data is self._connection:
            await self.async_request_refresh()

    async def async_drain(self) -> bool:
        """Reject queued work and wait for the active operation, without cancelling it."""
        self._closing = True
        try:
            async with timeout(_UNLOAD_WAIT_SECONDS), self._session_lock:
                return True
        except TimeoutError:
            self._closing = False
            _LOGGER.warning("Hub operation still active; refusing to replace its coordinator")
            return False
        except BaseException:
            self._closing = False
            raise

    def resume_operations(self) -> None:
        """Allow the original owner to continue after an unsuccessful unload."""
        self._closing = False

    @asynccontextmanager
    async def async_session_scope(self) -> AsyncIterator[None]:
        """Admit one Hub transaction, including a connection test for this entry."""
        if self._closing:
            raise SessionBusy("The Hub integration is unloading")
        async with self._session_lock:
            if self._closing or self._entry.data is not self._connection:
                raise SessionBusy("The Hub connection is being reloaded")
            yield

    async def async_apply_setting(self, group: str, changes: dict[str, Any]) -> dict[str, Any]:
        """Serialize admin actions with polling; refresh after the session is released."""
        self._check_action_allowed(group, changes)
        if group in {"maintenance_backup", "maintenance_prepare", "maintenance_execute"}:
            async with self._action_lock(group, changes):
                return await self._operate_maintenance(group, changes)
        if group in {"mode_state", "mode_prepare", "mode_execute"}:
            async with self._action_lock(group, changes):
                return await self._operate_mode(group, changes)
        if group == "cancel_diagnostic":
            if self._diagnostic_cancel is None:
                return {"status": "not_running"}
            self._diagnostic_cancel.set()
            return {"status": "cancel_requested"}
        if group in DIAGNOSTIC_RUNS:
            if self._diagnostic_cancel is not None:
                raise InvalidSetting("A Hub diagnostic is already requested by this integration")
            self._diagnostic_cancel = Event()
            try:
                async with self._action_lock(group, changes):
                    return await apply_setting(
                        self._connection[CONF_HOST],
                        self._connection[CONF_PASSWORD],
                        group,
                        changes,
                        cancel=self._diagnostic_cancel,
                        expected_identity=self._entry.unique_id or "",
                    )
            finally:
                self._diagnostic_cancel = None
        if group == "guest_schedule":
            changes = changes | {"time_zone": self.hass.config.time_zone}
        async with self._action_lock(group, changes):
            result = await apply_setting(
                self._connection[CONF_HOST],
                self._connection[CONF_PASSWORD],
                group,
                changes,
                expected_identity=self._entry.unique_id or "",
            )
        # These actions report their authoritative readback in the action session.
        # The normal scheduled poll refreshes the cache without delaying the result.
        deferred = {"guest", "dhcp_v4", "dhcp_v6", "firewall", "mtu"}
        if (
            not self._closing
            and group not in deferred
            and result["status"] in {"verified", "recorded"}
        ):
            await self.async_request_refresh()
        return result

    def _check_action_allowed(self, group: str, changes: dict[str, Any]) -> None:
        if requires_management(group, changes) and not self._entry.options.get(
            CONF_MANAGEMENT, False
        ):
            raise InvalidSetting(
                "This Hub is in read-only mode; enable management in integration Options"
            )
        if group in {
            "maintenance_backup",
            "maintenance_prepare",
            "maintenance_execute",
        } and not self._entry.options.get(CONF_MAINTENANCE, False):
            raise InvalidSetting("Experimental Hub maintenance is disabled for this entry")

    @asynccontextmanager
    async def _action_lock(self, group: str, changes: dict[str, Any]) -> AsyncIterator[None]:
        async with self.async_session_scope():
            # An action can queue behind polling; recheck after waiting for the session.
            self._check_action_allowed(group, changes)
            yield

    async def _operate_mode(self, group: str, changes: dict[str, Any]) -> dict[str, Any]:
        host, password = self._connection[CONF_HOST], self._connection[CONF_PASSWORD]
        if group in {"mode_state", "mode_prepare"}:
            options = self._entry.options
            observed = await apply_setting(
                host,
                password,
                "mode_state",
                {"for_switch": True} if group == "mode_prepare" else {},
            )
            if observed["identity"] != self._entry.unique_id:
                raise InvalidSetting(
                    "The current management address did not identify the configured Hub"
                )
            if group == "mode_state":
                return {"status": "read", "mode": observed["mode"], "management_address": host}
            if self._entry.options is not options:
                raise InvalidSetting("Hub options changed during preparation; prepare again")
            self._mode_plan = None
            self._maintenance_plan = None
            try:
                plan = ModePlan.create(
                    host, observed, changes["mode"], changes.get("router_management_address")
                )
            except ValueError as exc:
                raise InvalidSetting(str(exc)) from None
            self._mode_plan = plan
            return {"status": "prepared", "expires_in_seconds": PLAN_SECONDS, **plan.public()}
        if (plan := self._mode_plan) is None:
            raise InvalidSetting("No operating mode change is prepared")
        try:
            plan.validate(changes["plan_id"], host, changes["confirm_local_recovery"])
        except ValueError as exc:
            raise InvalidSetting(str(exc)) from None
        self._mode_plan = None  # Consume the plan before any write attempt.
        result = await apply_setting(
            host,
            password,
            "mode_submit",
            {
                "identity": plan.identity,
                "current_mode": plan.current_mode,
                "target_mode": plan.target_mode,
            },
        )
        # No forced refresh, implicit rollback or credentials sent to the new address.
        details = {k: v for k, v in plan.public().items() if k != "plan_id"}
        return result | details

    async def _operate_maintenance(self, group: str, changes: dict[str, Any]) -> dict[str, Any]:
        host, password = self._connection[CONF_HOST], self._connection[CONF_PASSWORD]
        options = self._entry.options
        directory = Path(
            self.hass.config.path(".storage", f"{DOMAIN}_configurations", self._entry.entry_id)
        )
        if group == "maintenance_execute":
            if (plan := self._maintenance_plan) is None:
                raise InvalidSetting("No Hub maintenance operation is prepared")
            try:
                plan.validate(changes["plan_id"], host, changes["confirm_local_recovery"])
            except ValueError as exc:
                raise InvalidSetting(str(exc)) from None
            self._maintenance_plan = None
            details: dict[str, Any] = {
                "operation": plan.operation,
                "identity": plan.identity,
                "firmware": plan.firmware,
            }
            if plan.filename is not None:
                try:
                    content = await self.hass.async_add_executor_job(
                        read_configuration_file, directory, plan.filename
                    )
                except OSError, ValueError:
                    raise InvalidSetting(
                        "The selected local configuration is no longer readable"
                    ) from None
                if sha256(content).hexdigest() != plan.digest:
                    raise InvalidSetting("The file changed after preparation; no restore was sent")
                details.update(filename=plan.filename, content=content)
            result = await apply_setting(host, password, "maintenance_submit", details)
            return result | {"operation": plan.operation, "uptime_before_seconds": plan.old_uptime}

        if group == "maintenance_backup":
            result = await apply_setting(
                host,
                password,
                "maintenance_backup",
                {"identity": self._entry.unique_id},
            )
            try:
                saved = await self.hass.async_add_executor_job(
                    write_configuration_file, directory, result["content"], result["extension"]
                )
            except OSError, ValueError:
                raise InvalidSetting(
                    "The backup could not be saved in the private configuration directory"
                ) from None
            return {"status": "saved", **saved, "location": str(directory)}

        operation, filename = changes["operation"], changes.get("filename")
        observed = await apply_setting(
            host,
            password,
            "maintenance_state",
            {"operation": operation} if operation == "factory_reset" else {},
        )
        if observed["identity"] != self._entry.unique_id:
            raise InvalidSetting("The current address did not identify the configured Hub")
        self._maintenance_plan = None
        self._mode_plan = None
        if (operation == "restore") != (filename is not None):
            raise InvalidSetting(
                "A restore needs one local filename; neither reboot nor reset takes one"
            )
        content = None
        if filename is not None:
            try:
                content = await self.hass.async_add_executor_job(
                    read_configuration_file, directory, filename
                )
            except OSError, ValueError:
                raise InvalidSetting(
                    "Choose a readable .cfg or .xml file in this Hub's private directory"
                ) from None
        if self._entry.options is not options:
            raise InvalidSetting("Hub options changed during preparation; prepare again")
        try:
            plan = MaintenancePlan.create(operation, host, observed, filename, content)
        except ValueError as exc:
            raise InvalidSetting(str(exc)) from None
        self._maintenance_plan = plan
        return {
            "status": "prepared",
            "operation": operation,
            "plan_id": plan.id,
            "expires_in_seconds": PLAN_TTL,
            "filename": filename,
            "sha256": plan.digest,
            "location": str(directory) if filename is not None else None,
        }

    async def _async_update_data(self) -> Snapshot:
        try:
            async with self.async_session_scope():
                data = await collect(
                    self._connection[CONF_HOST],
                    self._connection[CONF_PASSWORD],
                    extended=self._entry.options.get(CONF_EXTENDED, DEFAULT_EXTENDED),
                )
                verify_hub_identity(data.groups["device"], self._entry.unique_id)
        except SessionBusy:
            raise UpdateFailed("Hub admin portal in use; polling will retry later") from None
        except SessionExpired:
            raise UpdateFailed("Hub read session expired; polling will retry later") from None
        except AuthenticationError:
            raise ConfigEntryAuthFailed("The Hub rejected the settings password") from None
        except HubError as error:
            raise UpdateFailed(str(error)) from None
        if data.uptime is not None:
            estimate = (data.observed_at - timedelta(seconds=data.uptime)).replace(microsecond=0)
            if self.boot_time is None or abs((self.boot_time - estimate).total_seconds()) > 12:
                self.boot_time = estimate
        else:
            self.boot_time = None
        self._record_events(data)
        return data

    def _record_events(self, data: Snapshot) -> None:
        if (events := data.groups.get("events")) is None:
            return
        current = {row["_fingerprint"] for row in events}
        if self._seen_events is not None:
            emitted = set()
            for row in reversed(events):
                key = row["_fingerprint"]
                if (
                    key in self._seen_events
                    or key in emitted
                    or row["source"] != "docsis"
                    or row["category"] == "other_docsis_event"
                ):
                    continue
                emitted.add(key)
                self.hass.bus.async_fire(
                    f"{DOMAIN}_log_event",
                    {
                        "config_entry_id": self._entry.entry_id,
                        "router_time": row["router_time"],
                        "category": row["category"],
                        "priority": row["priority"],
                    },
                )
        else:
            self._seen_events = set()
        # Firmware rolls the log; keep prior keys until substantial churn.
        self._seen_events.update(current)
        if len(self._seen_events) > 4096:
            self._seen_events = current
