"""UI setup, host reconfiguration and password rotation for the local reader."""

from __future__ import annotations

from typing import Any

from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_PASSWORD
from homeassistant.core import callback
from homeassistant.helpers.selector import TextSelector, TextSelectorConfig, TextSelectorType
import voluptuous as vol

from .client import AuthenticationError, HubError, SessionBusy, UnsupportedHub, normalize_host
from .collection import collect
from .const import (
    CONF_EXTENDED,
    CONF_INTERVAL,
    CONF_MAINTENANCE,
    CONF_MANAGEMENT,
    DEFAULT_EXTENDED,
    DEFAULT_HOST,
    DEFAULT_INTERVAL,
    DOMAIN,
)
from .modem_mode import hub_identity


def _schema(host: str) -> vol.Schema:
    return vol.Schema(
        {
            vol.Required(CONF_HOST, default=host): str,
            vol.Required(CONF_PASSWORD): TextSelector(
                TextSelectorConfig(type=TextSelectorType.PASSWORD)
            ),
        }
    )


async def _identify(host: str, password: str) -> str:
    data = await collect(host, password, extended=False)
    return hub_identity(data.groups["device"])


async def _identify_for_entry(host: str, password: str, entry: config_entries.ConfigEntry) -> str:
    # Core holds setup_lock across unload/setup. A connection test must not
    # slip between these phases or open a competing session on a loaded entry.
    async with entry.setup_lock:
        if (coordinator := getattr(entry, "runtime_data", None)) is not None:
            async with coordinator.async_session_scope():
                return await _identify(host, password)
        return await _identify(host, password)


class HubConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Create and repair config entries through the UI."""

    VERSION = 1

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: config_entries.ConfigEntry) -> HubOptionsFlow:
        return HubOptionsFlow()

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        return await self._configure("user", user_input, None)

    async def async_step_reauth(self, entry_data: dict[str, Any]):
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(self, user_input: dict[str, Any] | None = None):
        return await self._configure("reauth_confirm", user_input, self._get_reauth_entry())

    async def async_step_reconfigure(self, user_input: dict[str, Any] | None = None):
        return await self._configure("reconfigure", user_input, self._get_reconfigure_entry())

    async def _configure(
        self,
        step: str,
        user_input: dict[str, Any] | None,
        entry: config_entries.ConfigEntry | None,
    ):
        host = entry.data[CONF_HOST] if entry else DEFAULT_HOST
        errors = {}
        if user_input is not None:
            host = user_input[CONF_HOST]
            try:
                host = normalize_host(host)
            except ValueError:
                errors[CONF_HOST] = "invalid_host"
            else:
                try:
                    password = user_input[CONF_PASSWORD]
                    identity = (
                        await _identify_for_entry(host, password, entry)
                        if entry is not None
                        else await _identify(host, password)
                    )
                except SessionBusy:
                    errors["base"] = "session_busy"
                except AuthenticationError:
                    errors["base"] = "invalid_auth"
                except UnsupportedHub:
                    errors["base"] = "unsupported"
                except HubError:
                    errors["base"] = "cannot_connect"
                else:
                    if entry and entry.unique_id != identity:
                        return self.async_abort(reason="different_hub")
                    data = {CONF_HOST: host, CONF_PASSWORD: user_input[CONF_PASSWORD]}
                    if entry:
                        return self.async_update_reload_and_abort(entry, data_updates=data)
                    await self.async_set_unique_id(identity)
                    self._abort_if_unique_id_configured()
                    return self.async_create_entry(title="Virgin Media Hub 4", data=data)
        return self.async_show_form(step_id=step, data_schema=_schema(host), errors=errors)


class HubOptionsFlow(config_entries.OptionsFlow):
    """Allow a slower poll or disabling optional read groups."""

    async def async_step_init(self, user_input: dict[str, Any] | None = None):
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)
        options = self.config_entry.options
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_EXTENDED, default=options.get(CONF_EXTENDED, DEFAULT_EXTENDED)
                    ): bool,
                    vol.Required(
                        CONF_INTERVAL, default=options.get(CONF_INTERVAL, DEFAULT_INTERVAL)
                    ): vol.All(vol.Coerce(int), vol.Range(min=2, max=60)),
                    vol.Required(
                        CONF_MANAGEMENT, default=options.get(CONF_MANAGEMENT, False)
                    ): bool,
                    vol.Required(
                        CONF_MAINTENANCE, default=options.get(CONF_MAINTENANCE, False)
                    ): bool,
                }
            ),
        )
