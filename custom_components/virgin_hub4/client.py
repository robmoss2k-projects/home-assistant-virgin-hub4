"""Local Hub 4 admin-session transport with an explicit read allowlist."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from hashlib import pbkdf2_hmac
from ipaddress import IPv4Address, IPv4Network
import json
import logging
import re
import secrets
from time import monotonic
from typing import Any
from urllib.parse import parse_qsl, unquote, urljoin, urlsplit

import aiohttp
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from .portal import Provisioning

_LOGGER = logging.getLogger(__name__)
_LOGIN = "/php/ajaxSet_Password.php"
_LOGOUT = "/php/logout.php"
_USER = "/php/user_data.php"
_MAX_BODY = 2_000_000
_DEFAULT_TIMEOUT = 5
# The signed-in Hub 4 capture took 5.284 s for this combined DOCSIS + log read.
_NETWORK_STATUS_TIMEOUT = 20
_NETWORK_STATUS = "/php/device_networkstatus_data.php"
_MAINTENANCE_REFERER = "/?device_reboot&mid=ReloadAndReboot"
_BACKUP_DOWNLOAD_HANDLER = "/php/trigger_download.php/"
_EMPTY_UPLOAD_DOCUMENT = re.compile(
    r"(?:<!doctype\s+html>\s*)?(?:<html(?:\s[^>]*)?>\s*)?"
    r"(?:<head>\s*</head>\s*)?<body(?:\s[^>]*)?>\s*</body\s*>\s*(?:</html\s*>)?",
    re.IGNORECASE,
)
MAX_BACKUP_BYTES = 4_000_000
_LAN_NETWORKS = tuple(
    IPv4Network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


class HubError(Exception):
    """Base error; messages must not contain payloads or credentials."""


class CannotConnect(HubError):
    """No usable HTTP response from the Hub."""


class AuthenticationError(HubError):
    """The Hub explicitly rejected the settings password."""


class SessionExpired(HubError):
    """The current transaction lost authorization; the password may still be good."""


class SessionBusy(HubError):
    """Another administrator already has a session."""


class UnsupportedHub(HubError):
    """Firmware/session protocol not recognised."""


class InvalidResponse(HubError):
    """Unexpected, missing or incomplete Hub data."""


def normalize_host(host: str) -> str:
    """Accept a private IPv4 management address, not an arbitrary URL."""
    try:
        address = IPv4Address(host.strip())
    except ValueError:
        raise ValueError("Enter the Hub's private IPv4 management address") from None
    if not any(address in net for net in _LAN_NETWORKS):
        raise ValueError("Enter the Hub's private IPv4 management address")
    return str(address)


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _json_object(value: str) -> dict[str, Any]:
    try:
        response = json.loads(value)
    except TypeError, ValueError:
        raise InvalidResponse("Expected a Hub JSON object") from None
    if response in (0, "0"):
        raise SessionExpired("The Hub no longer accepts this session")
    if not isinstance(response, dict):
        raise InvalidResponse("Expected a Hub JSON object")
    return response


def _upload_body(reply: str) -> str:
    """Use the response body the portal's upload iframe would examine."""
    if match := re.search(r"<body(?:\s[^>]*)?>(.*?)</body\s*>", reply, re.I | re.S):
        return match[1].strip()
    return reply.strip()


def _maintenance_reply(reply: str) -> str:
    """Recognise negative replies without assuming an unknown body means success."""
    reply = reply.strip()
    if not reply:
        return "empty"
    if re.fullmatch(r"<pre(?:\s[^>]*)?>\s*</pre\s*>", reply, re.I):
        return "session_expired"
    if "FILE_ERROR" in reply:
        return "file_rejected"
    try:
        value = json.loads(reply)
    except ValueError:
        return "unknown"
    if value in (0, "0"):
        return "session_expired"
    if isinstance(value, dict):
        if value.get("error") or value.get("success") is False:
            return "rejected"
        if not value:
            return "empty_object"
    return "unknown"


def _encode_password(password: str) -> str:
    # Match the firmware's HTML encoding before its normal password exchange.
    return (
        password.replace("&", "&amp;")
        .replace('"', "&quot;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("'", "&#039;")
    )


@dataclass(repr=False, slots=True)
class SessionCrypto:
    """Compatibility with the encrypted format used by the Hub UI."""

    key: bytes
    salt: str
    iv: str
    _requests: int = field(default=0, init=False)

    @classmethod
    def from_password(
        cls, encoded: str, *, salt: str | None = None, iv: str | None = None
    ) -> SessionCrypto:
        salt = salt if salt is not None else secrets.token_hex(8)
        iv = iv if iv is not None else secrets.token_hex(8)
        key = pbkdf2_hmac("sha256", encoded.encode(), bytes.fromhex(salt), 1000, 16)
        return cls(key, salt, iv)

    def metadata(self, action: str) -> dict[str, str]:
        # The Hub encrypts each read reply with the IV supplied in the request.
        # Allocate the same way for reads and writes, including the login, so
        # a single transaction never repeats an AES-CCM key/nonce pair.
        if self._requests >= 2**64:
            raise InvalidResponse("The Hub session exhausted its encryption values")
        nonce = (int(self.iv, 16) + self._requests) % 2**64
        self._requests += 1
        return {"authData": action, "salt": self.salt, "iv": f"{nonce:016x}"}

    def encrypt(self, fields: dict[str, Any], action: str) -> dict[str, str]:
        meta = self.metadata(action)
        blob = AESCCM(self.key, tag_length=16).encrypt(
            bytes.fromhex(meta["iv"]),
            _json(fields | meta).encode(),
            action.encode(),
        )
        return {"encryptedBlob": blob.hex(), **meta}

    def open_response(self, response: dict[str, Any], request: dict[str, str]) -> dict[str, Any]:
        """Only decode a protected reply that matches this request, not an older one."""
        try:
            if any(response[k] != request[k] for k in ("authData", "salt", "iv")):
                raise ValueError
            iv = bytes.fromhex(response["iv"])
            if len(iv) != 8:
                raise ValueError
            plaintext = AESCCM(self.key, tag_length=16).decrypt(
                iv,
                bytes.fromhex(response["encryptedBlob"]),
                request["authData"].encode(),
            )
            return _json_object(plaintext.decode())
        except KeyError, TypeError, ValueError, InvalidTag:
            raise InvalidResponse("Could not decode Hub settings response") from None


# Every path here was observed returning data in the browser capture. No
# generic request function is exported from the Home Assistant integration.
SCRIPT_READS: dict[str, tuple[str, str]] = {
    "home": ("/php/home_data.php", "/"),
    "device": ("/php/device_status_data.php", "/?device_status&mid=Info"),
    "line": (
        _NETWORK_STATUS,
        "/?device_networkstatus&mid=NetworkStatus",
    ),
    "mode": ("/php/modem_settings_data.php", "/?modem_settings&mid=Modem"),
    "client_network": (
        "/php/device_connection_data.php",
        "/?device_connection&mid=ConnectedDevices",
    ),
    "radio": ("/php/wifi_radio_data.php", "/?wifi_radio&mid=WifiRadio"),
    "wps": ("/php/wifi_wps_data.php", "/?wifi_wps&mid=WifiWps"),
    "firewall": ("/php/firewall_data.php", "/?firewall&mid=Firewall"),
    "mac_filter": ("/php/macfilter_data.php", "/?macfilter&mid=MACFilter"),
    "ip_filter": ("/php/ipfilter_data.php", "/?ipfilter&mid=IPFilter"),
    "forwarding": (
        "/php/portforwarding_data.php",
        "/?portforwarding&mid=PortForwarding",
    ),
    "triggering": (
        "/php/porttriggering_data.php",
        "/?porttriggering&mid=PortTriggering",
    ),
    "dmz": ("/php/security_dmz_data.php", "/?security_dmz&mid=DMZ"),
    "dhcp": ("/php/dhcp_setting_data.php", "/?dhcp_setting&mid=DHCP"),
    "upnp": ("/php/upnp_setting_data.php", "/?upnp_setting&mid=uPnP"),
    "mtu": ("/php/tool_mtu_data.php", "/?tool_mtu&mid=MTUSize"),
    "light_ring": ("/php/lightring_data.php", "/?lightring&mid=Lightring"),
    "ping_config": ("/php/tool_ping_data.php", "/?tool_ping&mid=Ping"),
    "trace_config": ("/php/tool_trace_data.php", "/?tool_trace&mid=TraceRoute"),
}

_CLIENT_FIELDS = (
    "numHostEnt",
    "hostName",
    "phyAddress",
    "ipAddress",
    "layer1Interface",
    "maxBitRate",
    "lastDownLinkRate",
    "active",
    "FriendlyName",
    "SSID",
    "HotSpot",
    "ipv6Address",
)
_DHCP_FIELDS = (
    "enableV4",
    "startAddrV4",
    "endAddrV4",
    "subnetIp",
    "subnetMask",
    "leaseTimeV4",
    "typeV6",
    "prefixV6",
    "prefixBeginV6",
    "prefixEndV6",
    "leaseTimeV6",
    "lifetimeV6",
    "intervalV6",
)


@asynccontextmanager
async def owned_session(host: str, password: str) -> AsyncIterator[HubClient]:
    """Open and release one Hub login, without taking over or retrying it."""
    async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as session:
        client = HubClient(session, host)
        await client.login(password)
        try:
            yield client
        finally:
            await client.logout()


class HubClient:
    """One admin transaction. Use an owned aiohttp session, not HA's global jar."""

    def __init__(self, session: aiohttp.ClientSession, host: str) -> None:
        self._session = session
        self._origin = f"http://{normalize_host(host)}"
        self._nonce: str | None = None
        self._crypto: SessionCrypto | None = None
        self._local_admin = False

    async def _post(
        self,
        path: str,
        referer: str = "/",
        *,
        data: dict[str, str] | aiohttp.FormData | None = None,
        allow_empty: bool = False,
    ) -> str:
        timeout = _NETWORK_STATUS_TIMEOUT if path == _NETWORK_STATUS else _DEFAULT_TIMEOUT
        started = monotonic()
        headers = {
            "Origin": self._origin,
            "Referer": self._origin + referer,
            "X-Requested-With": "XMLHttpRequest",
            "CSRF_NONCE": self._nonce or "undefined",
        }
        try:
            async with self._session.post(
                self._origin + path,
                headers=headers,
                data=data,
                allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=timeout, connect=4),
            ) as response:
                if response.status in (401, 403):
                    raise SessionExpired("The Hub rejected the current session")
                if response.status != 200:
                    raise CannotConnect(f"{path}: Hub replied with HTTP {response.status}")
                body = bytearray()
                async for chunk in response.content.iter_chunked(65536):
                    body.extend(chunk)
                    if len(body) > _MAX_BODY:
                        raise InvalidResponse("Hub response exceeds the size limit")
                if not body.strip() and path != _LOGOUT and not allow_empty:
                    if self._nonce is not None:
                        raise SessionExpired("The Hub returned an empty signed-out response")
                    raise InvalidResponse("The Hub did not return the expected data")
                return body.decode("utf-8", errors="replace")
        except TimeoutError:
            raise CannotConnect(
                f"{path}: timed out after {monotonic() - started:.1f}s (request budget {timeout}s)"
            ) from None
        except aiohttp.ClientError as exc:
            raise CannotConnect(f"{path}: HTTP client error ({type(exc).__name__})") from None

    async def login(self, password: str) -> None:
        """Authenticate normally; never replace another portal user's session."""
        if self._nonce is not None:
            raise RuntimeError("Login called twice for one transaction")
        mode = _json_object(
            await self._post(
                _USER,
                data={
                    "userData": _json({"loginCSRMode": "", "UserName": ""}),
                    "opType": "READ",
                },
            )
        )
        if str(mode.get("loginCSRMode")) != "0":
            raise UnsupportedHub("The normal local Hub admin login is not available")
        encoded = _encode_password(password)
        crypto = SessionCrypto.from_password(encoded)
        # The same endpoint also changes passwords. This client never sends
        # the change-password operation: both fields are the original password.
        config = crypto.encrypt(
            {
                "csrfNonce": "undefined",
                "newPassword": encoded,
                "oldPassword": encoded,
                "ChangePassword": "false",
            },
            "encryptData",
        )
        result = _json_object(await self._post(_LOGIN, data={"configInfo": _json(config)}))
        status = result.get("p_status")
        if status == "Active_session":
            raise SessionBusy("The Hub already has an active admin session")
        if not isinstance(status, str) or not status:
            raise InvalidResponse("The Hub did not return a recognised login reply")
        if status != "Match":
            raise AuthenticationError("The Hub did not accept the settings password")
        nonce = result.get("nonce")
        if not isinstance(nonce, str) or not nonce or "\n" in nonce or "\r" in nonce:
            raise InvalidResponse("The Hub did not return a valid session")
        self._crypto = crypto
        self._nonce = nonce
        # Do not infer the Hub's connection classification from its private
        # address or from the browser's hard-coded default.
        self._local_admin = result.get("gwWan") == "f"

    async def logout(self) -> bool:
        """Release only a session obtained by this client."""
        if self._nonce is None:
            return False
        try:
            await self._post(_LOGOUT)
            return True
        except HubError:
            _LOGGER.debug("Could not confirm release of the Hub admin session")
            return False
        finally:
            self._nonce = None
            self._crypto = None
            self._local_admin = False

    def _require_session(self) -> SessionCrypto:
        if self._crypto is None or self._nonce is None:
            raise SessionExpired("There is no Hub admin session")
        return self._crypto

    async def read_script(self, group: str) -> str:
        """Read an allowlisted status fragment."""
        self._require_session()
        path, referer = SCRIPT_READS[group]
        return await self._post(path, referer)

    async def submit_operating_mode(self, *, modem: bool) -> str:
        self._require_session()
        reply = await self._post(
            "/php/ajaxSet_modem_settings.php",
            SCRIPT_READS["mode"][1],
            data={"data": _json({"eRouterMode": "1" if modem else "0", "csrf_nonce": self._nonce})},
            allow_empty=True,
        )
        return reply.strip()

    async def write_light_ring(self, value: int) -> None:
        self._require_session()
        await self._post(
            "/php/ajaxSet_lightring_data.php",
            SCRIPT_READS["light_ring"][1],
            data={"lightRing": _json({"lightRing": value}), "opType": "WRITE"},
            allow_empty=True,
        )

    async def write_upnp(self, enabled: bool) -> None:
        self._require_session()
        await self._post(
            *SCRIPT_READS["upnp"],
            data={"UPnPData": _json({"UPnP_Status": int(enabled)})},
            allow_empty=True,
        )

    async def write_mtu(self, value: int) -> None:
        crypto = self._require_session()
        await self._post(
            "/php/ajaxSet_mtu_size.php",
            SCRIPT_READS["mtu"][1],
            data={"MTUData": _json(crypto.encrypt({"WANMTUSize": value}, "encryptData"))},
            allow_empty=True,
        )

    async def write_firewall(self, fields: dict[str, bool | int]) -> None:
        self._require_session()
        await self._post(
            "/php/ajaxSet_Firewall.php",
            SCRIPT_READS["firewall"][1],
            data={"firewallData": _json(fields | {"csrf_nonce": self._nonce})},
            allow_empty=True,
        )

    async def write_dmz(self, enabled: bool, target: str) -> None:
        self._require_session()
        await self._post(
            "/php/ajaxSet_security_dmz.php",
            SCRIPT_READS["dmz"][1],
            data={
                "data": _json(
                    {"DMZState": int(enabled), "PrivateIP": target, "csrf_nonce": self._nonce}
                )
            },
            allow_empty=True,
        )

    async def write_guest(self, fields: dict[str, Any]) -> None:
        crypto = self._require_session()
        await self._post(
            "/php/ajaxSet_guest_settings.php",
            "/?guest_settings",
            data={"gnData": _json(crypto.encrypt(fields, "encryptData"))},
            allow_empty=True,
        )

    async def write_guest_schedule(self, fields: dict[str, Any]) -> None:
        crypto = self._require_session()
        envelope = crypto.encrypt(fields | {"csrf_nonce": self._nonce}, "encryptData")
        await self._post(
            "/php/wifi_data.php",
            "/",
            data={"wifiData": _json(envelope), "opType": "WRITE"},
            allow_empty=True,
        )

    async def write_radio(self, fields: dict[str, Any]) -> None:
        crypto = self._require_session()
        envelope = crypto.encrypt(fields | {"csrf_nonce": self._nonce}, "encryptData")
        await self._post(
            "/php/wifi_data.php",
            SCRIPT_READS["radio"][1],
            data={"wifiData": _json(envelope), "opType": "WRITE"},
            allow_empty=True,
        )

    async def write_port_rules(
        self,
        group: str,
        payload: dict[str, Any],
        *,
        add: bool,
    ) -> None:
        self._require_session()
        page, field = {
            "forwarding": ("portforwarding", "PortMappingData"),
            "triggering": ("porttriggering", "PortTriggeringData"),
        }[group]
        prefix = "ajaxSet" if add else "ajaxEditDel"
        await self._post(
            f"/php/{prefix}_{page}_data.php",
            SCRIPT_READS[group][1],
            data={field: _json(payload)},
            allow_empty=True,
        )

    async def read_mac_rules(self) -> dict[str, Any]:
        self._require_session()
        return _json_object(
            await self._post(
                "/php/ajaxGet_macfilter_list_data.php",
                SCRIPT_READS["mac_filter"][1],
                data={"macFilterList": "[]"},
            )
        )

    async def add_ip_rule(self, fields: dict[str, Any], *, ip6: bool) -> None:
        self._require_session()
        version = 6 if ip6 else 4
        await self._post(
            f"/php/ajaxSet_ipv{version}_filter_data.php",
            SCRIPT_READS["ip_filter"][1],
            data={f"IPFilter_V{version}_Data": _json(fields)},
            allow_empty=True,
        )

    async def edit_ip_rule(self, key: str | int, *, ip6: bool, enabled: bool, delete: bool) -> None:
        self._require_session()
        fields = {
            "Key": key,
            "Enable": str(enabled).lower(),
            "Delete": str(delete).lower(),
            "IPV6": str(ip6).lower(),
        }
        await self._post(
            "/php/ajaxSet_ipfilter_data.php",
            SCRIPT_READS["ip_filter"][1],
            data={"ipFilterDelOrEnable": _json(fields)},
            allow_empty=True,
        )

    async def write_mac_rules(self, fields: dict[str, Any]) -> None:
        self._require_session()
        await self._post(
            "/php/ajaxSet_macfilter_data.php",
            SCRIPT_READS["mac_filter"][1],
            data={"macfilterData": _json(fields | {"csrf_nonce": self._nonce})},
            allow_empty=True,
        )

    async def write_wps(self, enabled: bool) -> None:
        value = "true" if enabled else "false"
        await self._write_wps({"WPSPbcPinEnable": value, "Wps50Mode": value})

    async def _write_wps(self, fields: dict[str, str]) -> None:
        self._require_session()
        await self._post(
            "/php/ajaxSet_wifi_wps.php",
            SCRIPT_READS["wps"][1],
            data={"WPSdata": _json(fields)},
            allow_empty=True,
        )

    async def start_wps(self) -> None:
        await self._write_wps({"WpsPushButton": "1", "Wps50PushButton": "1"})

    async def clear_failed_wps(self) -> None:
        """Dismiss a failed push-button attempt, as the portal does."""
        await self._write_wps({"WpsPushButton": "3", "Wps50PushButton": "3"})

    async def read_wps_result(self) -> dict[str, str]:
        self._require_session()
        result = _json_object(
            await self._post(
                "/php/ajax_wifi_wps_resultstatus.php",
                SCRIPT_READS["wps"][1],
                data={"WPSdata[WPSstatus]": "", "WPSdata[WPS50status]": ""},
            )
        )
        if not all(isinstance(result.get(k), str) for k in ("WPSstatus", "WPS50status")):
            raise InvalidResponse("The Hub did not report both WPS band results")
        return {k: result[k] for k in ("WPSstatus", "WPS50status")}

    async def read_clients(self) -> dict[str, Any]:
        self._require_session()
        return _json_object(
            await self._post(
                "/php/associated_devices_data.php",
                "/?device_connection&mid=ConnectedDevices",
                data={"assocDevData": _json(dict.fromkeys(_CLIENT_FIELDS, "")), "opType": "READ"},
            )
        )

    async def write_device_label(self, mac: str, label: str) -> None:
        self._require_session()
        await self._post(
            "/php/associated_devices_data.php",
            "/",
            data={
                "assocDevData": _json({"FriendlyName": label, "MACAddress": mac}),
                "opType": "WRITE",
            },
            allow_empty=True,
        )

    async def get_probe_status(self, *, trace: bool) -> dict[str, Any]:
        self._require_session()
        if trace:
            route, field, group, options = (
                "/php/ajaxGet_tool_trace.php",
                "TraceRouteData",
                "trace_config",
                ("state", "result"),
            )
        else:
            route, field, group, options = (
                "/php/ajaxGet_ping_data.php",
                "PingData",
                "ping_config",
                ("status", "SuccessCount", "FailureCount", "avgtime", "mintime", "maxtime"),
            )
        data = dict.fromkeys(options, "") | {"getting": "status"}
        return _json_object(
            await self._post(
                route, SCRIPT_READS[group][1], data={f"{field}[{k}]": v for k, v in data.items()}
            )
        )

    async def set_probe(self, fields: dict[str, Any], *, trace: bool) -> None:
        self._require_session()
        if trace:
            route, field, group = "/php/ajaxSet_tool_trace.php", "data", "trace_config"
            fields = fields | {"csrf_nonce": self._nonce}
        else:
            route, field, group = "/php/ajaxSet_ping_data.php", "PingData", "ping_config"
        await self._post(
            route, SCRIPT_READS[group][1], data={field: _json(fields)}, allow_empty=True
        )

    async def diagnostic_ipv6_dns(self) -> dict[str, Any]:
        self._require_session()
        return _json_object(
            await self._post(
                "/php/ajaxGet_ping_data.php",
                SCRIPT_READS["ping_config"][1],
                data={
                    "PingData[getting]": "DNSQuery",
                    "PingData[TargetAddress]": "ipv6.google.com",
                    "PingData[status]": "",
                },
            )
        )

    async def diagnostic_links(self) -> dict[str, Any]:
        self._require_session()
        fields = dict.fromkeys(
            ("LanPortStatus", "LanPortSpeed", "WiFiClientCount", "WiFiClientSignal"), ""
        )
        return _json_object(
            await self._post(
                "/php/associated_devices_data.php",
                "/",
                data={"assocDevData": _json(fields), "opType": "READ"},
            )
        )

    async def exercise_ethernet_links(self) -> None:
        self._require_session()
        await self._post(
            "/php/associated_devices_data.php",
            "/",
            data={"assocDevData": '{"LanPortLinkDownUp":[]}', "opType": "WRITE"},
            allow_empty=True,
        )

    async def read_dhcp(self, *, clients: bool) -> dict[str, Any]:
        self._require_session()
        fields = ("clientData", "staticData") if clients else _DHCP_FIELDS
        data = dict.fromkeys(fields, "") | {"getting": "clientTbl" if clients else "dhcpInfo"}
        return _json_object(
            await self._post(
                "/php/ajaxGet_dhcp_setting_data.php",
                "/?dhcp_setting&mid=DHCP",
                data={f"dhcpData[{key}]": value for key, value in data.items()},
            )
        )

    async def write_dhcp(self, fields: dict[str, Any]) -> str | None:
        self._require_session()
        result = await self._post(
            "/php/ajaxSet_dhcp_setting_data.php",
            SCRIPT_READS["dhcp"][1],
            data={"DhcpData": _json(fields)},
            allow_empty=True,
        )
        return {
            "SubnetMaskError": "The Hub rejected the subnet mask: it is in use elsewhere.",
            "LanIPError": "The Hub rejected the start address: it is in use elsewhere.",
        }.get(result.strip())

    async def read_schedule(self, *, ip: bool) -> dict[str, Any]:
        self._require_session()
        prefix = "ip" if ip else "mac"
        return _json_object(
            await self._post(
                f"/php/{prefix}_blocktime.php",
                f"/?{prefix}filter",
                data={
                    "blockTimeData[timeSchedules]": "",
                    "blockTimeData[blockTimeType]": "",
                    "opType": "READ",
                },
            )
        )

    async def write_schedule(self, fields: dict[str, Any], *, ip: bool) -> None:
        self._require_session()
        prefix = "ip" if ip else "mac"
        await self._post(
            f"/php/{prefix}_blocktime.php",
            f"/?{prefix}filter",
            data={"blockTimeData": _json(fields), "opType": "WRITE"},
            allow_empty=True,
        )

    async def read_wifi(self, group: str) -> dict[str, Any]:
        crypto = self._require_session()
        if group in ("smart_wifi", "guest_expiry"):
            fields = (
                ("sonAdminStatus", "sonOperationalStatus", "HideSmartWifiSection")
                if group == "smart_wifi"
                else ("EnableGuest", "NetworkName", "GuestWizPassphrase", "ActiveTimeout")
            )
            action = "getWifiData"
            meta = crypto.metadata(action)
            params = dict.fromkeys(fields, "") | meta
            path = "/php/wifi_data.php"
            data = {f"wifiData[{key}]": value for key, value in params.items()} | {"opType": "READ"}
        else:
            if group == "wifi_security":
                path, field, action = (
                    "/php/ajaxGet_wifi_settings_data.php",
                    "wifiData",
                    "doWiFiLoadData",
                )
                fields = ("Configuration", "MACFilter")
            elif group == "guest":
                path, field, action = (
                    "/php/ajaxGet_guest_settings.php",
                    "gnData",
                    "getGuestNetworkData",
                )
                fields = (
                    "enable",
                    "ssid",
                    "broadcast",
                    "security",
                    "passphrase",
                    "24Passphrase",
                    "50Passphrase",
                )
            else:
                raise ValueError("Unknown wireless status group")
            meta = crypto.metadata(action)
            data = {field: _json(dict.fromkeys(fields, "") | meta)}
        result = _json_object(await self._post(path, data=data))
        return crypto.open_response(result, meta)

    async def read_activity(self) -> dict[str, Any]:
        self._require_session()
        fields = (
            "lang",
            "availableLang",
            "cmOperationState",
            "deviceMode",
            "dsliteMode",
            "eRouterMode",
            "isguestssid",
            "ddnsEnable",
        )
        return _json_object(
            await self._post(
                _USER,
                data={"userData": _json(dict.fromkeys(fields, "")), "opType": "READ"},
            )
        )

    async def read_ip_provisioning(self, *, firewall: bool) -> frozenset[str]:
        """Match the portal's distinct DHCP and firewall family visibility."""
        return (await self.read_portal_provisioning(require_dslite=not firewall)).families(
            dhcp=not firewall
        )

    async def read_portal_provisioning(self, *, require_dslite: bool = True) -> Provisioning:
        """Read the live menu inputs, in the same session as the action."""
        self._require_session()
        data = _json_object(
            await self._post(
                _USER,
                data={
                    "userData": _json({"deviceMode": "", "dsliteMode": ""}),
                    "opType": "READ",
                },
            )
        )
        mode, dslite = str(data.get("deviceMode")), str(data.get("dsliteMode"))
        if mode not in {"1", "2", "3"} or (
            require_dslite and mode != "1" and dslite not in {"0", "1", "2"}
        ):
            raise InvalidResponse("The Hub did not report a recognised IP provisioning mode")
        return Provisioning(mode, dslite if dslite in {"0", "1", "2"} else None)

    async def read_portal_language(self, *, choices: bool) -> dict[str, Any]:
        self._require_session()
        field = "availableLang" if choices else "lang"
        return _json_object(
            await self._post(_USER, data={"userData": _json({field: ""}), "opType": "READ"})
        )

    async def write_portal_language(self, language: str) -> None:
        self._require_session()
        await self._post(
            _USER, data={"userData": _json({"lang": language}), "opType": "WRITE"}, allow_empty=True
        )

    async def download_configuration(self) -> tuple[bytes, str]:
        """Fetch the same-origin download issued by the authenticated Hub."""
        self._require_session()
        info = _json_object(
            await self._post(
                _USER,
                _MAINTENANCE_REFERER,
                data={"userData": _json({"backup": ""}), "opType": "READ"},
            )
        )
        href = info.get("url")
        if (
            not isinstance(href, str)
            or not href
            or len(href) > 2048
            or "\\" in href
            or any(ord(c) < 32 for c in href)
        ):
            raise InvalidResponse("The Hub did not issue a usable configuration download")
        try:
            url = urlsplit(urljoin(self._origin + "/", href))
        except ValueError:
            raise InvalidResponse(
                "The Hub returned an invalid configuration download URL"
            ) from None
        origin = urlsplit(self._origin)
        path = unquote(url.path)
        allowed = path.rstrip("/") == "/backup" or (
            path.lower().endswith((".cfg", ".xml")) and not path.startswith("/php/")
        )
        if url.path == _BACKUP_DOWNLOAD_HANDLER:
            # Observed on the UK Hub 4. Follow only this exact handler and
            # only for the nonce issued to the session that requested export.
            try:
                parameters = parse_qsl(
                    url.query, keep_blank_values=True, strict_parsing=True, max_num_fields=1
                )
            except ValueError:
                parameters = []
            allowed = bool(self._nonce) and parameters == [("HTTP_CSRF_NONCE", self._nonce)]
        if (
            url.scheme != origin.scheme
            or url.netloc != origin.netloc
            or url.fragment
            or not allowed
        ):
            raise InvalidResponse(
                "The Hub returned a configuration download outside the local backup routes"
            )
        headers = {
            "Referer": self._origin + _MAINTENANCE_REFERER,
            "CSRF_NONCE": self._nonce or "undefined",
        }
        try:
            async with self._session.get(
                url.geturl(),
                headers=headers,
                allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=25, connect=4),
            ) as response:
                if response.status != 200 or response.content_type == "text/html":
                    raise InvalidResponse("The Hub did not return a configuration file")
                blob = bytearray()
                async for chunk in response.content.iter_chunked(65536):
                    blob.extend(chunk)
                    if len(blob) > MAX_BACKUP_BYTES:
                        raise InvalidResponse("The configuration download exceeds the size limit")
        except TimeoutError, aiohttp.ClientError, ValueError:
            raise CannotConnect("Could not download the Hub configuration file") from None
        first = bytes(blob[:128]).lstrip().lower()
        if not first or first.startswith((b"<html", b"<!doctype html", b"<pre")):
            raise InvalidResponse("The Hub returned an empty download or a portal page")
        extension = (
            ".xml" if path.lower().endswith(".xml") or first.startswith(b"<?xml") else ".cfg"
        )
        return bytes(blob), extension

    async def upload_configuration(self, filename: str, content: bytes) -> str:
        """Send the portal's two restore requests; never retry either request."""
        self._require_session()
        language = await self.read_portal_language(choices=False)
        if language.get("lang") != "en":
            raise InvalidResponse(
                "Restore is prepared only for the captured English portal upload form"
            )
        try:
            prep = await self._post(
                _USER,
                _MAINTENANCE_REFERER,
                data={"userData": _json({"Ignore": ""}), "opType": "WRITE"},
                allow_empty=True,
            )
        except SessionExpired:
            return "session_expired"
        except HubError:
            return "preparation_unverified"
        preparation = _maintenance_reply(prep)
        if preparation not in {"empty", "empty_object"}:
            return preparation if preparation != "unknown" else "preparation_unverified"
        form = aiohttp.FormData()
        form.add_field("opType", "WRITE")
        form.add_field("csrfNonce", self._nonce or "")
        form.add_field(
            "Browse", content, filename=filename, content_type="application/octet-stream"
        )
        reply = await self._post(_USER, _MAINTENANCE_REFERER, data=form, allow_empty=True)
        outcome = _maintenance_reply(_upload_body(reply))
        if outcome in {"file_rejected", "rejected"}:
            return outcome
        if outcome == "empty" and (
            not reply.strip() or _EMPTY_UPLOAD_DOCUMENT.fullmatch(reply.strip())
        ):
            return "submitted"
        return "submission_uncertain"

    async def submit_maintenance(self, operation: str) -> str:
        self._require_session()
        if operation == "factory_reset":
            self.require_local_reset()
        payload = {"reboot": {"reboot": "restart"}, "factory_reset": {"factoryReset": "reset"}}[
            operation
        ]
        reply = (
            await self._post(
                _USER,
                _MAINTENANCE_REFERER,
                data={"userData": _json(payload), "opType": "WRITE"},
                allow_empty=True,
            )
        ).strip()
        outcome = _maintenance_reply(reply)
        return "rejected" if outcome in {"rejected", "file_rejected"} else "submission_uncertain"

    def require_local_reset(self) -> None:
        """Block reset unless this authenticated session is confirmed local."""
        if not self._local_admin:
            raise InvalidResponse("The Hub did not confirm a local admin session for factory reset")

    async def write_wifi_settings(self, fields: dict[str, Any], *, add_filter: bool) -> None:
        crypto = self._require_session()
        payload = fields | {"csrf_nonce": self._nonce}
        if not add_filter:
            payload = crypto.encrypt(payload, "storeMacFilterSetting")
        await self._post(
            "/php/ajaxSet_wifi_settings_data.php",
            "/?wifi_settings&mid=WirelessSecurity",
            data={"wifiData": _json(payload)},
            allow_empty=True,
        )

    async def read_rules(self, group: str) -> dict[str, Any]:
        self._require_session()
        requests = {
            "forwarding_rules": ("/php/ajaxGet_portforwarding_data.php", None),
            "triggering_rules": ("/php/ajaxGet_porttriggering_data.php", None),
            "wireless_filter_list": (
                "/php/ajaxGet_wifi_settings_data.php",
                {"wifiData": _json({"WirelessFilterList": ""})},
            ),
            "wireless_attached_devices": (
                "/php/ajaxGet_wifi_settings_data.php",
                {"wifiData": _json({"AttachedDevices": ""})},
            ),
            "mac_filter_attached_devices": (
                "/php/ajaxGet_macfilter_data.php",
                {"attachedDevicesData": _json({"AttachedDevices": ""})},
            ),
        }
        path, data = requests[group]
        return _json_object(await self._post(path, data=data))
