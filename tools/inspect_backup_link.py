"""Request one Hub backup link and report its shape, without fetching the file."""

from __future__ import annotations

import argparse
import asyncio
from getpass import GetPassWarning, getpass
import json
from pathlib import PurePosixPath
import re
from urllib.parse import parse_qsl, unquote, urljoin, urlsplit
import warnings

import aiohttp

from custom_components.virgin_hub4.client import (
    _MAINTENANCE_REFERER,
    _USER,
    HubClient,
    HubError,
    _json_object,
    normalize_host,
)

_DIRECTORY = re.compile(r"[a-z_][a-z_.-]{0,19}", re.I)
_SUFFIX = re.compile(r"\.[a-z0-9]{1,8}", re.I)
_PHP_HANDLER = re.compile(r"/php/[^/\\?#\x00-\x1f\x7f]{1,180}\.php/?", re.I)
_PARAMETER = re.compile(r"[a-z_][a-z0-9_-]{0,24}", re.I)
_BACKUP_SUFFIXES = {".bak", ".bin", ".cfg", ".conf", ".config", ".dat", ".gz", ".xml", ".zip"}


def _parameter_shape(value: str) -> str:
    if not value:
        return "empty"
    if value.isascii() and value.isdecimal():
        return "decimal"
    suffix = PurePosixPath(value).suffix.lower()
    if suffix in _BACKUP_SUFFIXES:
        return ("path" if "/" in value or "\\" in value else "filename") + suffix
    return "opaque"


def summarize_link(href: object, host: str, *, session_nonce: str | None = None) -> dict:
    """Keep credentials, query values, download tokens and actual filenames private."""
    if not isinstance(href, str) or not href or len(href) > 2048:
        return {"link": "unusable"}
    if "\\" in href or any(ord(char) < 32 for char in href):
        return {"link": "contains_unsafe_characters"}
    supplied = urlsplit(href)
    target = urlsplit(urljoin(f"http://{host}/", href))
    path = unquote(target.path)
    parts = PurePosixPath(path).parts[1:]
    directories = [part if _DIRECTORY.fullmatch(part) else "<opaque>" for part in parts[:-1]]
    suffix = PurePosixPath(path).suffix
    query = parse_qsl(target.query, keep_blank_values=True, max_num_fields=24)
    params = [
        {"name": key if _PARAMETER.fullmatch(key) else "<opaque>", "shape": _parameter_shape(value)}
        for key, value in query
    ]
    nonce_values = [value for key, value in query if key == "HTTP_CSRF_NONCE"]
    has_userinfo = target.username is not None or target.password is not None
    # A PHP handler name is not the downloadable config filename. Only report
    # the path on the configured Hub, never the query string or a nonce in a path.
    php_handler = (
        target.path
        if target.hostname == host
        and not has_userinfo
        and _PHP_HANDLER.fullmatch(path)
        and (not session_nonce or session_nonce not in path)
        and not any(len(value) >= 8 and value in path for value in nonce_values)
        else None
    )
    return {
        "form": "absolute" if supplied.scheme else "relative",
        "scheme": target.scheme,
        "same_host": target.hostname == host,
        "explicit_port": target.port,
        "directory_shape": directories,
        "leaf_suffix": suffix if _SUFFIX.fullmatch(suffix) else None,
        "php_handler": php_handler,
        "matches_exact_backup_path": path.rstrip("/") == "/backup",
        "query_present": bool(target.query),
        "query_parameters": params,
        "nonce_matches_session": (
            nonce_values == [session_nonce] if nonce_values and session_nonce else None
        ),
        "fragment_present": bool(target.fragment),
        "userinfo_present": has_userinfo,
    }


async def inspect(host: str, password: str) -> dict:
    async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as session:
        hub = HubClient(session, host)
        await hub.login(password)
        try:
            reply = _json_object(
                await hub._post(
                    _USER,
                    _MAINTENANCE_REFERER,
                    data={"userData": '{"backup":""}', "opType": "READ"},
                )
            )
            return summarize_link(reply.get("url"), host, session_nonce=hub._nonce)
        finally:
            await hub.logout()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="192.168.0.1", type=normalize_host)
    args = parser.parse_args()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", GetPassWarning)
            password = getpass("Hub settings password (input hidden): ")
    except EOFError, GetPassWarning, KeyboardInterrupt:
        print("Use an interactive terminal that can hide input.")
        return 2
    if not password:
        print("No password entered; no login attempted.")
        return 2
    try:
        print(json.dumps(asyncio.run(inspect(args.host, password))))
    except HubError as error:
        print(f"Backup link probe: {type(error).__name__}")
        return 1
    except ValueError:
        print("The Hub returned a malformed download link.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
