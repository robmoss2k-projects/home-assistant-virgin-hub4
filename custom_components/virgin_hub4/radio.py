"""Translation between partial HA radio settings and the Hub's full radio form."""

from __future__ import annotations

from typing import Any

from .client import InvalidResponse
from .parser import flag, number

BANDS = ("24g", "5g")
OPTIONS = {
    "24g": (
        ("b,g", "b", "g", "n", "g,n", "b,g,n"),
        ("20MHz", "40MHz", "20,40MHz"),
    ),
    "5g": (
        ("a,n", "a", "n", "ac", "n,ac", "a,n,ac"),
        ("20MHz", "40MHz", "20,40MHz", "20,40,80MHz", "80MHz"),
    ),
}
# The browser maps its bandwidth drop-down indexes back to these tokens. In
# particular its “20/40 MHz” label sends 40MHz; the enum's 20,40MHz is not a choice.
PORTAL_WIDTHS = {"24g": ("20MHz", "40MHz"), "5g": ("20MHz", "40MHz", "80MHz")}
PORTAL_STANDARDS = {"24g": ("n", "g,n", "b,g,n"), "5g": ("ac", "n,ac", "a,n,ac")}
_DFS_CHANNELS = {52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 122, 124, 128, 132, 136, 140}


def read_radio(values: dict[str, Any], smart: dict[str, Any]) -> dict[str, Any]:
    """Normalize flags and selections; keep region channel validation vendor-driven."""
    result = {}
    for band in BANDS:
        status = values.get(f"{band}_stat")
        parsed = {
            # This firmware reports a deliberately disabled radio as LowerLayerDown.
            "enabled": False if str(status).lower() == "lowerlayerdown" else flag(status),
            "automatic": flag(values.get(f"{band}_channel_mode")),
            "channel": number(values.get(f"{band}_channel"), integer=True),
            "standard": values.get(f"{band}_std"),
            "width": values.get(f"{band}_chbw"),
        }
        if any(value is None for value in parsed.values()):
            raise InvalidResponse(f"The Hub did not report all {band} settings")
        result.update({f"{band}_{key}": value for key, value in parsed.items()})
    if (state := flag(smart.get("sonOperationalStatus"))) is not None:
        result["optimisation"] = state
    return result


def plan_radio(
    proposed: dict[str, Any],
    current: dict[str, Any],
    raw: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build the portal's entire radio form, preserving omitted settings."""
    dfs_confirmed = proposed.get("confirm_dfs") is True
    proposed = {key: value for key, value in proposed.items() if key != "confirm_dfs"}
    if not proposed or set(proposed) - current.keys():
        raise ValueError("Provide one or more supported wireless settings")
    desired = current | proposed
    changed = {key for key in proposed if desired[key] != current[key]}
    smart = raw["smart_wifi"]
    admin = flag(smart.get("sonAdminStatus"))
    hidden = flag(smart.get("HideSmartWifiSection"))
    if "optimisation" in changed:
        if admin is not True or hidden is not False:
            raise ValueError("The Hub portal does not expose an editable Smart Wi-Fi switch")
        if not any(desired[f"{band}_enabled"] for band in BANDS):
            raise ValueError("Enable at least one radio before changing Smart Wi-Fi optimisation")
    if (
        admin is not False
        and hidden is not True
        and desired.get("optimisation")
        and changed - {"optimisation"}
    ):
        raise ValueError("Disable Smart Wi-Fi before changing either radio")
    wire: dict[str, Any] = {}
    for band, (standards, widths) in OPTIONS.items():
        enabled = desired[f"{band}_enabled"]
        auto = desired[f"{band}_automatic"]
        channel = desired[f"{band}_channel"]
        standard = desired[f"{band}_standard"]
        width = desired[f"{band}_width"]
        if not enabled and changed & {
            f"{band}_{field}" for field in ("automatic", "channel", "width")
        }:
            raise ValueError(f"Enable the {band} radio before changing its channel or width")
        allowed = {
            int(item)
            for item in str(raw.get(f"{band}_channelList", "")).split(",")
            if item.strip().isdecimal()
        }
        if standard not in standards or width not in widths:
            raise ValueError(f"Unsupported {band} wireless standard or width")
        if f"{band}_standard" in changed and standard not in PORTAL_STANDARDS[band]:
            raise ValueError(f"The Hub portal does not offer that {band} wireless standard")
        if f"{band}_width" in changed and width not in PORTAL_WIDTHS[band]:
            raise ValueError(f"The Hub portal does not offer that {band} channel width")
        if f"{band}_channel" in proposed and auto:
            raise ValueError(f"Use manual channel selection to set a {band} channel")
        if not auto and channel not in allowed:
            raise ValueError(f"The Hub does not list that {band} channel as available")
        if band == "5g" and enabled and not auto:
            if (
                channel in _DFS_CHANNELS
                and changed & {"5g_enabled", "5g_automatic", "5g_channel"}
                and not dfs_confirmed
            ):
                raise ValueError("Confirm the portal warning before selecting a manual DFS channel")
            if channel in {140, 165} and width != "20MHz":
                raise ValueError("The selected 5 GHz channel needs a 20 MHz width")
            if channel in {132, 136} and width in {"80MHz", "20,40,80MHz"}:
                raise ValueError("The selected 5 GHz channel does not allow 80 MHz")
        wire.update(
            {
                f"js_{band}_stat": str(enabled).lower(),
                f"js_{band}_channel_mode": str(auto).lower(),
                f"js_{band}_channel": channel,
                f"js_{band}_mode": standard,
                f"js_{band}_channelBW": width,
            }
        )
    if "optimisation" in changed:
        wire["sonOperationalStatus"] = str(desired["optimisation"]).lower()
    # Auto channels can legitimately move; ensure only fixed channels match.
    expected = {
        key: value
        for key, value in desired.items()
        if not key.endswith("_channel") or not desired[f"{key.split('_', 1)[0]}_automatic"]
    }
    return wire, expected
