"""Translate the Hub's independent MAC and IP filtering schedules."""

from __future__ import annotations

import re
from typing import Any

from .client import InvalidResponse

# The screen displays Monday first, but the wire format uses Sunday as bit zero.
DAYS = ("sun", "mon", "tue", "wed", "thu", "fri", "sat")
MODES = ("always", "daily", "weekly")
_HOURS = (1 << 24) - 1
_DAYS = 0x7F


def _ranges(mask: int) -> list[tuple[int, int]]:
    return [
        (start, end)
        for start in range(24)
        if mask & (1 << start) and (start == 0 or not mask & (1 << (start - 1)))
        for end in [next((i for i in range(start + 1, 24) if not mask & (1 << i)), 24)]
    ]


def _state(mode: str, masks: list[int]) -> dict[str, Any]:
    if mode == "always":
        periods = []
    elif mode == "daily":
        periods = [{"start": start, "end": end} for start, end in _ranges(masks[0])]
    else:
        periods = [
            {"day": DAYS[i], "start": start, "end": end}
            for i in (1, 2, 3, 4, 5, 6, 0)
            for start, end in _ranges(masks[i])
        ]
    return {"mode": mode, "periods": periods}


def _bitfield(value: Any, maximum: int) -> int:
    if type(value) is int and 0 <= value <= maximum:
        return value
    if isinstance(value, str) and re.fullmatch(r"[0-9]{1,10}", value):
        decimal = int(value)
        if decimal <= maximum:
            return decimal
    raise InvalidResponse("The Hub returned an invalid filtering schedule bitfield")


def decode_schedule(data: dict[str, Any], *, ip: bool) -> dict[str, Any]:
    """Return canonical periods; reject incomplete or contradictory readback."""
    kind = data.get("blockTimeType")
    raw = data.get("timeSchedules")
    if ip:
        mode = MODES[_bitfield(kind, 2)]
        if not isinstance(raw, list) or not 1 <= len(raw) <= 7:
            raise InvalidResponse("The Hub did not return a valid IP filtering schedule")
        values = [_bitfield(value, 0x7FFFFFFF) for value in raw]
        if mode == "daily":
            packed = values[0]
            # Some firmware expands the daily mask into seven identical slots
            # and clears the day bits; the daily mode already selects all days.
            expanded = len(values) == 7 and all(value == packed for value in values)
            if not packed >> 7 or not (
                packed & _DAYS == _DAYS or (expanded and not packed & _DAYS)
            ):
                raise InvalidResponse("The Hub returned an invalid daily IP schedule")
            return _state(mode, [packed >> 7])
        if mode == "weekly":
            if (
                len(values) != 7
                or not any(value >> 7 for value in values)
                or any(value & _DAYS != 1 << i for i, value in enumerate(values) if value)
            ):
                raise InvalidResponse("The Hub returned an invalid weekly IP schedule")
            return _state(mode, [value >> 7 for value in values])
        return _state(mode, [])

    mode = {"Always": "always", "ByHour": "daily", "ByDayHour": "weekly"}.get(
        kind if isinstance(kind, str) else ""
    )
    if mode is None or not isinstance(raw, str) or not re.fullmatch(r"[0-9a-fA-F]{44}", raw):
        raise InvalidResponse("The Hub did not return a valid MAC filtering schedule")
    selected = int(raw[-2:], 16)
    masks = [int(raw[i : i + 6], 16) for i in range(0, 42, 6)][::-1]
    if mode == "daily" and (selected != _DAYS or not masks[0]):
        raise InvalidResponse("The Hub returned an invalid daily MAC schedule")
    if mode == "weekly" and (
        not selected or selected != sum(1 << i for i, mask in enumerate(masks) if mask)
    ):
        raise InvalidResponse("The Hub returned an invalid weekly MAC schedule")
    return _state(mode, masks)


def plan_schedule(proposed: dict[str, Any], *, ip: bool) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build the same complete schedule as the portal; do not edit individual rules."""
    mode = proposed.get("mode")
    periods = proposed.get("periods", [])
    if mode not in MODES or not isinstance(periods, list) or len(periods) > 32:
        raise ValueError("Choose always, daily or weekly and provide at most 32 hour ranges")
    if bool(periods) != (mode != "always"):
        raise ValueError("Supply hour ranges for daily or weekly schedules only")
    masks = [0] * 7
    keys = {"start", "end", "day"} if mode == "weekly" else {"start", "end"}
    for period in periods:
        if not isinstance(period, dict) or set(period) != keys:
            raise ValueError("Each range needs start and end hours, and a day for weekly mode")
        start, end = period["start"], period["end"]
        if type(start) is not int or type(end) is not int or not 0 <= start < end <= 24:
            raise ValueError("Use whole hours from 0 to 24 with start before end")
        if mode == "weekly" and period["day"] not in DAYS:
            raise ValueError("Use a weekday abbreviation such as mon or sun")
        index = DAYS.index(period["day"]) if mode == "weekly" else 0
        masks[index] |= ((1 << (end - start)) - 1) << start
    if mode == "daily" and len(periods) > 16:
        raise ValueError("The Hub supports at most 16 daily ranges")
    expected = _state(mode, masks)

    if ip:
        values: Any = {
            "always": str((_HOURS << 7) | _DAYS),
            "daily": (masks[0] << 7) | _DAYS,
            "weekly": [(mask << 7) | (1 << i) if mask else 0 for i, mask in enumerate(masks)],
        }[mode]
        return {"timeSchedules": values, "foralldays": mode == "weekly"}, expected

    if mode == "always":
        packed = "F" * 42 + "7F"
    elif mode == "daily":
        packed = f"{masks[0]:042x}7f"
    else:
        selected = sum(1 << i for i, mask in enumerate(masks) if mask)
        packed = "".join(f"{mask:06x}" for mask in reversed(masks)) + f"{selected:02x}"
    modes = {"always": "Always", "daily": "ByHour", "weekly": "ByDayHour"}
    return {"blockTimeType": modes[mode], "timeSchedules": packed}, expected
