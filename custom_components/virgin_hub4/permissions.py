"""Keep a read-only pilot independent of which actions are globally registered."""

from typing import Any

# The service schema validates fields, but the same action can list or change
# rules. Only the read operations below are allowed before opting in.
_READ_GROUPS = {"diagnostic_status", "guest_schedule_read", "mode_state", "portal_language_read"}
_TABLE_GROUPS = {
    "dhcp_reservations",
    "forwarding",
    "ip_rules",
    "mac_rules",
    "triggering",
    "wifi_access_list",
}


def requires_management(group: str, fields: dict[str, Any]) -> bool:
    """Unknown or newly added actions require opt-in by default."""
    if group in _READ_GROUPS:
        return False
    if group in _TABLE_GROUPS and fields.get("operation") == "list":
        return False
    return group != "cancel_diagnostic"
