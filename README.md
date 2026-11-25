# Virgin Media Hub 4 for Home Assistant

Local monitoring and optional management for the Virgin Media Hub 4.
Requires Home Assistant 2026.11.2 or later. See
[compatibility and test coverage](docs/compatibility.md) before using write actions.

## Current coverage

- Cable modem status, hardware, firmware, uptime and estimated boot time.
- All four captured DOCSIS channel tables and all their fields; summary sensors
  are enabled by default, individual channel readings are opt-in.
- Modem, radio, guest Wi-Fi, WPS and connected-device status, with WAN details,
  provisioning, firewall, filters, forwarding, DHCP, UPnP, DMZ, MTU and the light
  ring available as cached detail. Optional sections can be stopped in Options.
- In extended mode, use cached `mac_filter_rules` for the current scheduled
  MAC rule list; the HTML page initializer under `mac_filter` is not a live
  rule table.
- Network log via cached detail; credential-related message text is omitted and
  common address formats are redacted. Significant newly seen DOCSIS events
  emit `virgin_hub4_log_event`; loading the integration does not replay history.

The cable modem's reported online state is **not** a test of Internet access or
DNS. The network log retains the Hub's own clock values rather than assigning an
unverified time zone. Counter values keep their distinct DOCSIS meanings; this
version does not derive rates or compare profiles across a reset.

Administrator-only management is opt-in. The hardware-tested actions include
the light ring, UPnP without active mappings, main and guest Wi-Fi passphrases,
guest expiry settings, push-button WPS settings, connected-device names,
portal language, and bulk Apply for rule tables and DHCP reservations.
Request the action response to see what the Hub actually reported back.

Main Wi-Fi settings and access-list actions are separate from scheduled MAC
filtering. You can explicitly change either main-band passphrase, or the guest
passphrase, using the corresponding Wi-Fi action. Omitting the passphrase
preserves it. Matching main network names share security and broadcast
settings; an explicit passphrase change then applies to both bands. The Hub
administration password cannot be changed through this integration.

**Set guest Wi-Fi** submits the change at most once, then reads it back about
once a second for up to two minutes in the same admin session. It checks all
three Wi-Fi passphrases against the expected values without returning them.
`not_applied` means the final
read still showed different settings. `outcome_unknown` means the action
could not verify the result or passphrase retention. It does not re-login or
retry the write; inspect the Hub before trying again.

The guest wizard can set a name, passphrase and expiry in one action. Use the
Hub's local clock and a whole or half hour. A recorded date and actual shutoff
are separate checks. Applying a timer while guest Wi-Fi is off requires explicit
permission to enable it.

Rule and reservation actions support multi-row Apply. List first, then use the
returned rule IDs for checkbox changes or deletions. IP filtering sends one
request per changed row and stops if it cannot verify a step; inspect its
response before retrying. See the [compatibility matrix](docs/compatibility.md)
for the exact scope and what has not been verified on hardware.

DHCPv4 settings changes preserve the current LAN and pool unless explicitly
requested. Network-changing settings require confirmation if they could
interrupt clients. If supported firmware changes the Hub's own address and
the old address stops answering, verify the change locally and use
**Settings → Devices & services → Virgin Media Hub 4 → Reconfigure** with the
new address. The integration does not resend the write or move the entry
automatically.

Use **Ping from the Hub** or **Run a traceroute from the Hub** for a single
target. These actions wait for a fresh result; **Read the last Hub network
test** can return a record from an earlier run. **Cancel the Hub network
diagnostic** requests cancellation of an integration-owned run without
stopping a browser test. The diagnostics wizard can use the same Google
ping destinations as the Hub UI. Its optional Ethernet exercise can
disconnect every wired device and should only be used in a maintenance
window or on an isolated Hub.

Do not use the unverified network-changing or maintenance actions on a Hub
you rely on for connectivity. A successful submission does not prove that
the change completed. Backup export was hardware-verified; restore, reboot,
factory reset and modem mode were not. Keep Hub configuration files private.

For an IP filter, use `any`, an address, an IPv4 `start-end` address range,
or an IPv6 prefix. IPv6 rules also require direction and allow/deny policy.
Supply both source and destination port ranges for TCP, UDP or BOTH; omit
ports for other protocols. Use `list` to obtain the rule ID for enabling,
disabling or deleting an existing rule.

For port forwarding, UPnP-created mappings are displayed but never sent as
manual edits. An accepted request is not proof that a mapping was preserved;
if readback sees a changed dynamic table, the result is unverified. Mixed
manual/UPnP edits still need a live check.

Filtering schedules use the Hub's clock, not Home Assistant's. Choose `always`
with no periods, `daily` with start and end hours, or `weekly` with a `day`
(`mon` through `sun`) on each period. `start: 22, end: 24` includes hours 22
and 23; split a range crossing midnight into two periods. Each action replaces
the shared schedule for its own rule set. It does not add or change any rules.

## Home Assistant setup

[Open this integration in Home Assistant Marketplace](https://my.home-assistant.io/redirect/marketplace_repository/?owner=robmoss2k-projects&repository=home-assistant-virgin-hub4&category=integration)

1. In **Settings → Marketplace**, use **Add from link** with this GitHub
   repository, select **Integration**, and install the published version.
   A GitHub connection is needed for repositories added by link.
2. Under **Settings → Devices & services → Add integration**, choose **Virgin
   Media Hub 4**. Enter the private management IPv4 address and the Hub *settings*
   password, not the Wi-Fi password. Log out of the browser portal first.
3. Check **Cable modem online**, **Firmware**, and **Last boot** against the Hub.
   With an administrator account, use **Developer tools → Actions → Read cached
   Hub details** to inspect one group (such as `channels`, `events` or
   `dhcp_server`) or the complete snapshot. This action does not issue requests
   to the Hub. The response marks stale values and optional groups that failed.

Polling defaults to five minutes. Each poll opens its own local admin session
and tries to release it at the end. If the Hub reports its admin portal busy,
the integration waits for a later poll without trying to replace the session.
In the live pilot, the browser and HA sessions coexisted. Back off or disable extended
polling if it interferes with portal use. Do not expose the Hub's management
interface on the Internet.

New entries begin with core telemetry only and management disabled. Enable
extended polling separately if you want the full readout. Use integration
**Options → Allow changes and active diagnostics on this Hub** only when
you want to commission controls. Table listings, saved diagnostic results,
and cached reads remain available when management is disabled. Experimental
maintenance needs both options.

The proven hardware is revision 11 with firmware
`01.04.092.07.23.EURO.PC20` in IPv4 router mode. Other hardware, firmware,
provisioning configurations and modem mode are not supported claims for this release.

## Local checks

Use Python 3.14 in a virtual environment:

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m ruff check custom_components tests tools
```

The optional one-shot probe prompts for the password without displaying it:

```powershell
python -m tools.probe --host 192.168.0.1 --full
```

The probe prints counts, endpoint results and error categories, not credentials
or raw configuration. A capture can be checked offline with
`python -m tools.audit_capture <local-har-path>`. Keep original HAR files,
passwords and device backups out of Git; use synthetic fixtures instead.
