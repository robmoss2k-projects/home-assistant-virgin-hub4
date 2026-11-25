# Compatibility and test coverage

The verified baseline is a Virgin Media Hub 4, hardware revision 11,
firmware `01.04.092.07.23.EURO.PC20`, in IPv4 router mode on Home Assistant
2026.11.2. Home Assistant initially polls read-only; enabling management is
optional and is required for writes or active diagnostics. Other firmware
and provisioning modes may expose different controls.

## Verified through Home Assistant

- All 37 extended snapshot groups, DOCSIS and cable health, cached detail,
  and the live diagnostic, guest schedule and rule-list actions.
- Light ring, portal language, connected-device rename, UPnP with no active
  mappings, and enabling and disabling push-button WPS. Changes were read
  back and restored. WPS client pairing was not tested.
- Main and guest Wi-Fi key changes. Guest wizard name, key and expiry were
  recorded together and restored. This trial verified the saved timer, not
  that it fired; actual guest expiry was observed in an earlier direct Hub test.
- Bulk deletion of temporary forwarding, triggering, DHCP reservation and
  wireless MAC access rows; mixed delete/toggle for router MAC and IPv4 IP
  rules; and IP/MAC schedule change and restoration with empty rule tables.
  A populated mixed manual/UPnP table is covered only by fixtures.
- Hub-originated ping and traceroute and the diagnostics wizard with Ethernet
  exercise off. A prior HA pilot verified a private configuration export.

These checks establish Hub readback, not effects on external clients. Other
main Wi-Fi/radio settings, individual rules, DMZ and DHCP lease duration
have earlier direct-Hub evidence, not certification of every combination
through the released integration.

## Outside supported hardware claims

- WAN MTU, global firewall flags, DHCP server/pool/readdress and DHCPv6
  changes, Ethernet link exercise, modem-mode switching and polling in
  modem mode, restore, reboot and factory reset have fixture coverage,
  not physical acceptance. Such actions may interrupt access.
- IPv6-only and DS-Lite deployments and other hardware or firmware versions
  were not commissioned. This firmware discarded non-host IPv6 prefixes
  on write; the integration blocks them on this build. IPv6 writes are
  gated by the Hub's provisioning.
- Expired and rejected busy sessions were simulated. A normal browser
  session coexisted with a Home Assistant read on the tested Hub.
- The Hub administration password is not editable. Hidden WPS PIN,
  disabled guest email and unprovisioned Dynamic DNS are not exposed.

Keep Wi-Fi passwords out of saved automations and shared traces. The
integration excludes them from action responses and snapshots, but Home
Assistant may retain action inputs in its own traces. Treat exported Hub
configuration files as sensitive and do not assume they are encrypted.
