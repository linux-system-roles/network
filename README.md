# linux-system-roles/network

[![ansible-lint.yml](https://github.com/linux-system-roles/network/actions/workflows/ansible-lint.yml/badge.svg)](https://github.com/linux-system-roles/network/actions/workflows/ansible-lint.yml) [![ansible-test.yml](https://github.com/linux-system-roles/network/actions/workflows/ansible-test.yml/badge.svg)](https://github.com/linux-system-roles/network/actions/workflows/ansible-test.yml) [![codeql.yml](https://github.com/linux-system-roles/network/actions/workflows/codeql.yml/badge.svg)](https://github.com/linux-system-roles/network/actions/workflows/codeql.yml) [![integration.yml](https://github.com/linux-system-roles/network/actions/workflows/integration.yml/badge.svg)](https://github.com/linux-system-roles/network/actions/workflows/integration.yml) [![markdownlint.yml](https://github.com/linux-system-roles/network/actions/workflows/markdownlint.yml/badge.svg)](https://github.com/linux-system-roles/network/actions/workflows/markdownlint.yml) [![python-unit-test.yml](https://github.com/linux-system-roles/network/actions/workflows/python-unit-test.yml/badge.svg)](https://github.com/linux-system-roles/network/actions/workflows/python-unit-test.yml) [![shellcheck.yml](https://github.com/linux-system-roles/network/actions/workflows/shellcheck.yml/badge.svg)](https://github.com/linux-system-roles/network/actions/workflows/shellcheck.yml) [![woke.yml](https://github.com/linux-system-roles/network/actions/workflows/woke.yml/badge.svg)](https://github.com/linux-system-roles/network/actions/workflows/woke.yml) [![Coverage Status](https://coveralls.io/repos/github/linux-system-roles/network/badge.svg)](https://coveralls.io/github/linux-system-roles/network) [![Code Style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/ambv/black) [![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/linux-system-roles/network.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/linux-system-roles/network/context:python)

## Overview

The `network` role enables users to configure network on the target machines.
This role can be used to configure:

- Ethernet interfaces
- Bridge interfaces
- Bonded interfaces
- VLAN interfaces
- MacVLAN interfaces
- Infiniband interfaces
- Wireless (WiFi) interfaces
- IP configuration
- 802.1x authentication

## Introduction

The  `network` role supports two providers: `nm` and `initscripts`. `nm` is
used by default since RHEL7 and `initscripts` in RHEL6. The `initscripts` provider
requires `network-scripts` package which is deprecated in RHEL8 and dropped in
RHEL9. These providers can be configured per host via the
[`network_provider`](#variables) variable. In absence of explicit configuration, it is
autodetected based on the distribution. However, note that either `nm` or `initscripts`
is not tied to a certain distribution. The `network` role works everywhere the required
API is available. This means that `nm` requires at least NetworkManager's API version 1.2
available and certain settings supported by `nm` provider also requires higher
NetworkManager's API version since which the settings are introduced.

The `network` role supports two modules: `network_connections` and `network_state`.

For each host a list of networking profiles can be configured via the
`network_connections` variable.

- For `initscripts`, profiles correspond to ifcfg files in the
  `/etc/sysconfig/network-scripts/` directory and those ifcfg files
  has the line `NM_CONTROLLED=no` written.

- For `nm`, profiles correspond to connection profiles are handled by
  NetworkManager and only NetworkManager keyfile format profiles are
  supported in `/etc/NetworkManager/system-connections/` since RHEL9.

For each host the network state configuration can also be applied to the interface
directly via the `network_state` variable, and only the `nm` provider supports using
the `network_state` variable.

Note that the `network` role both operates on the connection profiles of the devices
(via the `network_connections` variable) and on devices directly (via the
`network_state` variable). When configuring the connection profiles through the role,
it uses the profile name by default as the interface name. It is also possible to
create generic profiles, by creating for example a profile with a certain IP
configuration without activating the profile. To apply the configuration to the actual
networking interface, use the `nmcli` commands on the target system.

**Warning**: The `network` role updates or creates all connection profiles on
the target system as specified in the `network_connections` variable. Therefore,
the `network` role removes options from the specified profiles if the options are
only present on the system but not in the `network_connections` variable.
Exceptions are mentioned below. However, the partial networking configuration can be
achieved via specifying the network state configuration in the `network_state`
variable.

## Requirements

See below

### Collection requirements

The role requires external collections only for management of `rpm-ostree`
nodes. Please run the following command to install them if you need to manage
`rpm-ostree` nodes:

```bash
ansible-galaxy collection install -vv -r meta/collection-requirements.yml
```

## Variables

The `network` role is configured via variables starting  with  `network_` as
the name prefix. List of variables:

- `network_provider` - The `network_provider` variable allows to set a specific
  provider (`nm` or `initscripts`) . Setting it to `{{
  network_provider_os_default }}`, the provider is set depending on the
  operating system. This is usually `nm` except for RHEL 6 or CentOS 6 systems.
  Changing the provider for an existing profile is not supported. To switch
  providers, it is recommended to first remove profiles with the old provider
  and then create new profiles with the new provider.
- `network_connections` - The connection profiles are configured as
  `network_connections`, which is a list of dictionaries that include specific
  options.
- `network_allow_restart` - It defaults to `false`. To load NetworkManager plugins
  after installation, NetworkManager requires to be restarted. For example, if a
  wireless connection is configured and NetworkManager-wifi is not installed,
  NetworkManager must be restarted prior to the connection being configured. The
  restart can result in connectivity loss and therefore the role does not allow it
  without explicit consent. The user can consent to it by setting
  `network_allow_restart` to `true`. Setting `network_allow_restart` to `false` will
  prevent the role from restarting NetworkManager.
- `network_state` - The network state settings can be configured in the managed
  host, and the format and the syntax of the configuration should be consistent
  with the [nmstate state examples](https://nmstate.io/examples.html) (YAML).

## Examples of Variables

Setting the variables

```yaml
network_provider: nm
network_connections:
  - name: eth0
    #...
network_allow_restart: true
```

```yaml
network_provider: nm
network_state:
  interfaces:
    - name: eth0
    #...
  routes:
    config:
      #...
  dns-resolver:
    config:
      #...
```

## network_connections Options

The `network_connections` variable is a list of dictionaries that include the
following options. List of options:

### `name` (usually required)

The `name` option identifies the connection profile to be configured. It is not
the name of the networking interface for which the profile applies, though we
can associate the profile with an interface and give them the same name. Note
that you can have multiple profiles for the same device, but only one profile
can be active on the device each time. For NetworkManager, a connection can
only be active at one device each time.

- For `NetworkManager`, the `name` option corresponds to the
  [`connection.id`](https://developer.gnome.org/NetworkManager/stable/nm-settings.html#nm-settings.property.connection.id)
  property option.
  Although NetworkManager supports multiple connections with the same `connection.id`,
  the `network` role cannot handle a duplicate `name`. Specifying a `name` multiple
  times refers to the same connection profile.

- For `initscripts`, the `name` option determines the ifcfg file name `/etc/sysconfig/network-scripts/ifcfg-$NAME`.
  Note that the `name` does not specify the `DEVICE` but a filename. As a consequence,
  `'/'` is not a valid character for the `name`.

You can also use the same connection profile multiple times. Therefore, it is possible
to create a profile and activate it separately.

**Note:** The network role will only change the profiles that are specified in the
`network_connections` variable. Therefore, if only the ports of a profile are specified
to be removed from the controller and the controller is not specified, then the
controller profile will remain on the system. This can happen, if for example all ports
are removed from a bond interface.

**Note:** To remove all profiles on a system that are not specified in the
`network_connections` variable, add an entry without a name and `persistent_state:
absent`. This will match and remove all remaining profiles:

```yaml
network_connections:
  - name: eth0  # profiles to keep/configure on the system
    [...]

  - persistent_state: absent  # remove all other profiles
```

### `state`

The `state` option identifies what is the runtime state of  each connection profile. The
`state` option (optional) can be set to the following values:

- `up` -  the connection profile is activated
- `down` - the connection profile is deactivated

#### `state: up`

- For `NetworkManager`, this corresponds to `nmcli connection id {{name}} up`.

- For `initscripts`, this corresponds to `ifup {{name}}`.

When the `state` option is set to `up`, you can also specify the `wait` option (optional):

- `wait: 0` - initiates only the activation, but does not wait until the device is fully
  connected. The connection will be completed in the background, for example after a
  DHCP lease was received.
- `wait: <seconds>` is a timeout that enables you to decide how long you give the device
  to activate. The default is using a suitable timeout. Note that the `wait` option is
  only supported by NetworkManager.

Note that `state: up` always re-activates the profile and possibly changes the
networking configuration, even if the profile was already active before. As
a consequence, `state: up` always changes the system.

#### `state: down`

- For `NetworkManager`,  it corresponds to `nmcli connection id {{name}} down`.

- For `initscripts`, it corresponds to call `ifdown {{name}}`.

You can deactivate a connection profile, even if is currently not active. As a
consequence, `state: down` always changes the system.

Note that if the `state` option is unset, the connection profile's runtime state will
not be changed.

### `persistent_state`

The `persistent_state` option identifies if a connection profile is persistent (saved on
disk). The `persistent_state` option can be set to the following values:

#### `persistent_state: present` (default)

Note that if `persistent_state` is `present` and the connection profile contains
the `type` option, the profile will be created or updated. If the connection profile is
incomplete (no `type` option), the behavior is undefined. Also, the `present` value
does not directly result in a change in the network configuration. If the `state` option
is not set to `up`, the profile is only created or modified, not activated.

For NetworkManager, the new connection profile is created with the `autoconnect`
option enabled by default. Therefore, NetworkManager can activate the new
profile on a currently disconnected device. ([rh#1401515](https://bugzilla.redhat.com/show_bug.cgi?id=1401515)).

#### `persistent_state: absent`

The `absent` value ensures that the profile is not present on the
target host. If a profile with the given `name` exists, it will be deleted. In this case:

- `NetworkManager` deletes all connection profiles with the corresponding
  `connection.id`. Deleting a profile usually does not change the current networking
  configuration, unless the profile was currently activated on a device. Deleting the
  currently active connection profile disconnects the device. That makes the device
  eligible to autoconnect another connection (for more details, see
  [rh#1401515](https://bugzilla.redhat.com/show_bug.cgi?id=1401515)).

- `initscripts` deletes the ifcfg file in most cases with no impact on the runtime state
  of the system unless some component is watching the sysconfig directory.

**Note**: For profiles that only contain a `state` option, the `network` role only activates
or deactivates the connection without changing its configuration.

### `type`

The `type` option can be set to the following values:

- `ethernet`
- `bridge`
- `bond`
- `team`
- `vlan`
- `macvlan`
- `infiniband`
- `wireless`
- `dummy`

#### `type: ethernet`

If the type is `ethernet`, then there can be an extra `ethernet` dictionary with the following
items (options): `autoneg`, `speed` and `duplex`, which correspond to the
settings of the `ethtool` utility with the same name.

- `autoneg`: `true` (default) or `false` [if auto-negotiation is enabled or disabled]
- `speed`: speed in Mbit/s
- `duplex`: `half` or `full`

Note that the `speed` and `duplex` link settings are required when autonegotiation is
disabled (`autoneg: false`).

#### `type: bridge`, `type: bond`, `type: team`

The `bridge`, `bond`, `team` device types work similar. Note that `team` is not
supported in RHEL6 kernels, and has been deprecated in RHEL 9.

For ports, the `port_type` and `controller` properties must be set. Note that ports
should not have `ip` settings, which means that the active ports will not have IP
addresses assigned.

The `controller` refers to the `name` of a profile in the Ansible
playbook. It is neither an interface-name nor a connection-id of
NetworkManager.

- For NetworkManager, `controller` will be converted to the `connection.uuid`
  of the corresponding profile.

- For initscripts, the controller is looked up as the `DEVICE` from the corresponding
  ifcfg file.

As `controller` refers to other profiles of the same or another play, the order of the
`connections` list matters. Profiles that are referenced by other profiles need to be
specified first. Also, `--check` ignores the value of the `controller` and assumes it
will be present during a real run. That means, in presence of an invalid `controller`,
`--check` may signal success but the actual play run fails.

If only bringing down the `controller` profile , then the port profiles will be brought
down automatically. If bringing down the connection on some or all ports, then the
controller profile stay active.

The `team` type uses `roundrobin` as the `runner` configuration. No further
configuration is supported at the moment.

#### `type: vlan`

Similar to `controller`, the `parent` references the connection profile in the ansible
role.
Here is a way to specify the VLAN ID

```yaml
type: vlan
vlan_id: 123

#### `type: macvlan`

Similar to `controller` and `vlan`, the `parent` references the connection profile in
the ansible role.

#### `type: infiniband`

For the infiniband connection, currently it is only supported for the nm provider, and
the following options are supported:

- `p_key`: The infiniband P_Key to use for the device. When it is not specified, then
  the connection is created on the physical infiniband fabrics. Otherwise, it is a
  16-bit unsigned integer and the ipoib (IP over Infiniband) connection will be
  created, the high bit should be set if it is a "full membership" P_Key. The special
  `p_key` values 0x0000 and 0x8000 are invalid as kernel does not support them.
- `transport_mode`: The ipoib (IP over Infiniband) connection operation mode. The
  possible modes are `datagram` (default) and `connected`.

**Note:** If the `p_key` is specified , then the `interface_name` must be unset.

#### `type: wireless`

The `wireless` type supports WPA-PSK (password) authentication, WPA-EAP (802.1x)
authentication, WPA3-Personal SAE (password) authentication and Enhanced Open (OWE).

`nm` (NetworkManager) is the only supported `network_provider` for this type.

If WPA-EAP is used, ieee802_1x settings must be defined in the
[ieee802_1x](#ieee802_1x) option.

The following options are supported:

- `ssid`: the SSID of the wireless network (required)
- `key_mgmt` (required)
  Any key from following key list:

  - `owe`
  - `sae`
  - `wpa-eap`
  - `wpa-psk`

- `password`: password for the network (required if `wpa-psk` or `sae` is used)

#### `type: dummy`

Dummy network interface, `nm` (NetworkManager) is the only supported `network_provider`
for this type.

### `autoconnect`

By default, profiles are created with autoconnect enabled.

- For `NetworkManager`, this corresponds to the `connection.autoconnect` property.

- For `initscripts`, this corresponds to the `ONBOOT` property.

### `mac`

The `mac` address is optional and restricts the profile to be usable only on
devices with the given MAC address. `mac` is only allowed for `type`
`ethernet` or `infiniband` to match a non-virtual device with the
profile. The value of the `mac` address needs to be specified in hexadecimal notation
using colons (for example: `mac: "00:00:5e:00:53:5d"`). To avoid YAML parsing mac
addresses as integers in sexagesimal (base 60) notation (see
<https://yaml.org/spec/1.1/#id858600>), it is recommended to always quote the value
with double quotes and sometimes it is necessary.

- For `NetworkManager`, `mac` is the permanent MAC address, `ethernet.mac-address`.

- For `initscripts`,  `mac` is the currently configured MAC address of the device (`HWADDR`).

### `cloned_mac`

The `cloned_mac` address is optional and allow to specify the strategy to get the default
mac or to set your own mac. The value of the `cloned_mac` address needs to be specified in
hexadecimal notation like `mac` property. Besides explicitly specifying the value as a MAC
address with hexadecimal notation, the following special values are also supported:

- `default`: honor the default behavior in NetworkManager
- `permanent`: use the permanent MAC address of the device
- `preserve`: don't change the MAC address of the device upon activation
- `random`: generate a randomized value upon each connect
- `stable`: generate a stable, hashed MAC address

### `mtu`

The `mtu` option denotes the maximum transmission unit for the profile's
device. The maximum value depends on the device. For virtual devices, the
maximum value of the `mtu` option depends on the underlying device.

### `interface_name`

For the `ethernet` and `infiniband`  types, the `interface_name` option restricts the
profile to the given interface by name. This argument is optional and by default the
profile name is used unless a mac address is specified using the `mac` key. Specifying
an empty string (`""`) means that the profile is not restricted to a network interface.

**Note:** With [persistent interface naming](https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/Networking_Guide/ch-Consistent_Network_Device_Naming.html),
the interface is predictable based on the hardware configuration.
Otherwise, the `mac` address might be an option.

For virtual interface types such as bridges, the `interface_name` is the name of the created
interface. In case of a missing `interface_name`, the `name` of the profile name is used.

**Note:** The `name` (the profile name) and the `interface_name` (the device name) may be
different or the profile may not be tied to an interface at all.

### `match`

Settings to specify devices or systems matching a profile. Currently, only the `path`
setting is implemented.

The settings support a list of patterns which support the following modifiers and
wildcards:

**Special modifiers for `match` settings:**

- `|`, the element is an alternative, the match evaluates to be true if at least one of
  the alternatives matches (logical OR). By default, an element is an alternative.
  This means that an element `foo` behaves the same as `|foo`

- `&`, the element is mandatory, the match evaluates to be true if all the element
  matches (logical AND)

- `!`, an element can also be inverted with exclamation mark (`!`) between the pipe
  symbol (or the ampersand) and before the pattern. Note that `!foo` is a shortcut for
  the mandatory match `&!foo`

- `\`, a backslash can be used at the beginning of the element (after the optional
  special characters) to escape the start of the pattern. For example, `&\!a` is an
  mandatory match for literally `!a`

**Wildcard patterns for `match` Settings:**
In general these work like shell globs.

- `*`, matches zero or more of any character
- `?`, matches any single character
- `[fo]` - matches any single `f` or `o` character - also supports ranges - `[0-9]`
  will match any single digit character

### `path`

The `path` setting is a list of patterns to match against the `ID_PATH` udev property
of devices. The `ID_PATH` udev property represents the persistent path of a device. It
consists of a subsystem string (pci, usb, platform, etc.) and a subsystem-specific
identifier. The `ID_PATH` of a device can be obtained with the command
`udevadm info /sys/class/net/$dev | grep ID_PATH=` or by looking at the `path` property
exported by NetworkManager (`nmcli -f general.path device show $dev`). The `path`
setting is optional and restricts the profile to be activated only on devices with a
matching `ID_PATH`. The `path` setting is only supported for ethernet or infiniband
profiles. It supports modifiers and wildcards as described for match settings.

### `zone`

The `zone` option sets the firewalld zone for the interface.

Ports to the bridge, bond or team devices cannot specify a zone.

### `ip`

The IP configuration supports the following options:

- `address`
  Manual addressing can be specified via a list of addresses under the `address` option.

- `auto_gateway`

  If enabled, a default route will be configured using the default gateway. If disabled,
  the default route will be removed.

  If this variable is not specified, the role will use the default behavior of the
  `network_provider` selected.

  Setting this option to `false` is equivalent to:

  - `DEFROUTE = no` in initscripts, or
  - `ipv4.never-default/ipv6.never-default yes` in nmcli

- `dhcp4`, `auto6`, and `ipv6_disabled`

  Also, manual addressing can be specified by setting either `dhcp4` or `auto6`.
  The `dhcp4` key is  for DHCPv4 and `auto6`  for  StateLess Address Auto Configuration
  (SLAAC). Note that the `dhcp4` and `auto6` keys can be omitted and the default key
  depends on the presence of manual addresses. `ipv6_disabled` can be set to disable
  ipv6 for the connection.

- `dhcp4_send_hostname`

  If `dhcp4` is enabled, it can be configured whether the DHCPv4 request includes
  the hostname via the `dhcp4_send_hostname` option. Note that `dhcp4_send_hostname`
  is only supported by the `nm` provider and corresponds to
  [`ipv4.dhcp-send-hostname`](https://developer.gnome.org/NetworkManager/stable/nm-settings.html#nm-settings.property.ipv4.dhcp-send-hostname)
  property.

- `dns`

  Manual DNS configuration can be specified via a list of addresses given in the
  `dns` option.

- `dns_search`

  Manual DNS configuration can be specified via a list of domains to search given in
  the `dns_search` option.

- `dns_options`

  `dns_options` is only supported for the NetworkManager provider. Manual DNS
  configuration via a list of DNS options can be given in the `dns_options`. The list
  of supported DNS options for IPv4 nameservers is described in
  [man 5 resolv.conf](https://man7.org/linux/man-pages/man5/resolv.conf.5.html).
  Currently, the list of supported DNS options is:
  - `attempts:n`
  - `debug`
  - `edns0`
  - `inet6`
  - `ip6-bytestring`
  - `ip6-dotint`
  - `ndots:n`
  - `no-aaaa`
  - `no-check-names`
  - `no-ip6-dotint`
  - `no-reload`
  - `no-tld-query`
  - `rotate`
  - `single-request`
  - `single-request-reopen`
  - `timeout:n`
  - `trust-ad`
  - `use-vc`

  **Note:** The "trust-ad" setting is only honored if the profile contributes name
  servers to resolv.conf, and if all contributing profiles have "trust-ad" enabled.
  When using a caching DNS plugin (dnsmasq or systemd-resolved in NetworkManager.conf)
  then "edns0" and "trust-ad" are automatically added.

- `dns_priority`

  DNS servers priority. The relative priority for DNS servers specified by this
  setting. The default value is 0, a lower numerical value has higher priority.
  The valid value of `dns_priority` ranges from -2147483648 to 2147483647. Negative
  values have the special effect of excluding other configurations with a greater
  numerical priority value; so in presence of at least one negative priority, only
  DNS servers from connections with the lowest priority value will be used.

- `gateway4` and `gateway6`

  The default gateway for IPv4 (`gateway4`) or IPv6 (`gateway6`) packets.

- `ipv4_ignore_auto_dns` and `ipv6_ignore_auto_dns`

  If enabled, the automatically configured name servers and search domains (via
  DHCPv4, DHCPv6, modem etc) for IPv4 or IPv6 are ignored, only the name servers and
  search domains specified in `dns` and `dns_search` properties are used. The
  settings are distinguished by the address families. The variables are not supported
  by initscripts provider.

  If the variables are not specified, the role will use the default behavior of nm
  provider.

- `route_metric4` and `route_metric6`

  For `NetworkManager`, `route_metric4` and `route_metric6` corresponds to the
  [`ipv4.route-metric`](https://developer.gnome.org/NetworkManager/stable/nm-settings.html#nm-settings.property.ipv4.route-metric)
  and
  [`ipv6.route-metric`](https://developer.gnome.org/NetworkManager/stable/nm-settings.html#nm-settings.property.ipv6.route-metric)
  properties, respectively. If specified, it determines the route metric for DHCP
  assigned routes and the default route, and thus the priority for multiple
  interfaces. For `initscripts`, `route_metric4` sets the metric for the default
  route and `route_metric6` is not supported.

- `route`

  Static route configuration can be specified via a list of routes given in the
  `route` option. The default value is an empty list. Each route is a dictionary with
  the following entries: `gateway`, `metric`, `network`, `prefix`, `table` and `type`.
  `network` and `prefix` specify the destination network. `table` supports both the
  numeric table and named table. In order to specify the named table, the users have to
  ensure the named table is properly defined in `/etc/iproute2/rt_tables` or
  `/etc/iproute2/rt_tables.d/*.conf`. The optional `type` key supports the values
  `blackhole`, `prohibit`, and `unreachable`.
  See [man 8 ip-route](https://man7.org/linux/man-pages/man8/ip-route.8.html#DESCRIPTION)
  for their definition. Routes with these types do not support a gateway. If the type
  is not specified, the route is considered as a unicast route. Note that the classless
  inter-domain routing(CIDR) notation or the network mask notation are not supported
  for the `network` key.

- `routing_rule`

  The policy routing rules can be specified via a list of rules given in the
  `routing_rule` option, which allow routing the packets on other packet fields
  except for destination address. The default value is a an empty list. Each rule is
  a dictionary with the following entries:
  - `priority` -
      The priority of the rule. A valid priority ranges from 0 to 4294967295. Higher
      number means lower priority.
  - `action` -
      The action of the rule. The possible values are `to-table` (default),
      `blackhole`, `prohibit`, `unreachable`.
  - `dport`-
      The range of the destination port (e.g. `1000 - 2000`). A valid dport value for
      both start and end ranges from 0 to 65534. And the start cannot be greater than
      the end.
  - `family` -
      The IP family of the rule. The possible values are `ipv4` and `ipv6`.
  - `from` -
      The source address of the packet to match (e.g. `192.168.100.58/24`).
  - `fwmark` -
      The fwmark value of the packet to match.
  - `fwmask` -
      The fwmask value of the packet to match.
  - `iif` -
      Select the incoming interface name to match.
  - `invert` -
      Invert the selected match of the rule. The possible values are boolean values
      `true` and `false` (default). If the value is `true`, this is equivalent to match
      any packet that not satisfying selected match of the rule.
  - `ipproto` -
      Select the IP protocol value to match, the valid value ranges from 1 to 255.
  - `oif` -
      Select the outgoing interface name to match.
  - `sport` -
      The range of the source port (e.g. `1000 - 2000`). A valid sport value for both
      start and end ranges from 0 to 65534. And the start cannot be greater than the
      end.
  - `suppress_prefixlength` -
      Reject routing decisions that have a prefix length of the specified or less.
  - `table` -
      The route table to look up for the `to-table` action. `table` supports both the
      numeric table and named table. In order to specify the named table, the users
      have to ensure the named table is properly defined in `/etc/iproute2/rt_tables`
      or `/etc/iproute2/rt_tables.d/*.conf`.
  - `to` -
      The destination address of the packet to match (e.g. `192.168.100.58/24`).
  - `tos` -
      Select the tos value to match.
  - `uid` -
      The range of the uid to match (e.g. `1000 - 2000`). A valid uid value for both
      start and end ranges from 0 to 4294967295. And the start cannot be greater than
      the end.

- `route_append_only`

  The `route_append_only` option allows only to add new routes to the
  existing routes on the system.

  If the `route_append_only` boolean option is set to `true`, the specified routes are
  appended to the existing routes. If `route_append_only` is set to `false` (default),
  the current routes are replaced. Note that setting `route_append_only` to `true`
  without setting `route` has the effect of preserving the current static routes.

- `rule_append_only`

  The `rule_append_only` boolean option allows to preserve the current routing rules.

**Note:** When `route_append_only` or `rule_append_only` is not specified, the network
role deletes the current routes or routing rules.

**Note:** Ports to the bridge, bond or team devices cannot specify `ip` settings.

### `ethtool`

The ethtool settings allow to enable or disable various features. The names
correspond to the names used by the `ethtool` utility. Depending on the actual
kernel and device, changing some options might not be supported.

The ethtool configuration supports the following options:

- `ring`

  Changes the `rx`/`tx` `ring` parameters of the specified network device. The list
  of supported `ring` parameters is:
  - `rx` - Changes the number of ring entries for the Rx ring.
  - `rx-jumbo` - Changes the number of ring entries for the Rx Jumbo ring.
  - `rx-mini` - Changes the number of ring entries for the Rx Mini ring.
  - `tx` - Changes the number of ring entries for the Tx ring.

```yaml
  ethtool:
    features:
      esp_hw_offload: true|false  # optional
      esp_tx_csum_hw_offload: true|false  # optional
      fcoe_mtu: true|false  # optional
      gro: true|false  # optional
      gso: true|false  # optional
      highdma: true|false  # optional
      hw_tc_offload: true|false  # optional
      l2_fwd_offload: true|false  # optional
      loopback: true|false  # optional
      lro: true|false  # optional
      ntuple: true|false  # optional
      rx: true|false  # optional
      rx_all: true|false  # optional
      rx_fcs: true|false  # optional
      rx_gro_hw: true|false  # optional
      rx_udp_tunnel_port_offload: true|false  # optional
      rx_vlan_filter: true|false  # optional
      rx_vlan_stag_filter: true|false  # optional
      rx_vlan_stag_hw_parse: true|false  # optional
      rxhash: true|false  # optional
      rxvlan: true|false  # optional
      sg: true|false  # optional
      tls_hw_record: true|false  # optional
      tls_hw_tx_offload: true|false  # optional
      tso: true|false  # optional
      tx: true|false  # optional
      tx_checksum_fcoe_crc: true|false  # optional
      tx_checksum_ip_generic: true|false  # optional
      tx_checksum_ipv4: true|false  # optional
      tx_checksum_ipv6: true|false  # optional
      tx_checksum_sctp: true|false  # optional
      tx_esp_segmentation: true|false  # optional
      tx_fcoe_segmentation: true|false  # optional
      tx_gre_csum_segmentation: true|false  # optional
      tx_gre_segmentation: true|false  # optional
      tx_gso_partial: true|false  # optional
      tx_gso_robust: true|false  # optional
      tx_ipxip4_segmentation: true|false  # optional
      tx_ipxip6_segmentation: true|false  # optional
      tx_nocache_copy: true|false  # optional
      tx_scatter_gather: true|false  # optional
      tx_scatter_gather_fraglist: true|false  # optional
      tx_sctp_segmentation: true|false  # optional
      tx_tcp_ecn_segmentation: true|false  # optional
      tx_tcp_mangleid_segmentation: true|false  # optional
      tx_tcp_segmentation: true|false  # optional
      tx_tcp6_segmentation: true|false  # optional
      tx_udp_segmentation: true|false  # optional
      tx_udp_tnl_csum_segmentation: true|false  # optional
      tx_udp_tnl_segmentation: true|false  # optional
      tx_vlan_stag_hw_insert: true|false  # optional
      txvlan: true|false  # optional
    coalesce:
      adaptive_rx: true|false  # optional
      adaptive_tx: true|false  # optional
      pkt_rate_high: 0  # optional mininum=0 maximum=0xffffffff
      pkt_rate_low: 0  # optional mininum=0 maximum=0xffffffff
      rx_frames: 0  # optional mininum=0 maximum=0xffffffff
      rx_frames_high: 0  # optional mininum=0 maximum=0xffffffff
      rx_frames_irq: 0  # optional mininum=0 maximum=0xffffffff
      rx_frames_low: 0  # optional mininum=0 maximum=0xffffffff
      rx_usecs: 0  # optional mininum=0 maximum=0xffffffff
      rx_usecs_high: 0  # optional mininum=0 maximum=0xffffffff
      rx_usecs_irq: 0  # optional mininum=0 maximum=0xffffffff
      rx_usecs_low: 0  # optional mininum=0 maximum=0xffffffff
      sample_interval: 0  # optional mininum=0 maximum=0xffffffff
      stats_block_usecs: 0  # optional mininum=0 maximum=0xffffffff
      tx_frames: 0  # optional mininum=0 maximum=0xffffffff
      tx_frames_high: 0  # optional mininum=0 maximum=0xffffffff
      tx_frames_irq: 0  # optional mininum=0 maximum=0xffffffff
      tx_frames_low: 0  # optional mininum=0 maximum=0xffffffff
      tx_usecs: 0  # optional mininum=0 maximum=0xffffffff
      tx_usecs_high: 0  # optional mininum=0 maximum=0xffffffff
      tx_usecs_irq: 0  # optional mininum=0 maximum=0xffffffff
      tx_usecs_low: 0  # optional mininum=0 maximum=0xffffffff
    ring:
      rx: 0  # optional mininum=0 maximum=0xffffffff
      rx_jumbo: 0  # optional mininum=0 maximum=0xffffffff
      rx_mini: 0  # optional mininum=0 maximum=0xffffffff
      tx: 0  # optional mininum=0 maximum=0xffffffff
```

### `ieee802_1x`

Configures 802.1x authentication for an interface.

Currently, NetworkManager is the only supported provider and EAP-TLS is the only
supported EAP method.

SSL certificates and keys must be deployed on the host prior to running the role.

- `eap`

  The allowed EAP method to be used when authenticating to the network with 802.1x.

  Currently, `tls` is the default and the only accepted value.

- `identity` (required)

  Identity string for EAP authentication methods.

- `private_key` (required)

  Absolute path to the client's PEM or PKCS#12 encoded private key used for 802.1x
  authentication.

- `private_key_password`

  Password to the private key specified in `private_key`.

- `private_key_password_flags`

  List of flags to configure how the private key password is managed.

  Multiple flags may be specified.

  Valid flags are:
  - `none`
  - `agent-owned`
  - `not-saved`
  - `not-required`

  See NetworkManager documentation on "Secret flag types" more details (`man 5
  nm-settings`).

- `client_cert` (required)

  Absolute path to the client's PEM encoded certificate used for 802.1x
  authentication.

- `ca_cert`

  Absolute path to the PEM encoded certificate authority used to verify the EAP
  server.

- `ca_path`

  Absolute path to directory containing additional pem encoded ca certificates used to
  verify the EAP server. Can be used instead of or in addition to ca_cert. Cannot be
  used if system_ca_certs is enabled.

- `system_ca_certs`

  If set to `true`, NetworkManager will use the system's trusted ca
  certificates to verify the EAP server.

- `domain_suffix_match`

  If set, NetworkManager will ensure the domain name of the EAP server certificate
  matches this string.

### `bond`

The `bond` setting configures the options of bonded interfaces (type `bond`).
See the [kernel documentation for
bonding](https://www.kernel.org/doc/Documentation/networking/bonding.txt) or
your distribution `nmcli` documentation for valid values. It supports the
following options:

- `mode`

  Bonding mode. The possible values are `balance-rr` (default), `active-backup`,
  `balance-xor`, `broadcast`, `802.3ad`, `balance-tlb`, or `balance-alb`.

- `ad_actor_sys_prio`

  In `802.3ad` bonding mode, this specifies the system priority. The valid range is
  1 - 65535.

- `ad_actor_system`

  In `802.3ad` bonding mode, this specifies the system mac-address for the actor in
  protocol packet exchanges (LACPDUs).

- `ad_select`

  This option specifies the 802.3ad aggregation selection logic to use.  The possible
  values are: `stable`, `bandwidth`, `count`.

- `ad_user_port_key`

  In `802.3ad` bonding mode, this defines the upper 10 bits of the port key. The
  allowed range for the value is 0 - 1023.

- `all_ports_active`

  `all_slaves_active` <!--- wokeignore:rule=slave ---> in kernel and NetworkManager.
  The boolean value `false` drops the duplicate frames (received on inactive ports)
  and the boolean value `true` delivers the duplicate frames.

- `arp_all_targets`

  This option specifies the quantity of arp_ip_targets that must be reachable in
  order for the ARP monitor to consider a port as being up. The possible values are
  `any` or `all`.

- `arp_interval`

  This option specifies the ARP link monitoring frequency in milliseconds. A value of
  0 disables ARP monitoring.

- `arp_validate`

  In any mode that supports arp monitoring, this option specifies whether or not ARP
  probes and replies should be validated. Or for link monitoring purposes, whether
  non-ARP traffic should be filtered (disregarded). The possible values are: `none`,
  `active`, `backup`, `all`, `filter`, `filter_active`, `filter_backup`.

- `arp_ip_target`

  When `arp_interval` is enabled, this option specifies the IP addresses to use as
  ARP monitoring peers.

- `downdelay`

  The time to wait (in milliseconds) before disabling a port after a link failure
  has been detected.

- `fail_over_mac`

  This option specifies the policy to select the MAC address for the bond interface
  in active-backup mode. The possible values are: `none` (default), `active`,
  `follow`.

- `lacp_rate`

  In `802.3ad` bonding mode, this option defines the rate in which we requst link
  partner to transmit LACPDU packets. The possible values are: `slow`, `fast`.

- `lp_interval`

  This option specifies the number of seconds between instances where the bonding
  driver sends learning packets to each ports peer switch.

- `miimon`

  Sets the MII link monitoring interval (in milliseconds).

- `min_links`

  This option specifies the minimum number of links that must be active before
  asserting the carrier.

- `num_grat_arp`

  This option specify the number of peer notifications (gratuitious ARPs) to be
  issued after a failover event. The allowed range for the value is 0 - 255.

- `packets_per_port`

  In `balance-rr` bonding mode, this option specifies the number of packets allowed
  for a port in network transmission before moving to the next one. The allowed
  range for the value is 0 - 65535.

- `peer_notif_delay`

  This option specifies the delay (in milliseconds) between each peer notification
  when they are issued after a failover event.

- `primary`

  This option defines the primary device.

- `primary_reselect`

  This option specifies the reselection policy for the primary port. The possible
  values are: `always`, `better`, `failure`.

- `resend_igmp`

  This option specifies the number of IGMP membership reports to be issued after a
  failover event. The allowed range for the value is 0 - 255.

- `tlb_dynamic_lb`

  This option specifies if dynamic shuffling of flows is enabled in tlb mode. The
  boolean value `true` enables the flow shuffling while the boolean value `false`
  disables it.

- `updelay`

  This option specifies the time (in milliseconds) to wait before enabling a port
  after a link recovery has been detected.

- `use_carrier`

  This options specifies whether or not miimon should use MII or ETHTOOL ioctls
  versus netif_carrier_ok() to determine the link sattus. The boolean value `true`
  enables the use of netif_carrier_ok() while the boolean value `false` uses MII or
  ETHTOOL ioctls instead.

- `xmit_hash_policy`

  This option specifies the transmit hash policy to use for port selection, the
  possible values are: `layer2`, `layer3+4`, `layer2+3`, `encap2+3`, `encap3+4`,
  `vlan+srcmac`.

## Examples of Options

Setting the same connection profile multiple times:

```yaml
network_connections:
  - name: Wired0
    type: ethernet
    interface_name: eth0
    ip:
      dhcp4: true

  - name: Wired0
    state: up
```

Activating a preexisting connection profile:

```yaml
network_connections:
  - name: eth0
    state: up
```

Deactivating a preexisting connection profile:

```yaml
network_connections:
  - name: eth0
    state: down
```

Creating a persistent connection profile:

```yaml
network_connections:
  - name: eth0
    #persistent_state: present  # default
    type: ethernet
    autoconnect: true
    mac: "00:00:5e:00:53:5d"
    ip:
      dhcp4: true
```

Specifying a connecting profile for an ethernet device with the `ID_PATH`:

```yaml
network_connections:
  - name: eth0
    type: ethernet
    # For PCI devices, the path has the form "pci-$domain:$bus:$device.$function"
    # The profile will only match the interface at the PCI address pci-0000:00:03.0
    match:
      path:
        - pci-0000:00:03.0
    ip:
      address:
        - 192.0.2.3/24
```

```yaml
  - name: eth0
    type: ethernet
    # Specifying a connecting profile for an ethernet device only with the PCI address
    # pci-0000:00:01.0 or pci-0000:00:03.0
    match:
      path:
        - pci-0000:00:0[1-3].0
        - &!pci-0000:00:02.0
    ip:
      address:
        - 192.0.2.3/24
```

Deleting a connection profile named `eth0` (if it exists):

```yaml
network_connections:
  - name: eth0
    persistent_state: absent
```

Configuring the Ethernet link settings:

```yaml
network_connections:
  - name: eth0
    type: ethernet

    ethernet:
      autoneg: false
      speed: 1000
      duplex: full
```

Creating a bridge connection:

```yaml
network_connections:
  - name: br0
    type: bridge
    #interface_name: br0  # defaults to the connection name
```

Configuring a bridge connection:

```yaml
network_connections:
  - name: internal-br0
    interface_name: br0
    type: bridge
    ip:
      dhcp4: false
      auto6: false
```

Setting `controller` and `port_type`:

```yaml
network_connections:
  - name: br0-bond0
    type: bond
    interface_name: bond0
    controller: internal-br0
    port_type: bridge

  - name: br0-bond0-eth1
    type: ethernet
    interface_name: eth1
    controller: br0-bond0
    port_type: bond
```

Configuring VLANs:

```yaml
network_connections:
  - name: eth1-profile
    autoconnect: false
    type: ethernet
    interface_name: eth1
    ip:
      dhcp4: false
      auto6: false

  - name: eth1.6
    autoconnect: false
    type: vlan
    parent: eth1-profile
    vlan:
      id: 6
    ip:
      address:
        - 192.0.2.5/24
      auto6: false
```

Configuring MACVLAN:

```yaml
network_connections:
  - name: eth0-profile
    type: ethernet
    interface_name: eth0
    ip:
      address:
        - 192.168.0.1/24

  - name: veth0
    type: macvlan
    parent: eth0-profile
    macvlan:
      mode: bridge
      promiscuous: true
      tap: false
    ip:
      address:
        - 192.168.1.1/24
```

Configuring a wireless connection:

```yaml
network_connections:
  - name: wlan0
    type: wireless
    wireless:
      ssid: "My WPA2-PSK Network"
      key_mgmt: "wpa-psk"
      # recommend vault encrypting the wireless password
      # see https://docs.ansible.com/ansible/latest/user_guide/vault.html
      password: "p@55w0rD"
```

Setting the IP configuration:

```yaml
network_connections:
  - name: eth0
    type: ethernet
    ip:
      route_metric4: 100
      dhcp4: false
      #dhcp4_send_hostname: false
      gateway4: 192.0.2.1

      dns:
        - 192.0.2.2
        - 198.51.100.5
      dns_search:
        - example.com
        - subdomain.example.com
      dns_options:
        - rotate
        - timeout:1

      route_metric6: -1
      auto6: false
      gateway6: 2001:db8::1

      address:
        - 192.0.2.3/24
        - 198.51.100.3/26
        - 2001:db8::80/7

      route:
        - network: 198.51.100.128
          prefix: 26
          gateway: 198.51.100.1
          metric: 2
        - network: 198.51.100.64
          prefix: 26
          gateway: 198.51.100.6
          metric: 4
      route_append_only: false
      rule_append_only: true
```

Configuring 802.1x:

```yaml
network_connections:
  - name: eth0
    type: ethernet
    ieee802_1x:
      identity: myhost
      eap: tls
      private_key: /etc/pki/tls/client.key
      # recommend vault encrypting the private key password
      # see https://docs.ansible.com/ansible/latest/user_guide/vault.html
      private_key_password: "p@55w0rD"
      client_cert: /etc/pki/tls/client.pem
      ca_cert: /etc/pki/tls/cacert.pem
      domain_suffix_match: example.com
```

Configuring Enhanced Open(OWE):

```yaml
network_connections:
  - name: wlan0
    type: wireless
    wireless:
      ssid: "WIFI_SSID"
      key_mgmt: "owe"
```

## Examples of Applying the Network State Configuration

Configuring the IP addresses:

```yaml
network_state:
  interfaces:
    - name: ethtest0
      type: ethernet
      state: up
      ipv4:
        enabled: true
        address:
          - ip: 192.168.122.250
            prefix-length: 24
        dhcp: false
      ipv6:
        enabled: true
        address:
          - ip: 2001:db8::1:1
            prefix-length: 64
        autoconf: false
        dhcp: false
    - name: ethtest1
      type: ethernet
      state: up
      ipv4:
        enabled: true
        address:
          - ip: 192.168.100.192
            prefix-length: 24
        auto-dns: false
        dhcp: false
      ipv6:
        enabled: true
        address:
          - ip: 2001:db8::2:1
            prefix-length: 64
        autoconf: false
        dhcp: false
```

Configuring the route:

```yaml
network_state:
  interfaces:
    - name: eth1
      type: ethernet
      state: up
      ipv4:
        enabled: true
        address:
          - ip: 192.0.2.251
            prefix-length: 24
        dhcp: false

  routes:
    config:
      - destination: 198.51.100.0/24
        metric: 150
        next-hop-address: 192.0.2.251
        next-hop-interface: eth1
        table-id: 254
```

Configuring the DNS search and server:

```yaml
network_state:
  dns-resolver:
    config:
      search:
        - example.com
        - example.org
      server:
        - 2001:4860:4860::8888
        - 8.8.8.8
```

### Invalid and Wrong Configuration

The `network` role rejects invalid configurations. It is recommended to test the role
with `--check` first. There is no protection against wrong (but valid) configuration.
Double-check your configuration before applying it.

## Compatibility

The `network` role supports the same configuration scheme for both providers (`nm`
and `initscripts`). That means, you can use the same playbook with NetworkManager
and initscripts. However, note that not every option is handled exactly the same
by every provider. Do a test run first with `--check`.

It is not supported to create a configuration for one provider, and expect another
provider to handle them. For example, creating profiles with the `initscripts` provider,
and later enabling NetworkManager is not guaranteed to work automatically. Possibly,
you have to adjust the configuration so that it can be used by another provider.

For example, configuring a RHEL6 host with initscripts and upgrading to
RHEL7 while continuing to use initscripts in RHEL7 is an acceptable scenario. What
is not guaranteed is to upgrade to RHEL7, disable initscripts and expect NetworkManager
to take over the configuration automatically.

Depending on NetworkManager's configuration, connections may be stored as ifcfg files
as well, but it is not guaranteed that plain initscripts can handle these ifcfg files
after disabling the NetworkManager service.

The `network` role also supports configuring in certain Ansible distributions that the
role treats like RHEL, such as AlmaLinux, CentOS, OracleLinux, Rocky.

## Limitations

As Ansible usually works via the network, for example via SSH, there are some
limitations to be considered:

The `network` role does not support bootstraping networking configuration. One option
may be
[ansible-pull](https://docs.ansible.com/ansible/latest/cli/ansible-pull.html).
Another option maybe be to initially auto-configure the host during installation (ISO
based, kickstart, etc.), so that the host is connected to a management LAN or VLAN. It
strongly depends on your environment.

For `initscripts` provider, deploying a profile merely means to create the ifcfg
files. Nothing happens automatically until the play issues `ifup` or `ifdown`
via the `up` or `down` [states](#state) -- unless there are other
components that rely on the ifcfg files and react on changes.

The `initscripts` provider requires the different profiles to be in the right
order when they depend on each other. For example the bonding controller device
needs to be specified before the port devices.

When removing a profile for NetworkManager it also takes the connection
down and possibly removes virtual interfaces. With the `initscripts` provider
removing a profile does not change its current runtime state (this is a future
feature for NetworkManager as well).

For NetworkManager, modifying a connection with autoconnect enabled may result in the
activation of a new profile on a previously disconnected interface. Also, deleting a
NetworkManager connection that is currently active results in removing the interface.
Therefore, the order of the steps should be followed, and carefully handling of
[autoconnect](#autoconnect) property may be necessary. This should be improved in
NetworkManager RFE [rh#1401515](https://bugzilla.redhat.com/show_bug.cgi?id=1401515).

It seems difficult to change networking of the target host in a way that breaks
the current SSH connection of ansible. If you want to do that, ansible-pull might
be a solution. Alternatively, a combination of `async`/`poll` with changing
the `ansible_host` midway of the play.

**TODO** The current role does not yet support to easily split the
play in a pre-configure step, and a second step to activate the new configuration.

In general, to successfully run the play, determine which configuration is
active in the first place, and then carefully configure a sequence of steps to change to
the new configuration. The actual solution depends strongly on your environment.

### Handling potential problems

When something goes wrong while configuring networking remotely, you might need
to get physical access to the machine to recover.

**TODO** NetworkManager supports a
[checkpoint/rollback](https://developer.gnome.org/NetworkManager/stable/gdbus-org.freedesktop.NetworkManager.html#gdbus-method-org-freedesktop-NetworkManager.CheckpointCreate)
feature. At the beginning of the play we could create a checkpoint and if we lose
connectivity due to an error, NetworkManager would automatically rollback after
timeout. The limitations is that this would only work with NetworkManager, and
it is not clear that rollback will result in a working configuration.

*Want to contribute? Take a look at our [contributing
guidelines](https://github.com/linux-system-roles/network/blob/main/contributing.md)!*

## rpm-ostree

See README-ostree.md
