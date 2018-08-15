linux-system-roles/network
==========================
[![Coverage Status](https://coveralls.io/repos/github/linux-system-roles/network/badge.svg)](https://coveralls.io/github/linux-system-roles/network)
[![Travis Build Status](https://travis-ci.org/linux-system-roles/network.svg?branch=master)](https://travis-ci.org/linux-system-roles/network)
[![Code Style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/ambv/black)

This role enables users to configure network on target machines.
The role can be used to configure:

- Ethernet interfaces
- Bridge interfaces
- Bonded interfaces
- VLAN  interfaces
- MacVLAN interfaces
- Infiniband interfaces
- IP configuration

General
-------

The role supports two providers: `nm` and `initscripts`. The provider can be
configured per host via the [`network_provider`](#provider) variable. In
absence of explicit configuration, it is autodetected based on the
distribution. The `nm` provider is used by default on RHEL7 and `initscripts`
on RHEL6. However, note that the provider is not tied to a certain
distribution, given that the required API is available. For `nm` this means
that at least version 1.2 of NetworkManager's API is available. For
`initscripts`, it requires the legacy network service as commonly available on
Fedora/RHEL.

For each host a list of networking profiles can be configured via the
`network_connections` variable.

- For initscripts, profiles correspond to ifcfg files in `/etc/sysconfig/network-scripts/ifcfg-*`.

- For NetworkManager, profiles correspond to connection profiles as handled by NetworkManager.  Fedora and RHEL use the `rh-plugin` for NetworkManager which also writes configuration files to `/etc/sysconfig/network-scripts/ifcfg-*` for compatibility.

Note that the role primarily operates on networking profiles (connections) and
not on devices but it defaults to use the profile name as the interface name.
But it is also possible to create generic profiles, by creating for example a
profile with a certain IP configuration without activating the profile. To
apply the configuration to the actual networking interface, a command like
`nmcli` needs to be used on the target system.

### Warning

The role updates or creates all connection profiles on the target system as
specified in the `network_connections` variable. Therefore, the role will
remove settings from the specified profiles if the settings are only present on
the system but not in the `network_connections` variable. The following
exceptions apply:

* For profiles that only contain a `state` setting, the role will only activate
  or deactivate the connection without changing its configuration.

* The `route_append_only` setting allows to only add new routes to the
  existing routes on the system.

* The `rule_append_only` setting allows to preserve the current routing rules.
  There is no support to specify routing rules at the moment.

See also [Limitations](#limitations).

Variables
---------

The role is configured via variables with a `network_` name prefix.
The connection profiles are configured as `network_connections`, which
is a list of dictionaries that have a `name`.

### `name`

The `name` identifies the connection profile. It is not the name of the
networking interface for which the profile applies, though it makes
sense to restrict the profile to an interface and give them the same name.
Note also that you can have multiple profiles for the same device, but of
course only one profile can be active on the device at each time. Note that
for NetworkManager, a connection can only be active at one device at a time.

* For NetworkManager, the `name` translates to [`connection.id`](https://developer.gnome.org/NetworkManager/stable/nm-settings.html#nm-settings.property.connection.id).
  Altough NetworkManager supports multiple connections with the same `connection.id`,
  this role cannot handle a duplicate `name`. Specifying a `name` multiple
  times refers to the same connection profile.

* For initscripts, the name determines the ifcfg file name `/etc/sysconfig/network-scripts/ifcfg-$NAME`.
  Note that here too the name doesn't specify the `DEVICE` but a filename. As a consequence
  `'/'` is not a valid character for the name.

### `state` and `persistent_state`

Each connection profile can have a runtime state, represented by the `state`
setting and a persistent state, represtented by the `persistent_state` setting.

The optional `state` setting supports the following values:

- `up`
- `down`

It defines whether the profile is activated (`up`) or deactivated (`down`). If
it is unset, the profile's runtime state will not be changed.

The `persistent_state` setting is either `present` (default) or `absent`. If
the `persistent_state` setting is `present` and the connection profile contains
a `type` setting, the profile will be created or updated. If the profile is
incomplete (lacks the `type` setting) and `persistent_state` is `present`,
the behavior is undefined. The value `absent` makes the role ensure
that the profile is not present on the target host.


#### Example

```yaml
network_connections:
  - name: eth0
    persistent_state: absent
```

Above example ensures the absence of a connection profile. If a profile with `name` `eth0`
exists, it will be deleted.

* For NetworkManager this deletes all connection profiles with the matching `connection.id`.
  Deleting a profile usually does not change the current networking configuration, unless
  the profile was currently activated on a device. In that case deleting the currently
  active connection profile disconnects the device. That makes the device eligible
  to autoconnect another connection (see also [rh#1401515](https://bugzilla.redhat.com/show_bug.cgi?id=1401515)).

* For initscripts it results in the deletion of the ifcfg file. Usually that
  has no side-effect, unless some component is watching the sysconfig directory.

#### Example

```yaml
network_connections:
  - name: eth0
    #persistent_state: present  # default
    type: ethernet
    autoconnect: yes
    mac: 00:00:5e:00:53:5d
    ip:
      dhcp4: yes
```

Above example creates a new connection profile or ensures that it is present
with the given configuration. It implies the `persistent_state` setting to be
`present`.

Valid values for `type` are:

  - `bond`
  - `bridge`
  - `ethernet`
  - `infiniband`
  - `macvlan`
  - `team`
  - `vlan`

The value `present` for the `persistent_state` setting does not directly
result in a change in the network configuration. That is, without `state`
set to `up`, the profile is only created or modified, not activated.

- For NetworkManager, note the new connection profile is created with
  `autoconnect` turned on by default. Thus, NetworkManager may very well decide
  right away to activate the new profile on a currently disconnected device.
  ([rh#1401515](https://bugzilla.redhat.com/show_bug.cgi?id=1401515)).

### `autoconnect`

By default, profiles are created with autoconnect enabled.

- For NetworkManager, this translates to the `connection.autoconnect` property.

- For initscripts, this corresponds to the `ONBOOT` property.

### `mac`

The `mac` address is optional and restricts the profile to be usable only on
devices with the given MAC address. `mac` is only allowed for `type`
`ethernet` or `type` `infiniband` to match a non-virtual device with the
profile.

- For NetworkManager `mac` is the permanent MAC address `ethernet.mac-address`.

- For initscripts, this means the currently configured MAC address of the device (`HWADDR`).

### `interface_name`

For the types `ethernet` and `infiniband`, this option restricts the profile to
the given interface by name. This argument is optional and by default the
profile name is used unless a mac address is specified using the `mac` key.
Specifying an empty string (`""`) allows to specify that the profile is not
restricted to a network interface.


**Note:** With [persistent interface naming](https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/Networking_Guide/ch-Consistent_Network_Device_Naming.html),
the interface is predictable based on the hardware configuration.
Otherwise, the `mac` address might be an option.

For virtual interface types like bridges, this argument is the name of the created
interface. In case of a missing `interface_name`, the profile name `name` is used.

**Note:** The profile name `name` and the device name `interface_name` may be
different or the profile may not be tied to an interface at all.

### `zone`

Sets the firewalld zone for the interface.

Slaves to bridge/bond/team devices cannot specify a zone.

### `state: up`

#### Example

```yaml
network_connections:
  - name: eth0
    state: up
```

The above example requires an existing profile to activate.

- For NetworkManager this results in `nmcli connection id {{name}} up`.

- For initscripts it is the same as `ifup {{name}}`.

State `up` also supports an optional integer setting `wait`. `wait: 0` will
only initiate the activation but not wait until the device is fully connected.
Connection will complete in the background, for example after a DHCP lease was
received. `wait: <SECONDS>` is a timeout for how long we give the device to
activate. The default is using a suitable timeout. Note that this setting is
only supported by NetworkManager.
**TODO** `wait` different from zero is not yet implemented.

Note that state `up` always re-activates the profile and possibly changes the
networking configuration, even if the profile was already active before. As
such, it always changes the system.

### `state: down`

#### Example

```yaml
network_connections:
  - name: eth0
    state: down
```

Another `state` is `down`.

- For NetworkManager it is like calling `nmcli connection id {{name}} down`.

- For initscripts this means to call `ifdown {{name}}`.

This is the opposite of the `up` state. It also will always issue the command
to deactivate the profile, even it if seemingly is currently not active. As
such, `down` always changes the system.

For NetworkManager, a `wait` argument is supported like for `up` state.

### Refer to the same connection multiple times

#### Example

```yaml
network_connections:
  - name: Wired0
    type: ethernet
    interface_name: eth0
    ip:
      dhcp4: yes

  - name: Wired0
    state: up
```

As said, the `name` identifies a unique profile. However, you can refer to the
same profile multiple times. Therefore it is possible to create a profile and
activate it separately.

### `ip`

The IP configuration supports the following options:

```yaml
network_connections:
  - name: eth0
    type: ethernet
    ip:
      route_metric4: 100
      dhcp4: no
      #dhcp4_send_hostname: no
      gateway4: 192.0.2.1

      dns:
        - 192.0.2.2
        - 198.51.100.5
      dns_search:
        - example.com
        - subdomain.example.com

      route_metric6: -1
      auto6: no
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
      route_append_only: no
      rule_append_only: yes
```

Manual addressing can be specified via a list of addresses and prefixes `address`.
Also, manual addressing can be combined with either `dhcp4` and `auto6` for DHCPv4
and SLAAC. The `dhcp4` and `auto6` keys can be omitted and the default depends on the
presence of manual addresses.

If `dhcp4` is enabled, it can be configured whether
the DHCPv4 request includes the hostname via `dhcp4_send_hostname`.
Note that `dhcp4_send_hostname` is only supported by the `nm` provider and translates
to [`ipv4.dhcp-send-hostname`](https://developer.gnome.org/NetworkManager/stable/nm-settings.html#nm-settings.property.ipv4.dhcp-send-hostname)
property.

Manual DNS configuration can be specified via a list of addresses
given in the `dns` option and a list of domains to search given in the
`dns_search` option.

- For NetworkManager, `route_metric4` and `route_metric6` corresponds to the
[`ipv4.route-metric`](https://developer.gnome.org/NetworkManager/stable/nm-settings.html#nm-settings.property.ipv4.route-metric) and
[`ipv6.route-metric`](https://developer.gnome.org/NetworkManager/stable/nm-settings.html#nm-settings.property.ipv6.route-metric)
 properties, respectively. If specified, it determines the route metric
for DHCP assigned routes and the default route, and thus the priority for multiple interfaces.

Static route configuration can be specified via a list of routes given in the `route`
option. The default value is an empty list. Each route is a dictionary with the following
entries: `network`, `prefix`, `gateway` and `metric`. `network` and `prefix` together specify
the destination network. CIDR notation or network mask notation are not supported yet. If the
boolean option `route_append_only` is `yes`, the specified routes are appended to the
existing routes, if it is `no` (default), the current routes are replaced. Setting this
option to `yes` without setting `route` has the effect of preserving the current static routes. The
boolean option `rule_append_only` works in a similar way for routing rules. Note that there is
no further support for routing rules at the moment, so this option serves merely the purpose
of preserving the current routing rules.  Note also that when
`route_append_only`/`rule_append_only` is not specified, the current routes/routing rules will
be deleted by the role.

Slaves to bridge/bond/team devices cannot specify `ip` settings.

### `type: ethernet`

Ethernet-specific options can be set using the connection profile variable `ethernet`. This
variable should be specified as a dictionary with the following items (options): `autoneg`, `speed` and `duplex`,
which correspond to the settings of the `ethtool` utility with the same name. `speed` is an
integer giving the speed in Mb/s, the valid values of `duplex` are `half` and `full`, and
`autoneg` accepts a boolean value (default is `yes`) to configure autonegotiation. The `speed` and `duplex` settings are required when autonegotiation is disabled.

```yaml
network_connections:
  - name: eth0
    type: ethernet

    ethernet:
      autoneg: no
      speed: 1000
      duplex: full
```

### Virtual types and Slaves

Device types like `bridge`, `bond`, `team` work similar:

```yaml
network_connections:
  - name: br0
    type: bridge
    #interface_name: br0  # defaults to the connection name
```

Note that `team` is not supported on RHEL6 kernels.

For slaves of these virtual types, the special properites `slave_type` and
`master` must be set. Also note that slaves cannot have `ip` settings.

```yaml
network_connections:
  - name: internal-br0
    interface_name: br0
    type: bridge
    ip:
      dhcp4: no
      auto6: no

  - name: br0-bond0
    type: bond
    interface_name: bond0
    master: internal-br0
    slave_type: bridge

  - name: br0-bond0-eth1
    type: ethernet
    interface_name: eth1
    master: br0-bond0
    slave_type: bond
```

Note that the `master` refers to the `name` of a profile in the ansible
playbook. That is, it is neither an interface-name, nor a connection-id of
NetworkManager.

- For NetworkManager, `master` will be converted to the `connection.uuid`
  of the corresponding profile.

- For initscripts, the master is looked up as the `DEVICE` from the corresponding
  ifcfg file.

As `master` refers to other profiles of the same or another play,
the order of the `connections` list matters. Also, `--check` ignores
the value of the `master` and assumes it will be present during a real
run. That means, in presence of an invalid `master`, `--check` may
signal success but the actual play run fails.

### `type: vlan`

VLANs work too:

```yaml
network_connections:
  - name: eth1-profile
    autoconnet: no
    type: ethernet
    interface_name: eth1
    ip:
      dhcp4: no
      auto6: no

  - name: eth1.6
    autoconnect: no
    type: vlan
    parent: eth1-profile
    vlan:
      id: 6
    ip:
      address:
        - 192.0.2.5/24
      auto6: no
```

Like for `master`, the `parent` references the connection profile in the ansible
role.

### `type: macvlan`

MACVLANs also work:

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
      promiscuous: yes
      tap: no
    ip:
      address:
        - 192.168.1.1/24
```

Like for `master` and `vlan`, the `parent` references the connection profile in the ansible
role.

### `network_provider`

When Network Manager is running on the target system, the role will use the
`nm` provider and `initscripts` otherwise. The variable `network_provider`
allows to specify a specific provider. Setting it to
`network_provider_os_default` will choose the provider depening on the
operating system. This is usually `nm` except for RHEL 6 or CentOS 6 systems.

#### Example

```yaml
network_provider: nm
network_connections:
  - name: eth0
    #...
```

Limitations
-----------

### Configure over the Network

Ansible usually works via the network, for example via SSH. This role doesn't answer
how to bootstrap networking configuration. One option may be [ansible-pull](https://docs.ansible.com/ansible/playbooks_intro.html#ansible-pull).
Another to initially auto-configure the host during installation (ISO based, kickstart, etc.),
so that the host is connected to a management LAN or VLAN. It strongly depends on your environment.

- For initscripts provider, deploying a profile merely means to create the ifcfg
  files. Nothing happening automatically until the play issues `ifup` or `ifdown`
  via the `up` or `down` [states](#state) -- unless of course, there are other
  components that watch the ifcfg files and react on changes.

- The initscripts provider requires the different profiles to be in the right
  order when they depend on each other, for example the bonding master device
  needs to be specified before the slave devices.

- When removing a profile for NetworkManager it will also take the connection
  down and possibly remove virtual interfaces. With the initscripts provider
  removing a profile does not change its current runtime state (this is going
  to be the case for NetworkManager in the future, too.).

- For NetworkManager, modifying a connection with autoconnect enabled
  may result in the activation of the new profile on a previously disconnected
  interface. Also, deleting a NetworkManager connection that is currently active
  will tear down the interface. Therefore, the order of the steps may matter
  and or careful handling of [autoconnect](#autoconnect) property may be necessary.
  This should be improved in NetworkManager RFE [rh#1401515](https://bugzilla.redhat.com/show_bug.cgi?id=1401515).

- It seems difficult to change networking of the target host in a way that breaks the current
  SSH connection of ansible. If you want to do that, ansible-pull might be a solution.
  Alternatively, a combination of `async`/`poll` with changing the `ansible_host` midway
  of the play.
  **TODO** The current role doesn't yet support to easily split the
  play in a pre-configure step, and a second step to activate the new configuration.

In general, to successfully run the play, one must understand which configuration is
active in the first place and then carefully configure a sequence of steps to change to
the new configuration. Don't cut off the branch on which you are sitting. The actual
solution depends strongly on your environment.

### If something goes wrong

When something goes wrong while configuring the networking remotely, you might need
to get phyisical access to the machine to recover.

- **TODO** NetworkManager supports a [checkpoint/rollback](https://developer.gnome.org/NetworkManager/stable/gdbus-org.freedesktop.NetworkManager.html#gdbus-method-org-freedesktop-NetworkManager.CheckpointCreate)
  feature. At the beginning of the play we could create a checkpoint and if we lose connectivity
  due to an error, NetworkManager would automatically rollback after timeout.
  The limitations is that this would only work with NetworkManager, and it's not
  clear that rollback will result in a working configuration either.

#### Invalid and Wrong Configuration

The role will reject invalid configurations, so it is a good idea to test the role
with `--check` first. There is no protection against wrong (but valid) configuration.
Double-check your configuration before applying it.

### Compatibility

The role supports the same configuration scheme for both providers. That means, you can
use the same playbook with NetworkManager and initscripts. Note however, that not every
option is handled exactly the same by every provider. Do a test run first with `--check`.

It is also not supported to create a configuration for one provider, and expect another
provider to handle them. For example, creating proviles with `initscripts` provider
and later enabling NetworkManager is not guaranteed to work automatically. Possibly
you have to adjust the configuration so that it can be used by another provider.

For example what will work is to configure a RHEL6 host with initscripts and upgrade to
RHEL7 while continuing to use initscripts on RHEL7. What is not guaranteed to work
it to upgrade to RHEL7, disable initscripts and expect NetworkManager to take over
the configuration automatically.

Depending on NetworkManager's configuration, connections may be stored as ifcfg files
as well, but again it is not guaranteed that plain initscripts can handle these ifcfg files
after disabling the NetworkManager service.
