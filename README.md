linux-system-roles/network
==========================

This role enables users to configure network on target machines.
The role can be used to configure:

- Ethernet interfaces
- Bridge interfaces
- Bonded interfaces
- VLAN  interfaces
- IP configuration

General
-------

The role supports two providers: `nm` and `initscripts`. The provider can be configured per host
via the [`provider`](#provider) variable. In absence of explicit configuration, it is autodetected based on
the distribution. The `nm` provider is used by default on RHEL7 and
`initscripts` on RHEL6. However, note that the provider is not tied to a certain distribution,
given that the required API is available. For `nm` this means that at least version 1.2 of NetworkManager's
API is available. For `initscripts`, it requires the legacy network service as commonly available
on Fedora/RHEL.

For each host a list of networking profiles can be configure via the `network` variable.

- For initscripts, profiles correspond to ifcfg files in `/etc/sysconfig/network-scripts/ifcfg-*`.

- For NetworkManager, profiles correspond to connection profiles as handled by NetworkManager.  Fedora and RHEL use the `rh-plugin` for NetworkManager which also writes configuration files to `/etc/sysconfig/network-scripts/ifcfg-*` for compatibility.

Note that the role primarily operates on networking profiles (connections) and
not on devices. For example, in the role you would not configure the current IP address
of an interface. Instead, you create a profile with a certain IP configuration and
optionally activate the profile on a device. Which means, to apply the configuration
to the actual networking interface.



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

* For initscripts, the name determines the ifcfg file name `/etc/sysconfig/network-scripts/-ifcfg-$NAME`.
  Note that here too the name doesn't specify the `DEVICE` but a filename. As a consequence
  `'/'` is not a valid character for the name.

### `state`

#### Example

```yaml
network_connections:
  - name: "eth0"
    state: "absent"
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

We already saw that state `absent` before. There are more states:

  - `absent`
  - `present`
  - `up`
  - `down`

If the `state` variable is omitted, the default is `up` -- unless a `type` is specified,
in which case the default is `present`.

#### Example

```yaml
network_connections:
  - name: "eth0"
    #state: present        # default, as a type is present
    type: "ethernet"
    autoconnect: yes
    mac: "d6:06:b9:56:12:5d"
    ip:
      dhcp4: yes
```

Above example creates a new connection profile or ensures that it is present
with the given configuration. It has implicitly `state` `present`, due to the
presence of `type`. On the other hand, the `present` state requires at least a `type`
variable.

Valid values for `type` are:

  - `ethernet`
  - `bridge`
  - `bond`
  - `team`
  - `vlan`

`state` `present` does not directly result in a change in the network configuration.
That is, the profile is only created or modified, not activated.

- For NetworkManager, note the new connection profile is created with
  `autoconnect` turned on by default. Thus, NetworkManager may very well decide
  right away to activate the new profile on a currently disconnected device.
  ([rh#1401515](https://bugzilla.redhat.com/show_bug.cgi?id=1401515)).

### `autoconnect`

By default, profiles are created with autoconnect enabled.

- For NetworkManager, this translates to the `connection.autoconnect` property.

- For initscripts, this corresponds to the `ONBOOT` property.

### `mac`

The `mac` address is optional and restricts the profile to be usable only
on devices with the given MAC address. `mac` only makes sense for `type` `ethernet`
to match a non-virtual device with the profile.

- For NetworkManager `mac` is the permanent MAC address `ethernet.mac-address`.

- For initscripts, this means the currently configurd MAC address of the device (`HWADDR`).

### `interface_name`

For type `ethernet`, this option restricts the profile to the
given interface by name. This argument is optional and by default
a profile is not restricted to any interface by name.
Note that with [persistent interface naming](https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/Networking_Guide/ch-Consistent_Network_Device_Naming.html),
the interface is predictable based on the hardware configuration.
Otherwise, the `mac` address might be an option.

For virtual interface types like bridges, this argument is the name of the created
interface. In case of a missing `interface_name`, the profile name `name` is used.

Note the destinction between the profile name `name` and the device
name `interface_name`, which may or may not be the same.

### `state: up`

#### Example

```yaml
network_connections:
  - name: "eth0"
    #state: up        # implicit default, as there is no type specified
    wait: 0
```

The above example defaults to `state=up` and requires an existing profile to activate.
Note that if neither `type` nor `state` is specifed, `up` is implied. Thus in above
example the `state` is redundant.

- For NetworkManager this results in `nmcli connection id {{name}} up`.

- For initscripts it is the same as `ifup {{name}}`.

`up` also supports an optional integer argument `wait`. `wait=0` will only initiate
the activation but not wait until the device is fully connected. Connection will complete
in the background, for example after a DHCP lease was received.
`wait: <SECONDS>` is a timeout for how long we give the device
to activate. The default is `wait=-1` which uses a suitable timeout. Note that this
argument only makes sense for NetworkManager.
**TODO** `wait` different from zero is not yet implemented.

Note that `up` always re-activates the profile and possibly changes the networking
configuration, even if the profile was already active before. As such, it always
changes the system.

### `state: down`

#### Example

```yaml
network_connections:
  - name: eth0
    state: down
    wait: 0
```

Another `state` is `down`.

- For NetworkManager it is like calling `nmcli connection id {{name}} down`.

- For initscripts this means to call `ifdown {{name}}`.

This is the opposite of the `up` state. It also will always issue the command
to deactivate the profile, even it if seemingly is currently not active. As such,
`down` always changes the system.

For NetworkManager, a `wait` argument is supported like for `up` state.

### Refer to the same connection multiple times

#### Example

```yaml
network_connections:
  - name: "Wired0"
    type: "ethernet"
    interface_name: "eth0"
    ip:
      dhcp4: yes

  - name: "Wired0"
```

As said, the `name` identifies a unique profile. However, you can refer to the same
profile multiple times. Thus above example makes perfectly sense to create a profile and
activate it within the same play.

### `ip`

The IP configuration supports the following options:

```yaml
network_connections:
  - name: "eth0"
    type: "ethernet"
    ip:
      route_metric4: 100
      dhcp4: no
      #dhcp4_send_hostname: no
      gateway4: 192.168.5.1

      route_metric6: -1
      auto6: no
      gateway6: fc00::1

      address:
        - 192.168.5.3/24
        - 10.0.10.3/16
        - fc00::80/7
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

- For NetworkManager, `route_metric4` and `route_metric6` corresponds to the
[`ipv4.route-metric`](https://developer.gnome.org/NetworkManager/stable/nm-settings.html#nm-settings.property.ipv4.route-metric) and
[`ipv6.route-metric`](https://developer.gnome.org/NetworkManager/stable/nm-settings.html#nm-settings.property.ipv6.route-metric)
 properties, respectively. If specified, it determines the route metric
for DHCP assigned routes and the default route, and thus the priority for multiple interfaces.

Slaves to bridge/bond/team devices cannot specify `ip` settings.

### Virtual types and Slaves

Device types like `bridge`, `bond`, `team` work similar:

```yaml
network_connections:
  - name: "br0"
    type: bridge
    #interface_name: br0    # defaults to the connection name
```

Note that `team` is not supported on RHEL6 kernels.

For slaves of these virtual types, the special properites `slave_type` and
`master` must be set. Also note that slaves cannot have `ip` settings.

```yaml
network_connections:
  - name: br0
    type: bridge
    ip:
      dhcp4: no
      auto6: no

  - name: br0-bond0
    type: bond
    interface_name: bond0
    master: br0
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
    vlan_id: 6
    ip:
      address:
        - 192.168.10.5/24
      auto6: no
```

Like for `master`, the `parent` references the connection profile in the ansible
role.

### `network_provider`

Whether to use `nm` or `initscripts` is detected based on the distribution.
It can be however be explicitly set via `network_.provider` variable.

#### Example

```yaml
network_provider: nm
network_connections:
  - name: "eth0"
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
