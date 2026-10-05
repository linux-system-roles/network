

# linux-system-roles.network role – Configure networking

This role is part of the [fedora.linux_system_roles collection](https://galaxy.ansible.com/ui/repo/published/fedora/linux_system_roles/).

It is not included in `ansible-core`. To check whether it is installed, run `ansible-galaxy collection list`.

To install it use: `ansible-galaxy collection install fedora.linux_system_roles`.

To use it in a playbook, specify: `linux-system-roles.network`.

- [Entry point `main` – Configure networking](#entry-point-main--configure-networking)

  - [Synopsis](#synopsis)

  - [Parameters](#parameters)

  - [Attributes](#attributes)

  - [Notes](#notes)

  - [Examples](#examples)

  - [Authors](#authors)

## Entry point `main` – Configure networking

### Synopsis

- The `network` role configures network interfaces and IP settings on the target machines. It can configure Ethernet, bridge, bonded, VLAN, MacVLAN, Infiniband, wireless (WiFi), and dummy interfaces, IP configuration, and 802.1x authentication.

- The role supports two providers, `nm` (NetworkManager) and `initscripts`. `nm` is used by default since RHEL 7 and `initscripts` on RHEL 6. The `initscripts` provider requires the `network-scripts` package, which is deprecated in RHEL 8 and dropped in RHEL 9. The provider is autodetected per host from the distribution unless set explicitly with the `network_provider` variable. Neither provider is tied to a distribution: `nm` works wherever NetworkManager API version 1.2 or later is available, and some settings require a newer API version.

- Two mechanisms are available to configure networking. The **`network_connections`** variable manages connection profiles (one list item per profile) and is supported by both providers. The **`network_state`** variable applies an Nmstate desired state directly to the devices and is only supported by the `nm` provider on RHEL 8 and later.

- Because its backend is Nmstate, **`network_state`** represents the future direction of the role, aiming to provide a more streamlined and reliable way to manage networking; most features available in NetworkManager are also available through it. For the Nmstate schema, syntax, and examples, see [nmstate.io](https://nmstate.io) and the [nmstate API documentation](https://docs.rs/nmstate/latest/nmstate/index.html).

- **Warning**: the `network` role updates or creates all connection profiles listed in **`network_connections`** on the target system, and it removes options that are present on the system but not in **`network_connections`**. Partial configuration can instead be achieved with **`network_state`**.

- Collection requirements: to manage `rpm-ostree` nodes, the role requires additional modules from external collections; install them with `ansible-galaxy collection install -vv -r meta/collection-requirements.yml`. To manage other systems, the role has no additional requirements.

- The role operates both on the connection profiles of devices (via **`network_connections`**) and on devices directly (via **`network_state`**). You can create generic profiles, for example a profile with a certain IP configuration, without activating them, then apply the configuration to the interface with `nmcli` on the target system.

- Compatibility: both providers share the same configuration scheme, so the same playbook can be used with NetworkManager and initscripts. Not every option is handled identically by both providers, so do a test run with `--check` first. Creating a configuration with one provider and expecting another provider to handle it is not supported. The role also supports distributions that it treats like RHEL, such as AlmaLinux, CentOS, OracleLinux, and Rocky.

- Invalid versus wrong configuration: the role rejects invalid configurations (test with `--check` first), but there is no protection against configuration that is valid but wrong. Double-check your configuration before applying it.

- Limitations: the role does not bootstrap networking (consider [ansible-pull](https://docs.ansible.com/ansible/latest/cli/ansible-pull.html) or auto-configuring the host during installation). For the `initscripts` provider, deploying a profile only writes the ifcfg files; nothing happens until an `up` or `down` state issues `ifup` or `ifdown`. The `initscripts` provider requires dependent profiles in the right order, for example a bonding controller before its ports. Removing a NetworkManager profile also takes the connection down and may remove virtual interfaces, while removing an `initscripts` profile does not change the current runtime state. For NetworkManager, modifying a connection with autoconnect enabled may activate a new profile, and deleting a connection that is currently active removes the interface, so order the steps and handle the `autoconnect` property carefully (see [rh#1401515](https://bugzilla.redhat.com/show_bug.cgi?id=1401515)).

- Routing rules and named routing tables are not supported with the `initscripts` provider: if `network_provider` is set to `initscripts`, `routing_rule` entries and named `table` references in `route` are silently ignored. Use the `nm` provider for routing rule support.

- Configuring `dns-resolver` through **`network_state`** is not supported when NetworkManager has a `[global-dns]` or `[global-dns-domain-*]` section in its configuration files (`/etc/NetworkManager/NetworkManager.conf` or a `conf.d` snippet). nmstate applies DNS through NetworkManager’s global DNS API, which NetworkManager rejects while global DNS is set in a configuration file; the role then fails with an error naming the file. Either remove the section and reload NetworkManager, or configure DNS on the connection profiles instead of `dns-resolver`.

- The `network_connections` module is intended for internal use and integration testing only, and is not intended for direct external use.

- For `rpm-ostree` systems, see the `README-ostree.md` file in the role.

### Parameters

| Parameter                                                   | Comments |
| ----------------------------------------------------------- | --- |
| **network_allow_restart** *boolean*                         | Whether the role is allowed to restart NetworkManager when a package installed for a wireless or team interface (such as `NetworkManager-wifi` or `NetworkManager-team`) requires it to be reloaded. A restart can disrupt connectivity, so the role refuses to restart NetworkManager unless this is set to `true`. **Choices:** `false` (default), `true` |
| **network_connections** *list / elements=dictionary*        | A list of connection profile specifications to create, modify, activate, or remove. Profiles referenced by `controller` or `parent` must appear earlier in the list than the profile referencing them. To remove every profile on the system that is not otherwise listed, add an item with no `name` and `persistent_state` set to `absent`. **Default:** `[]` |
| • **autoconnect** *boolean*                                 | Whether the profile is activated automatically. For `NetworkManager`, this corresponds to `connection.autoconnect`. For `initscripts`, this corresponds to `ONBOOT`. **Choices:** `false`, `true` (default) |
| • **autoconnect_retries** *integer*                         | The number of times to try autoactivating the connection before giving up. `0` means try forever, and `-1` uses the NetworkManager global default (normally 4 tries). `1` tries activation only once before blocking autoconnect until the next attempt to autoconnect. Only supported by the `nm` provider. **Default:** `-1` |
| • **bond** *dictionary*                                     | The bonding options of a `bond` profile. See the [kernel bonding documentation](https://www.kernel.org/doc/Documentation/networking/bonding.txt) or your distribution’s `nmcli` documentation for valid values. |
| • • **ad_actor_sys_prio** *integer*                         | The 802.3ad system priority. Only valid with mode `802.3ad`. |
| • • **ad_actor_system** *string*                            | The 802.3ad system MAC address used for the actor in LACPDU protocol packet exchanges. Only valid with mode `802.3ad`. |
| • • **ad_select** *string*                                  | The 802.3ad aggregation selection logic to use. Only valid with mode `802.3ad`. **Choices:** `"stable"`, `"bandwidth"`, `"count"` |
| • • **ad_user_port_key** *integer*                          | The upper 10 bits of the port key. Only valid with mode `802.3ad`. |
| • • **all_ports_active** *boolean*                          | Whether duplicate frames received on inactive ports are delivered (`true`) or dropped (`false`). **Choices:** `false`, `true` |
| • • **arp_all_targets** *string*                            | How many of `arp_ip_target` addresses must be reachable for the ARP monitor to consider a port up. Only valid with modes `balance-rr`, `active-backup`, `balance-xor`, or `broadcast`. **Choices:** `"any"`, `"all"` |
| • • **arp_interval** *integer*                              | The ARP link monitoring frequency in milliseconds. `0` disables ARP monitoring. Requires `arp_ip_target` to be set. Only valid with modes `balance-rr`, `active-backup`, `balance-xor`, or `broadcast`. |
| • • **arp_ip_target** *string*                              | The IP addresses to use as ARP monitoring peers when `arp_interval` is enabled. Requires `arp_interval` to be set. |
| • • **arp_validate** *string*                               | Whether ARP probes and replies should be validated in any mode that supports ARP monitoring, or whether non-ARP traffic should be filtered for link monitoring purposes. Only valid with modes `balance-rr`, `active-backup`, `balance-xor`, or `broadcast`. **Choices:** `"none"`, `"active"`, `"backup"`, `"all"`, `"filter"`, `"filter_active"`, `"filter_backup"` |
| • • **downdelay** *integer*                                 | The time to wait, in milliseconds, before disabling a port after a link failure is detected. Requires `miimon` to be enabled. |
| • • **fail_over_mac** *string*                              | The policy for selecting the MAC address of the bond interface in `active-backup` mode. **Choices:** `"none"`, `"active"`, `"follow"` |
| • • **lacp_rate** *string*                                  | The rate at which link partners are asked to transmit LACPDU packets. Only valid with mode `802.3ad`. **Choices:** `"slow"`, `"fast"` |
| • • **lp_interval** *integer*                               | The number of seconds between instances where the bonding driver sends learning packets to each port’s peer switch. |
| • • **miimon** *integer*                                    | The MII link monitoring interval in milliseconds. |
| • • **min_links** *integer*                                 | The minimum number of active links required before the carrier is asserted. |
| • • **mode** *string*                                       | The bonding mode. **Choices:** `"balance-rr"` (default), `"active-backup"`, `"balance-xor"`, `"broadcast"`, `"802.3ad"`, `"balance-tlb"`, `"balance-alb"` |
| • • **num_grat_arp** *integer*                              | The number of gratuitous ARP peer notifications to issue after a failover event. |
| • • **packets_per_port** *integer*                          | The number of packets to transmit through a port before moving to the next one. Only valid with mode `balance-rr`. |
| • • **peer_notif_delay** *integer*                          | The delay, in milliseconds, between each peer notification issued after a failover event. Requires `miimon` to be enabled and must be a multiple of `miimon`. Not allowed together with `arp_interval`. |
| • • **primary** *string*                                    | The name of the primary port device. Only valid with modes `active-backup`, `balance-tlb`, or `balance-alb`. |
| • • **primary_reselect** *string*                           | The reselection policy for the primary port. **Choices:** `"always"`, `"better"`, `"failure"` |
| • • **resend_igmp** *integer*                               | The number of IGMP membership reports to issue after a failover event. |
| • • **tlb_dynamic_lb** *boolean*                            | Whether dynamic shuffling of flows is enabled. Only valid with modes `balance-tlb` or `balance-alb`. **Choices:** `false`, `true` |
| • • **updelay** *integer*                                   | The time to wait, in milliseconds, before enabling a port after a link recovery is detected. Requires `miimon` to be enabled. |
| • • **use_carrier** *boolean*                               | Whether the `netif_carrier_ok` function (`true`) or MII/ETHTOOL ioctls (`false`) are used to determine link status for `miimon`. **Choices:** `false`, `true` |
| • • **xmit_hash_policy** *string*                           | The transmit hash policy used for port selection. **Choices:** `"layer2"`, `"layer3+4"`, `"layer2+3"`, `"encap2+3"`, `"encap3+4"`, `"vlan+srcmac"` |
| • **check_iface_exists** *boolean*                          | Whether to check that the target interface exists before activating the connection. Only supported by the `nm` provider. **Choices:** `false`, `true` (default) |
| • **cloned_mac** *string*                                   | The MAC address strategy to apply on activation. Accepts a hardware address in the same notation as `mac`, or one of the special values `default` (honor the NetworkManager default), `permanent` (use the device’s permanent address), `preserve` (do not change the current address), `random` (generate a new address on every connect), or `stable` (generate a stable, hashed address). **Default:** `"default"` |
| • **controller** *string*                                   | The `name` of another profile in **`network_connections`** that this profile is a port of, used for `bridge`, `bond`, and `team` controller devices. This refers to a profile name in the play, not an interface name or NetworkManager connection ID. Ports must not specify `ip` or `zone` settings. |
| • **ethernet** *dictionary*                                 | Ethernet link settings, corresponding to the `ethtool` utility’s link settings. Only allowed for `ethernet`, `vlan`, `bridge`, `bond`, and `team` types. |
| • • **autoneg** *boolean*                                   | Whether auto-negotiation is enabled. When `speed` or `duplex` are set, `autoneg` must not be enabled, and when it is disabled, both `speed` and `duplex` must be set. **Choices:** `false`, `true` |
| • • **duplex** *string*                                     | The link duplex mode. Required together with `speed` when `autoneg` is disabled. **Choices:** `"half"`, `"full"` |
| • • **speed** *integer*                                     | The link speed in Mbit/s. Required together with `duplex` when `autoneg` is disabled. **Default:** `0` |
| • **ethtool** *dictionary*                                  | Settings to enable or disable `ethtool` features on the device. Depending on the kernel and device, some settings might not be supported. |
| • • **coalesce** *dictionary*                               | A dictionary of `ethtool` interrupt coalescing settings. The `*_low` and `*_high` variants are only used when adaptive coalescing is enabled, applying while the measured packet rate is below `pkt_rate_low` or above `pkt_rate_high` respectively. |
| • • • **adaptive_rx** *boolean*                             | Whether adaptive Rx interrupt coalescing is enabled, letting the driver tune the Rx coalescing parameters dynamically based on the packet rate. **Choices:** `false`, `true` |
| • • • **adaptive_tx** *boolean*                             | Whether adaptive Tx interrupt coalescing is enabled, letting the driver tune the Tx coalescing parameters dynamically based on the packet rate. **Choices:** `false`, `true` |
| • • • **pkt_rate_high** *integer*                           | The packet rate, in packets per second, above which the `*_high` coalescing parameters are used. |
| • • • **pkt_rate_low** *integer*                            | The packet rate, in packets per second, below which the `*_low` coalescing parameters are used. |
| • • • **rx_frames** *integer*                               | The maximum number of received packets to wait for before raising an Rx interrupt. |
| • • • **rx_frames_high** *integer*                          | The number of received packets to wait for before raising an Rx interrupt while the packet rate is above `pkt_rate_high`. |
| • • • **rx_frames_irq** *integer*                           | The maximum number of received packets to wait for before raising an Rx interrupt while the host is already servicing an interrupt. |
| • • • **rx_frames_low** *integer*                           | The number of received packets to wait for before raising an Rx interrupt while the packet rate is below `pkt_rate_low`. |
| • • • **rx_usecs** *integer*                                | The number of microseconds to wait after a packet is received before raising an Rx interrupt. |
| • • • **rx_usecs_high** *integer*                           | The number of microseconds to wait before raising an Rx interrupt while the packet rate is above `pkt_rate_high`. |
| • • • **rx_usecs_irq** *integer*                            | The number of microseconds to wait before raising an Rx interrupt while the host is already servicing an interrupt. |
| • • • **rx_usecs_low** *integer*                            | The number of microseconds to wait before raising an Rx interrupt while the packet rate is below `pkt_rate_low`. |
| • • • **sample_interval** *integer*                         | How often, in seconds, the adaptive coalescing logic samples the packet rate. |
| • • • **stats_block_usecs** *integer*                       | The number of microseconds to wait between updates of the device’s in-memory statistics. |
| • • • **tx_frames** *integer*                               | The maximum number of packets to transmit before raising a Tx interrupt. |
| • • • **tx_frames_high** *integer*                          | The number of packets to transmit before raising a Tx interrupt while the packet rate is above `pkt_rate_high`. |
| • • • **tx_frames_irq** *integer*                           | The maximum number of packets to transmit before raising a Tx interrupt while the host is already servicing an interrupt. |
| • • • **tx_frames_low** *integer*                           | The number of packets to transmit before raising a Tx interrupt while the packet rate is below `pkt_rate_low`. |
| • • • **tx_usecs** *integer*                                | The number of microseconds to wait after a packet is transmitted before raising a Tx interrupt. |
| • • • **tx_usecs_high** *integer*                           | The number of microseconds to wait before raising a Tx interrupt while the packet rate is above `pkt_rate_high`. |
| • • • **tx_usecs_irq** *integer*                            | The number of microseconds to wait before raising a Tx interrupt while the host is already servicing an interrupt. |
| • • • **tx_usecs_low** *integer*                            | The number of microseconds to wait before raising a Tx interrupt while the packet rate is below `pkt_rate_low`. |
| • • **features** *dictionary*                               | A dictionary that enables (`true`) or disables (`false`) individual `ethtool` device features and offloads; every entry is a boolean toggle. Each key is a feature name: run `ethtool -k <device>` to list the features a device supports and see `man 8 ethtool` for the meaning of each one. The individual features are therefore not described separately below. Every feature also accepts a deprecated alias that uses dashes instead of underscores, matching the hyphen-separated feature names that `ethtool` and `nmcli` use natively (for example `tx-tcp-segmentation` for `tx_tcp_segmentation`); use the underscored name instead. |
| • • • **esp-hw-offload** *boolean*                          | **Choices:** `false`, `true` |
| • • • **esp-tx-csum-hw-offload** *boolean*                  | **Choices:** `false`, `true` |
| • • • **esp_hw_offload** *boolean*                          | **Choices:** `false`, `true` |
| • • • **esp_tx_csum_hw_offload** *boolean*                  | **Choices:** `false`, `true` |
| • • • **fcoe-mtu** *boolean*                                | **Choices:** `false`, `true` |
| • • • **fcoe_mtu** *boolean*                                | **Choices:** `false`, `true` |
| • • • **gro** *boolean*                                     | **Choices:** `false`, `true` |
| • • • **gso** *boolean*                                     | **Choices:** `false`, `true` |
| • • • **highdma** *boolean*                                 | **Choices:** `false`, `true` |
| • • • **hw-tc-offload** *boolean*                           | **Choices:** `false`, `true` |
| • • • **hw_tc_offload** *boolean*                           | **Choices:** `false`, `true` |
| • • • **l2-fwd-offload** *boolean*                          | **Choices:** `false`, `true` |
| • • • **l2_fwd_offload** *boolean*                          | **Choices:** `false`, `true` |
| • • • **loopback** *boolean*                                | **Choices:** `false`, `true` |
| • • • **lro** *boolean*                                     | **Choices:** `false`, `true` |
| • • • **ntuple** *boolean*                                  | **Choices:** `false`, `true` |
| • • • **rx** *boolean*                                      | **Choices:** `false`, `true` |
| • • • **rx-all** *boolean*                                  | **Choices:** `false`, `true` |
| • • • **rx-fcs** *boolean*                                  | **Choices:** `false`, `true` |
| • • • **rx-gro-hw** *boolean*                               | **Choices:** `false`, `true` |
| • • • **rx-udp_tunnel-port-offload** *boolean*              | **Choices:** `false`, `true` |
| • • • **rx-vlan-filter** *boolean*                          | **Choices:** `false`, `true` |
| • • • **rx-vlan-stag-filter** *boolean*                     | **Choices:** `false`, `true` |
| • • • **rx-vlan-stag-hw-parse** *boolean*                   | **Choices:** `false`, `true` |
| • • • **rx_all** *boolean*                                  | **Choices:** `false`, `true` |
| • • • **rx_fcs** *boolean*                                  | **Choices:** `false`, `true` |
| • • • **rx_gro_hw** *boolean*                               | **Choices:** `false`, `true` |
| • • • **rx_udp_tunnel_port_offload** *boolean*              | **Choices:** `false`, `true` |
| • • • **rx_vlan_filter** *boolean*                          | **Choices:** `false`, `true` |
| • • • **rx_vlan_stag_filter** *boolean*                     | **Choices:** `false`, `true` |
| • • • **rx_vlan_stag_hw_parse** *boolean*                   | **Choices:** `false`, `true` |
| • • • **rxhash** *boolean*                                  | **Choices:** `false`, `true` |
| • • • **rxvlan** *boolean*                                  | **Choices:** `false`, `true` |
| • • • **sg** *boolean*                                      | **Choices:** `false`, `true` |
| • • • **tls-hw-record** *boolean*                           | **Choices:** `false`, `true` |
| • • • **tls-hw-tx-offload** *boolean*                       | **Choices:** `false`, `true` |
| • • • **tls_hw_record** *boolean*                           | **Choices:** `false`, `true` |
| • • • **tls_hw_tx_offload** *boolean*                       | **Choices:** `false`, `true` |
| • • • **tso** *boolean*                                     | **Choices:** `false`, `true` |
| • • • **tx** *boolean*                                      | **Choices:** `false`, `true` |
| • • • **tx-checksum-fcoe-crc** *boolean*                    | **Choices:** `false`, `true` |
| • • • **tx-checksum-ip-generic** *boolean*                  | **Choices:** `false`, `true` |
| • • • **tx-checksum-ipv4** *boolean*                        | **Choices:** `false`, `true` |
| • • • **tx-checksum-ipv6** *boolean*                        | **Choices:** `false`, `true` |
| • • • **tx-checksum-sctp** *boolean*                        | **Choices:** `false`, `true` |
| • • • **tx-esp-segmentation** *boolean*                     | **Choices:** `false`, `true` |
| • • • **tx-fcoe-segmentation** *boolean*                    | **Choices:** `false`, `true` |
| • • • **tx-gre-csum-segmentation** *boolean*                | **Choices:** `false`, `true` |
| • • • **tx-gre-segmentation** *boolean*                     | **Choices:** `false`, `true` |
| • • • **tx-gso-partial** *boolean*                          | **Choices:** `false`, `true` |
| • • • **tx-gso-robust** *boolean*                           | **Choices:** `false`, `true` |
| • • • **tx-ipxip4-segmentation** *boolean*                  | **Choices:** `false`, `true` |
| • • • **tx-ipxip6-segmentation** *boolean*                  | **Choices:** `false`, `true` |
| • • • **tx-nocache-copy** *boolean*                         | **Choices:** `false`, `true` |
| • • • **tx-scatter-gather** *boolean*                       | **Choices:** `false`, `true` |
| • • • **tx-scatter-gather-fraglist** *boolean*              | **Choices:** `false`, `true` |
| • • • **tx-sctp-segmentation** *boolean*                    | **Choices:** `false`, `true` |
| • • • **tx-tcp-ecn-segmentation** *boolean*                 | **Choices:** `false`, `true` |
| • • • **tx-tcp-mangleid-segmentation** *boolean*            | **Choices:** `false`, `true` |
| • • • **tx-tcp-segmentation** *boolean*                     | **Choices:** `false`, `true` |
| • • • **tx-tcp6-segmentation** *boolean*                    | **Choices:** `false`, `true` |
| • • • **tx-udp-segmentation** *boolean*                     | **Choices:** `false`, `true` |
| • • • **tx-udp_tnl-csum-segmentation** *boolean*            | **Choices:** `false`, `true` |
| • • • **tx-udp_tnl-segmentation** *boolean*                 | **Choices:** `false`, `true` |
| • • • **tx-vlan-stag-hw-insert** *boolean*                  | **Choices:** `false`, `true` |
| • • • **tx_checksum_fcoe_crc** *boolean*                    | **Choices:** `false`, `true` |
| • • • **tx_checksum_ip_generic** *boolean*                  | **Choices:** `false`, `true` |
| • • • **tx_checksum_ipv4** *boolean*                        | **Choices:** `false`, `true` |
| • • • **tx_checksum_ipv6** *boolean*                        | **Choices:** `false`, `true` |
| • • • **tx_checksum_sctp** *boolean*                        | **Choices:** `false`, `true` |
| • • • **tx_esp_segmentation** *boolean*                     | **Choices:** `false`, `true` |
| • • • **tx_fcoe_segmentation** *boolean*                    | **Choices:** `false`, `true` |
| • • • **tx_gre_csum_segmentation** *boolean*                | **Choices:** `false`, `true` |
| • • • **tx_gre_segmentation** *boolean*                     | **Choices:** `false`, `true` |
| • • • **tx_gso_partial** *boolean*                          | **Choices:** `false`, `true` |
| • • • **tx_gso_robust** *boolean*                           | **Choices:** `false`, `true` |
| • • • **tx_ipxip4_segmentation** *boolean*                  | **Choices:** `false`, `true` |
| • • • **tx_ipxip6_segmentation** *boolean*                  | **Choices:** `false`, `true` |
| • • • **tx_nocache_copy** *boolean*                         | **Choices:** `false`, `true` |
| • • • **tx_scatter_gather** *boolean*                       | **Choices:** `false`, `true` |
| • • • **tx_scatter_gather_fraglist** *boolean*              | **Choices:** `false`, `true` |
| • • • **tx_sctp_segmentation** *boolean*                    | **Choices:** `false`, `true` |
| • • • **tx_tcp6_segmentation** *boolean*                    | **Choices:** `false`, `true` |
| • • • **tx_tcp_ecn_segmentation** *boolean*                 | **Choices:** `false`, `true` |
| • • • **tx_tcp_mangleid_segmentation** *boolean*            | **Choices:** `false`, `true` |
| • • • **tx_tcp_segmentation** *boolean*                     | **Choices:** `false`, `true` |
| • • • **tx_udp_segmentation** *boolean*                     | **Choices:** `false`, `true` |
| • • • **tx_udp_tnl_csum_segmentation** *boolean*            | **Choices:** `false`, `true` |
| • • • **tx_udp_tnl_segmentation** *boolean*                 | **Choices:** `false`, `true` |
| • • • **tx_vlan_stag_hw_insert** *boolean*                  | **Choices:** `false`, `true` |
| • • • **txvlan** *boolean*                                  | **Choices:** `false`, `true` |
| • • **ring** *dictionary*                                   | A dictionary of `ethtool` `rx`/`tx` ring buffer entry counts. |
| • • • **rx** *integer*                                      | The number of ring entries for the Rx ring. |
| • • • **rx_jumbo** *integer*                                | The number of ring entries for the Rx Jumbo ring. |
| • • • **rx_mini** *integer*                                 | The number of ring entries for the Rx Mini ring. |
| • • • **tx** *integer*                                      | The number of ring entries for the Tx ring. |
| • **force_state_change** *boolean*                          | Whether to force the runtime state change specified by `state` even when the role does not detect a difference between the requested and current configuration. Only meaningful together with `state`. **Choices:** `false`, `true` |
| • **ieee802_1x** *dictionary*                               | 802.1x authentication settings for `ethernet` or `wireless` interfaces. Only supported by the `nm` provider. `tls` is currently the only supported EAP method, and the certificates and keys it references must already be deployed on the host before running the role. |
| • • **ca_cert** *path*                                      | The absolute path to the PEM encoded certificate authority used to verify the EAP server. |
| • • **ca_path** *path*                                      | The absolute path to a directory of additional PEM encoded CA certificates used to verify the EAP server. Can be used instead of or in addition to `ca_cert`. Cannot be used together with `system_ca_certs`. |
| • • **client_cert** *path / required*                       | The absolute path to the client’s PEM encoded certificate. |
| • • **domain_suffix_match** *string*                        | A domain name suffix that must match the domain name in the EAP server’s certificate. |
| • • **eap** *string*                                        | The EAP method used to authenticate to the network. **Choices:** `"tls"` (default) |
| • • **identity** *string / required*                        | The identity string for the EAP authentication method. |
| • • **private_key** *path / required*                       | The absolute path to the client’s PEM or PKCS#12 encoded private key. |
| • • **private_key_password** *string*                       | The password protecting `private_key`. |
| • • **private_key_password_flags** *list / elements=string* | Flags controlling how NetworkManager manages the private key password. See the “Secret flag types” section of `man 5 nm-settings` for details. **Choices:** `"none"`, `"agent-owned"`, `"not-saved"`, `"not-required"` |
| • • **system_ca_certs** *boolean*                           | Whether NetworkManager should use the system’s trusted CA certificates to verify the EAP server. **Choices:** `false` (default), `true` |
| • **ignore_errors** *boolean*                               | Whether to ignore errors that occur while applying this specific connection profile and continue applying the remaining profiles instead of failing the play. **Choices:** `false`, `true` |
| • **infiniband** *dictionary*                               | Settings for `infiniband` connections. Only supported by the `nm` provider. |
| • • **p_key** *integer*                                     | The Infiniband P_Key to use for the device, a 16-bit unsigned integer with the high bit set for “full membership”. The values `0x0000` and `0x8000` are invalid. If set, `mac` or `parent` must also be set, and `interface_name` must be unset. When unset, the connection is created on the physical Infiniband fabric. |
| • • **transport_mode** *string*                             | The IP over Infiniband (ipoib) operation mode. **Choices:** `"datagram"` (default), `"connected"` |
| • **infiniband_p_key** *integer*                            | Deprecated alias for `infiniband.p_key`. Use the `infiniband` option instead. Cannot be combined with an `infiniband` dictionary. |
| • **infiniband_transport_mode** *string*                    | Deprecated alias for `infiniband.transport_mode`. Use the `infiniband` option instead. Cannot be combined with an `infiniband` dictionary. **Choices:** `"datagram"`, `"connected"` |
| • **interface_name** *string*                               | The name of the networking interface that the profile is restricted to or, for virtual devices, the name of the interface to create. Only allowed for `ethernet` and `infiniband` when `mac` is not set. Set to an empty string (`""`) to leave the profile unrestricted to a specific interface. Defaults to the profile `name` for most types, except that `bond`, `bridge`, `macvlan`, `team`, and `vlan` require an explicit `interface_name`. |
| • **ip** *dictionary*                                       | The IP configuration of the profile. Ports of `bridge`, `bond`, or `team` devices cannot specify `ip` settings. |
| • • **address** *list / elements=any*                       | A list of static IP addresses to assign. Each item is either a string in `<address>/<prefix>` notation, for example `192.0.2.3/24`, or a dictionary with an `address` key and an optional `prefix` key. |
| • • **auto6** *boolean*                                     | Whether to configure IPv6 addressing using StateLess Address Auto Configuration (SLAAC). If unset, defaults to `true` unless static IPv6 addresses are configured in `address`. **Choices:** `false`, `true` |
| • • **auto_gateway** *boolean*                              | Whether a default route should be configured using the automatically detected default gateway. Setting this to `false` is equivalent to `DEFROUTE=no` in initscripts or `ipv4.never-default`/ `ipv6.never-default` set to `yes` with `nmcli`. If enabled, at least one of `gateway4`, `gateway6`, or DHCP/SLAAC must be in use. **Choices:** `false`, `true` |
| • • **dhcp4** *boolean*                                     | Whether to obtain an IPv4 address using DHCP. If unset, defaults to `true` unless static IPv4 addresses are configured in `address`. **Choices:** `false`, `true` |
| • • **dhcp4_send_hostname** *boolean*                       | Whether the DHCPv4 request should include the host’s name. Only valid when `dhcp4` is enabled. Only supported by the `nm` provider. **Choices:** `false`, `true` |
| • • **dns** *list / elements=string*                        | A list of name server IP addresses for manual DNS configuration, for example `192.0.2.2`. |
| • • **dns_options** *list / elements=string*                | A list of DNS options as described in `man 5 resolv.conf`, for example `rotate` or `timeout:1`. Only supported by the `nm` provider. |
| • • **dns_priority** *integer*                              | The priority of the DNS servers configured on this connection. A lower numerical value has a higher priority. A negative value excludes name servers from connections with a higher (less negative) priority value when at least one negative priority is present. **Default:** `0` |
| • • **dns_search** *list / elements=string*                 | A list of DNS search domains for manual DNS configuration, for example `example.com`. |
| • • **gateway4** *string*                                   | The default gateway for IPv4 packets, for example `192.0.2.1`. |
| • • **gateway6** *string*                                   | The default gateway for IPv6 packets, for example `2001:db8::1`. |
| • • **ipv4_ignore_auto_dns** *boolean*                      | Whether to ignore IPv4 name servers and search domains obtained automatically (for example via DHCP) and only use the servers and domains specified in `dns` and `dns_search`. Not supported by the `initscripts` provider. **Choices:** `false`, `true` |
| • • **ipv6_disabled** *boolean*                             | Whether IPv6 should be disabled for the connection. Mutually exclusive with `auto6` enabled, static IPv6 addresses in `address`, `gateway6`, and `route_metric6`. **Choices:** `false`, `true` |
| • • **ipv6_ignore_auto_dns** *boolean*                      | Whether to ignore IPv6 name servers and search domains obtained automatically and only use the servers and domains specified in `dns` and `dns_search`. Not supported by the `initscripts` provider. **Choices:** `false`, `true` |
| • • **route** *list / elements=dictionary*                  | A list of static routes. |
| • • • **gateway** *string*                                  | The gateway address for the route. Not allowed together with `type`. |
| • • • **metric** *integer*                                  | The route metric. **Default:** `-1` |
| • • • **network** *string / required*                       | The destination network address of the route, for example `198.51.100.128`. Classless inter-domain routing (CIDR) and network mask notations are not supported here; use `prefix` instead. |
| • • • **prefix** *integer*                                  | The prefix length of the destination network in `network`. Defaults to the address family’s full prefix length when not specified. |
| • • • **src** *string*                                      | The source IP address to use for the route. |
| • • • **table** *any*                                       | The routing table for the route, as a numeric table ID or the name of a table defined in `/etc/iproute2/rt_tables` or `/etc/iproute2/rt_tables.d/*.conf`. The role does not create these routing table definitions automatically. Not supported by the `initscripts` provider. |
| • • • **type** *string*                                     | The route type. Routes of these types do not support a `gateway`. If not specified, the route is a regular unicast route. **Choices:** `"blackhole"`, `"prohibit"`, `"unreachable"` |
| • • **route_append_only** *boolean*                         | Whether to append the routes in `route` to the routes already present on the system instead of replacing them. Setting this to `true` without setting `route` preserves the current static routes. **Choices:** `false` (default), `true` |
| • • **route_metric4** *integer*                             | The route metric used for DHCP-assigned routes and the default IPv4 route, which also determines priority when multiple interfaces are configured. For `initscripts`, this sets the metric of the default route. |
| • • **route_metric6** *integer*                             | The route metric used for the default IPv6 route. Not supported by the `initscripts` provider. |
| • • **routing_rule** *list / elements=dictionary*           | A list of policy routing rules, allowing packets to be routed based on fields other than the destination address. |
| • • • **action** *string*                                   | The action to take when the rule matches. `table` is required when `action` is `to-table`. **Choices:** `"to-table"` (default), `"blackhole"`, `"prohibit"`, `"unreachable"` |
| • • • **dport** *any*                                       | The destination port or port range to match, for example `1000-2000`. Accepts a single port number or a string in `<start>-<end>` notation, with valid ports ranging from 0 to 65534. |
| • • • **family** *string*                                   | The IP family of the rule. Derived from `from` or `to` when not specified. **Choices:** `"ipv4"`, `"ipv6"` |
| • • • **from** *any*                                        | The source address to match, for example `192.168.100.58/24`. Accepts a string in `<address>/<prefix>` notation or a dictionary with `address` and `prefix` keys. |
| • • • **fwmark** *integer*                                  | The firewall mark value of the packet to match. Must be set together with `fwmask`. |
| • • • **fwmask** *integer*                                  | The firewall mask value of the packet to match. Must be set together with `fwmark`. |
| • • • **iif** *string*                                      | The name of the incoming interface to match. |
| • • • **invert** *boolean*                                  | Whether to invert the match of the rule, so the rule matches any packet that does not satisfy the selected match. **Choices:** `false` (default), `true` |
| • • • **ipproto** *integer*                                 | The IP protocol number to match. |
| • • • **oif** *string*                                      | The name of the outgoing interface to match. |
| • • • **priority** *integer / required*                     | The priority of the rule. A lower numerical value means higher priority. |
| • • • **sport** *any*                                       | The source port or port range to match, in the same format as `dport`. |
| • • • **suppress_prefixlength** *integer*                   | Reject routing decisions with a prefix length less than or equal to the specified value. Only allowed with the `to-table` action. |
| • • • **table** *any*                                       | The routing table to look up for the `to-table` action, in the same format as `route.table`. |
| • • • **to** *any*                                          | The destination address to match, in the same format as `from`. |
| • • • **tos** *integer*                                     | The type-of-service value to match. |
| • • • **uid** *any*                                         | The user ID or user ID range to match, in the same format as `dport`, with valid values ranging from 0 to 4294967295. |
| • • **rule_append_only** *boolean*                          | Whether to append the rules in `routing_rule` to the routing rules already present on the system instead of replacing them. **Choices:** `false` (default), `true` |
| • • **wait_ip** *string*                                    | Which IP stack must be configured before the connection is considered activated. `any` waits for either stack, `ipv4` and `ipv6` wait for the respective stack, and `ipv4+ipv6` waits for both. **Choices:** `"any"` (default), `"ipv4"`, `"ipv6"`, `"ipv4+ipv6"` |
| • **mac** *string*                                          | Restricts the profile to the device with the given hardware address. Only allowed for `type` `ethernet` (6 octets) or `infiniband` (20 octets). Specify the value in hexadecimal notation using colons, for example `"00:00:5e:00:53:5d"`, and quote it to avoid it being parsed as a sexagesimal number. |
| • **macvlan** *dictionary*                                  | Settings for `macvlan` connections. |
| • • **mode** *string*                                       | The MACVLAN mode. **Choices:** `"vepa"`, `"bridge"` (default), `"private"`, `"passthru"`, `"source"` |
| • • **promiscuous** *boolean*                               | Whether the underlying device is used in promiscuous mode. Can only be disabled (`false`) when `mode` is `passthru`. **Choices:** `false`, `true` (default) |
| • • **tap** *boolean*                                       | Whether the device should be a MACVTAP device instead of a regular MACVLAN device. **Choices:** `false` (default), `true` |
| • **master** *string*                                       | Deprecated alias for `controller`. Use `controller` instead. |
| • **match** *dictionary*                                    | Settings used to match the profile against devices or systems, currently only supporting `path`. |
| • • **path** *list / elements=string*                       | A list of patterns to match against the `ID_PATH` udev property of a device, for example `pci-0000:00:03.0`. Supports the alternative (`\|`), mandatory (`&`), and inverted (`!`) modifiers, as well as `*`, `?`, and `[...]` shell-style wildcards. Only supported for `ethernet` or `infiniband` profiles. |
| • **mtu** *integer*                                         | The maximum transmission unit of the profile’s device. The maximum allowed value depends on the device; for virtual devices it depends on the underlying device. |
| • **name** *string*                                         | The name that identifies the connection profile. This is not necessarily the name of the networking interface, although a profile can be associated with an interface using the same name. For `NetworkManager`, this corresponds to `connection.id`. For `initscripts`, this determines the ifcfg file name `/etc/sysconfig/network-scripts/ifcfg-$NAME` and therefore cannot contain `/`. Required unless `persistent_state` is `absent`, in which case an empty `name` matches and removes every other profile. |
| • **parent** *string*                                       | The `name` of another profile in **`network_connections`** that this profile’s device is created on top of. Used for `vlan`, `macvlan`, and `infiniband` (when `infiniband.p_key` is set). |
| • **persistent_state** *string*                             | Whether the connection profile should be saved on disk. `present` (the default) creates or updates the profile when `type` is also specified. `absent` deletes any profile matching `name`. **Choices:** `"present"`, `"absent"` |
| • **port_type** *string*                                    | The type of the `controller` profile that this profile is a port of. Requires `controller` to be set. If not specified, it is derived from the type of the `controller` profile. **Choices:** `"bridge"`, `"bond"`, `"team"` |
| • **slave_type** *string*                                   | Deprecated alias for `port_type`. Use `port_type` instead. **Choices:** `"bridge"`, `"bond"`, `"team"` |
| • **state** *string*                                        | The runtime state of the connection profile. `up` activates the profile (equivalent to `nmcli connection up` or `ifup`) and `down` deactivates it (equivalent to `nmcli connection down` or `ifdown`). `present` and `absent` are accepted as aliases of the `persistent_state` values of the same name, but `state` and `persistent_state` cannot both be set on the same item. If unset, the runtime state is left unchanged. **Choices:** `"up"`, `"down"`, `"present"`, `"absent"` |
| • **type** *string*                                         | The type of the connection profile. Providing `type` means the profile is completely specified; without it, only the runtime `state` of an existing profile can be changed. **Choices:** `"ethernet"`, `"infiniband"`, `"bridge"`, `"team"`, `"bond"`, `"vlan"`, `"macvlan"`, `"wireless"`, `"dummy"` |
| • **vlan** *dictionary*                                     | Settings for `vlan` connections. |
| • • **id** *integer / required*                             | The VLAN ID, ranging from 0 to 4094. |
| • **vlan_id** *integer*                                     | Deprecated alias for `vlan.id`. Use the `vlan` option instead. Cannot be combined with `vlan`. |
| • **wait** *float*                                          | The number of seconds to wait for the device to finish activating when `state` is `up`. `0` starts the activation without waiting for completion, for example while a DHCP lease is obtained in the background. When unset, a suitable default timeout is used. Only supported by the `nm` provider and only meaningful together with `state`. |
| • **wireless** *dictionary*                                 | Settings for `wireless` connections, supporting WPA-PSK, WPA-EAP (802.1x), WPA3-Personal SAE, and Enhanced Open (OWE) authentication. Only supported by the `nm` provider. |
| • • **key_mgmt** *string / required*                        | The key management method used to authenticate to the network. When `wpa-eap` is used, 802.1x settings must also be defined in `ieee802_1x`. **Choices:** `"owe"`, `"sae"`, `"wpa-eap"`, `"wpa-psk"` |
| • • **password** *string*                                   | The password for the network. Required when `key_mgmt` is `wpa-psk` or `sae`, and not allowed otherwise. |
| • • **ssid** *string / required*                            | The SSID of the wireless network. |
| • **zone** *string*                                         | The firewalld zone to associate with the interface. Ports of `bridge`, `bond`, or `team` devices cannot specify a zone. |
| **network_force_state_change** *boolean*                    | Whether to force the runtime state change requested by a profile’s `state` even when the role does not detect a difference between the requested and current configuration. Acts as the default for every item of **`network_connections`** that does not set its own `force_state_change`. **Choices:** `false`, `true` |
| **network_ignore_errors** *boolean*                         | Whether to ignore errors encountered while applying a connection profile and continue applying the remaining profiles instead of failing the play. Acts as the default for every item of **`network_connections`** that does not set its own `ignore_errors`. **Choices:** `false`, `true` |
| **network_state** *dictionary*                              | The desired network state to apply directly to the devices, using the [Nmstate](https://nmstate.io) schema (see the [Nmstate examples](https://nmstate.io/examples.html) and the [nmstate API documentation](https://docs.rs/nmstate/latest/nmstate/index.html)). When left empty, no state is applied. Only supported by the `nm` provider on RHEL 8 and later. Only the top-level keys are listed below; nmstate itself validates everything nested under them, so this role does not re-validate that content. **Default:** `{}` |
| • **description** *string*                                  | A human-readable description of the whole desired state. Not persisted or applied by the network backend. |
| • **dns-resolver** *dictionary*                             | The desired DNS resolver configuration (search domains and servers). See the [Nmstate DNS resolver schema](https://nmstate.io/devel/yaml_api.html) for its exact structure. Cannot be used while NetworkManager has a `[global-dns]` or `[global-dns-domain-*]` section configured. |
| • **hostname** *dictionary*                                 | The desired hostname configuration. See the [Nmstate hostname schema](https://nmstate.io/devel/yaml_api.html) for its exact structure. |
| • **interfaces** *list / elements=dictionary*               | The desired per-interface configuration (type, state, IP addressing, and type-specific settings such as bridge, bond, or VLAN options). See the [Nmstate interface schema](https://nmstate.io/devel/yaml_api.html) for its exact structure. |
| • **ovn** *dictionary*                                      | The desired OVN (Open Virtual Network) mapping configuration. See the [Nmstate OVN schema](https://nmstate.io/devel/yaml_api.html) for its exact structure. |
| • **ovs-db** *dictionary*                                   | The desired global Open vSwitch database configuration. See the [Nmstate OVS-DB schema](https://nmstate.io/devel/yaml_api.html) for its exact structure. |
| • **route-rules** *dictionary*                              | The desired routing rules. See the [Nmstate route rules schema](https://nmstate.io/devel/yaml_api.html) for its exact structure. |
| • **routes** *dictionary*                                   | The desired static routes. See the [Nmstate routes schema](https://nmstate.io/devel/yaml_api.html) for its exact structure. |

### Attributes

| Attribute      | Support                                                                                            | Description |
| -------------- | -------------------------------------------------------------------------------------------------- | --- |
| **check_mode** | **full**                                                                                           | The role can be run with `--check` to preview the changes it would make without applying them. Running with `--check` first is recommended before applying a new configuration. |
| **platform**   | **Platforms:** **Fedora**, **EL**, **CentOS**, **RHEL**, **AlmaLinux**, **Rocky**, **OracleLinux** | Target operating systems. The role also supports distributions that it treats like RHEL, such as AlmaLinux, CentOS, OracleLinux, and Rocky. |

### Notes

- The `network_provider`, `network_provider_os_default`, `network_packages`, and `network_service_name` variables are intentionally not listed in the parameters below, even though they appear in `defaults/main.yml`. Their defaults depend on facts (such as `ansible_facts.services` and `ansible_facts.packages`) that are only gathered by this role’s own tasks. Ansible resolves the current value of every declared option when it validates role arguments, and it does so before the role’s own tasks (including its fact gathering) run. Declaring those variables here would force their fact-dependent defaults to be evaluated too early and break provider autodetection for the common case where the calling playbook has not already gathered service and package facts.

- **`network_ignore_errors`** and **`network_force_state_change`** are not set in `defaults/main.yml` (they are left undefined so the `network_connections` module can apply its own static default), but they are documented, user-facing parameters read directly in `tasks/main.yml` and are listed in the parameters below.

### Examples

```yaml
- name: Configure an Ethernet profile with full IPv4 and IPv6 settings
  hosts: all
  vars:
    network_connections:
      - name: eth0
        type: ethernet
        ip:
          route_metric4: 100
          dhcp4: false
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
  roles:
    - linux-system-roles.network

- name: Create a bridge with a bond attached to it
  hosts: all
  vars:
    network_connections:
      - name: internal-br0
        interface_name: br0
        type: bridge
        ip:
          dhcp4: false
          auto6: false
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
  roles:
    - linux-system-roles.network

- name: Configure a VLAN on top of an Ethernet profile
  hosts: all
  vars:
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
  roles:
    - linux-system-roles.network

- name: Configure a MACVLAN on top of an Ethernet profile
  hosts: all
  vars:
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
  roles:
    - linux-system-roles.network

- name: Configure a WPA-PSK wireless connection
  hosts: all
  vars:
    network_connections:
      - name: wlan0
        type: wireless
        wireless:
          ssid: "My WPA2-PSK Network"
          key_mgmt: "wpa-psk"
          # recommend vault encrypting the wireless password
          password: "{{ vault_wifi_password }}"
  roles:
    - linux-system-roles.network

- name: Configure 802.1x (EAP-TLS) authentication on an Ethernet profile
  hosts: all
  vars:
    network_connections:
      - name: eth0
        type: ethernet
        ieee802_1x:
          identity: myhost
          eap: tls
          private_key: /etc/pki/tls/client.key
          # recommend vault encrypting the private key password
          private_key_password: "{{ vault_private_key_password }}"
          client_cert: /etc/pki/tls/client.pem
          ca_cert: /etc/pki/tls/cacert.pem
          domain_suffix_match: example.com
  roles:
    - linux-system-roles.network

- name: Apply IP addresses directly to devices with network_state
  hosts: all
  vars:
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
  roles:
    - linux-system-roles.network

- name: Configure a static route with network_state
  hosts: all
  vars:
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
  roles:
    - linux-system-roles.network

- name: Configure DNS search domains and servers with network_state
  hosts: all
  vars:
    network_state:
      dns-resolver:
        config:
          search:
            - example.com
            - example.org
          server:
            - 2001:4860:4860::8888
            - 8.8.8.8
  roles:
    - linux-system-roles.network
```

### Authors

- Thomas Haller

- Till Maas
