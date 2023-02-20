Changelog
=========

[1.11.2] - 2023-02-20
--------------------

### New Features

- none

### Bug Fixes

- initscripts: Configure output device in routes

### Other Changes

- none

[1.11.1] - 2023-01-24
--------------------

### New Features

- none

### Bug Fixes

- none

### Other Changes

- ansible-lint 6.x updates
- Support running the tests with ANSIBLE_GATHERING=explicit
- Clean up / Workaround non-inclusive words
- Add check for non-inclusive language
- fix the ansible-pull link, the old do not work
- tag all bond tests with expfail

[1.11.0] - 2022-12-12
--------------------

### New Features

- Support cloned MAC address

### Bug Fixes

- none

### Other Changes

- none

[1.10.1] - 2022-11-14
--------------------

### New Features

- none

### Bug Fixes

- none

### Other Changes

- support ansible-core-2.14, ansible-lint 6.x

[1.10.0] - 2022-11-01
--------------------

### New Features

- Support looking up named route table in routing rule
- Support 'route_metric4' for initscripts provider
- Support the DNS priority

### Bug Fixes

- bond: improve the validation for setting peer_notif_delay
- bond: test arp_all_targets only when arp_interval is enabled
- bond: attach ports when creating the bonding connection

### Other Changes

- Set the route metric when testing the 'auto_gateway'
- Fix markdownlint 'unordered list indentation' issue
- add ip.route_metric4: 65535 to failing bond tests
- use rpm -i instead of yum install for epel7

[1.9.1] - 2022-08-05
--------------------

### New features

- none

### Bug Fixes

- network_state: improve state comparison for achieving idempotency
- argument_validator: fix IPRouteUtils.get_route_tables_mapping() for whitespace
  sequence

### Other Changes

- none

[1.9.0] - 2022-07-07
--------------------

### New features

- Support the nmstate network state configuration

### Bug Fixes

- IfcfgUtil: Remediate `connection_seems_active()` for controller

### Other Changes

- use `include_tasks` instead of `include`
- make `min_ansible_version` a string in meta/main.yml

[1.8.0] - 2022-05-19
--------------------

### New features

- Support routing rules
- Support the ipoib (IP over Infiniband) connection

### Bug fixes

- Reject configuring `ipv6_disabled` if not supported in NM
- Support playbooks which use `gather_facts: false`

[1.7.1] - 2022-03-14
--------------------

### New features

- Add support for Rocky Linux

### Bug fixes

- bond: Fix supporting the infiniband ports in active-backup mode

[1.7.0] - 2022-02-14
--------------------

### New features

- NetworkManager provider: Support all available bonding modes and options

[1.6.0] - 2022-02-02
--------------------

### New features

- Support routing tables in static routes

### Bug fixes

- Fix setting DNS search settings when only one IP family is enabled
- Fix switching from initscripts to NetworkManager 1.18

[1.5.0] - 2021-12-14
--------------------

### Changes

- Support ansible-core 2.11 and 2.12

### New features

- Support matching network interfaces by their device path such as PCI address

[1.4.0] - 2021-08-10
--------------------

### Changes

- Drop the support for Ansible 2.8
- Display the `stderr_lines` only by default
- All the config parameters can still be displayed as previous using
    `ansible-playbook -v`

### New features

- Support Simultaneous Authentication of Equals(SAE) authentication
- Support Opportunistic Wireless Encryption (OWE)
- Support Ethtool ring settings
- Support `auto_gateway` option

### Bug fixes

- Fix static IPv6 support for initscripts provider
- Fix `dns_search` and `dns_options` support for all address family
- Fix deprecation warning on Ethtool setting
- Fix the idempotence when applying the same network connection twice

[1.3.0] - 2021-04-08
--------------------

### Changes

- Use inclusive language
- `slave` is deprecated in favor of `port` <!--- wokeignore:rule=slave -->
- `master` is deprecated in favor of `controller` <!--- wokeignore:rule=master -->

### New features

- Support disabling IPv6
- Support `dns_options` when using one or more IPv4 nameservers
- Support Ethtool coalesce settings
- Support dummy interfaces <!--- wokeignore:rule=dummy -->

### Bug fixes

- Fix static IPv6 support for initscripts provider

[1.2.0] - 2020-08-26
--------------------

### Changes

- Rename ethtool features to use underscores instead of dashes to support
  Jinja2 dot notation. Accept old notation for compatibility with existing
  playbooks.

### New features

- Initial 802.1x authentication support (only EAP-TLS)
- Wireless support
- Handle OracleLinux as a RHEL clone
- Remove dependency on ethtool command line tool
- initscripts: Support creating and activating bond profiles in one run
- Ignore up/down states if a profile is not defined and not present on the
  managed host
- Document bond profiles

### Bug fixes

- NetworkManager: Always rollback checkpoint on failure
- NetworkManager: Try to reapply changes to reduce network interruptions
- initscripts: Fix dependencies for Fedora 32
- Only log actual warnings as Ansible warnings
