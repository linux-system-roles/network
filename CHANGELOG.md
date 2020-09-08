# Changelog
## [1.2.0] - 2020-08-26
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
- Ignore up/down states if a profile is not defined and not present on the managed host
- Document bond profiles
### Bug fixes
- NetworkManager: Always rollback checkpoint on failure
- NetworkManager: Try to reapply changes to reduce network interruptions
- initscripts: Fix dependencies for Fedora 32
- Only log actual warnings as Ansible warnings
