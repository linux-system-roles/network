#!/usr/bin/python
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: network_state
version_added: "2.13.0"
short_description: module for network role to apply network state configuration
description:
    - This module allows to apply the network state configuration through nmstate,
      https://github.com/nmstate/nmstate
options:
    desired_state:
        description: Nmstate state definition
        required: true
        type: dict
author: "Wen Liang (@liangwen12year)"
"""

EXAMPLES = r"""
network_state:
  desired_state:
    dns-resolver:
      config:
        search:
          - example.com
          - example.org
        server:
          - 2001:4860:4860::8888
          - 8.8.8.8
"""

RETURN = r"""
state:
    description: Network state after running the module
    type: dict
    returned: always
"""

import glob
import os
import re
import traceback

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

try:
    import libnmstate  # pylint: disable=import-error
except ImportError:
    NETWORK_HAS_NMSTATE = False
    NETWORK_NMSTATE_IMPORT_ERROR = traceback.format_exc()
else:
    NETWORK_HAS_NMSTATE = True
    NETWORK_NMSTATE_IMPORT_ERROR = None

# NetworkManager.conf(5) load order: a later dir shadows a same-named file.
# D-Bus-set global DNS lives in [.intern.*] groups and must not match.
NM_CONFIG_FILE = "/etc/NetworkManager/NetworkManager.conf"
NM_CONFIG_DIRS = [
    "/usr/lib/NetworkManager/conf.d",
    "/run/NetworkManager/conf.d",
    "/etc/NetworkManager/conf.d",
]
NM_GLOBAL_DNS_SECTION_RE = re.compile(b"^\\s*\\[global-dns(-domain-[^\\]]*)?\\]")


def find_nm_global_dns_config():
    """Return the NetworkManager config files that define [global-dns*] sections."""
    snippets = {}
    for config_dir in NM_CONFIG_DIRS:
        for path in glob.glob(os.path.join(config_dir, "*.conf")):
            snippets[os.path.basename(path)] = path
    found = []
    for path in [NM_CONFIG_FILE] + [snippets[name] for name in sorted(snippets)]:
        try:
            with open(path, "rb") as conf:
                if any(NM_GLOBAL_DNS_SECTION_RE.match(line) for line in conf):
                    found.append(path)
        except (IOError, OSError):
            continue
    return found


class NetworkState:
    def __init__(self, module, module_name):
        self.module = module
        self.params = module.params
        self.result = dict(changed=False)
        self.module_name = module_name
        self.previous_state = self.get_state_config()

    def run(self):
        """Apply desired_state through nmstate and exit the module."""
        desired_state = self.params["desired_state"]
        # NetworkManager rejects nmstate's D-Bus global DNS writes while a config
        # file defines global DNS, and nmstate reports that as an internal error.
        if "dns-resolver" in desired_state:
            global_dns_files = find_nm_global_dns_config()
            if global_dns_files:
                self.module.fail_json(
                    msg="Managing `dns-resolver` with `network_state` is not "
                    "supported while NetworkManager has a [global-dns] or "
                    "[global-dns-domain-*] section in its configuration (%s). "
                    "Remove the section and reload NetworkManager, or set the "
                    "DNS options on the connection profiles instead."
                    % ", ".join(global_dns_files)
                )
        libnmstate.apply(desired_state)
        current_state = self.get_state_config()
        if current_state != self.previous_state:
            self.result["changed"] = True

        self.result["state"] = current_state

        self.module.exit_json(**self.result)

    def get_state_config(self):
        if hasattr(libnmstate, "show_running_config") and callable(
            getattr(libnmstate, "show_running_config")
        ):
            state_config = libnmstate.show_running_config()
        else:
            state_config = libnmstate.show()
        return state_config


def run_module():
    module_args = dict(
        desired_state=dict(type="dict", required=True),
    )

    module = AnsibleModule(
        argument_spec=module_args,
    )

    if not NETWORK_HAS_NMSTATE:
        module.fail_json(
            msg=missing_required_lib("libnmstate"),
            exception=NETWORK_NMSTATE_IMPORT_ERROR,
        )

    network_state_module = NetworkState(module, "network_state")
    network_state_module.run()


def main():
    run_module()


if __name__ == "__main__":
    main()
