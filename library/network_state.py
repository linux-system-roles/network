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


class NetworkState:
    def __init__(self, module, module_name):
        self.module = module
        self.params = module.params
        self.result = dict(changed=False)
        self.module_name = module_name
        self.previous_state = self.get_state_config()

    def run(self):
        desired_state = self.params["desired_state"]
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
