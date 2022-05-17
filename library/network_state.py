#!/usr/bin/python
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: network_state
version_added: "2.9"
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

RETURN = r"""
state:
    description: Network state after running the module
    type: dict
    returned: always
"""

from ansible.module_utils.basic import AnsibleModule
import libnmstate  # pylint: disable=import-error


class NetworkState:
    def __init__(self, module, module_name):
        self.module = module
        self.params = module.params
        self.result = dict(changed=False)
        self.module_name = module_name
        self.previous_state = libnmstate.show()

    def run(self):
        desired_state = self.params["desired_state"]
        libnmstate.apply(desired_state)
        current_state = libnmstate.show()
        if current_state != self.previous_state:
            self.result["changed"] = True

        self.result["state"] = current_state

        self.module.exit_json(**self.result)


def run_module():
    module_args = dict(
        desired_state=dict(type="dict", required=True),
    )

    module = AnsibleModule(
        argument_spec=module_args,
    )

    network_state_module = NetworkState(module, "network_state")
    network_state_module.run()


def main():
    run_module()


if __name__ == "__main__":
    main()
