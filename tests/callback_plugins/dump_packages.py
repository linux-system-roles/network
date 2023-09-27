# -*- coding: utf-8 -*-
# Copyright (C) 2012, Michael DeHaan, <michael.dehaan@gmail.com>
# Copyright (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
    author: Unknown (!UNKNOWN)
    name: context_demo
    type: aggregate
    short_description: demo callback that adds play/task context
    description:
      - Displays some play and task context along with normal output.
      - This is mostly for demo purposes.
    requirements:
      - whitelist in configuration
"""

from ansible.plugins.callback import CallbackBase


class CallbackModule(CallbackBase):
    """
    This is a very trivial example of how any callback function can get at play and task objects.
    play will be 'None' for runner invocations, and task will be None for 'setup' invocations.
    """

    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "aggregate"
    CALLBACK_NAME = "dump_packages"
    CALLBACK_NEEDS_WHITELIST = False

    def __init__(self, *args, **kwargs):
        super(CallbackModule, self).__init__(*args, **kwargs)

    def v2_runner_on_ok(self, result):
        fields = result._task_fields
        if fields["action"] == "package" and fields["args"].get("state") != "absent":
            if isinstance(fields["args"]["name"], list):
                packages = " ".join(fields["args"]["name"])
            else:
                packages = fields["args"]["name"]
            self._display.display("lsrpackages: " + packages)
