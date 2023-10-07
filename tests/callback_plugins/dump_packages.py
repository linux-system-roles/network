# -*- coding: utf-8 -*-
# Copyright (C) 2023, Red Hat, Inc.
# SPDX-License-Identifier: MIT

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
    author: Rich Megginson
    name: dump_packages
    type: aggregate
    short_description: dump arguments to package module
    description:
      - Dump arguments to package module to get list of packages.
      - Used in conjunction with CI testing to get the packages used
      - with all combinations of: distribution/version/role arguments
      - Used to generate lists of packages for ostree image builds.
    requirements:
      - None
"""

from ansible.plugins.callback import CallbackBase  # noqa: E402


class CallbackModule(CallbackBase):
    """
    Dump packages.
    """

    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "aggregate"
    CALLBACK_NAME = "dump_packages"
    # needed for 2.9 compatibility
    CALLBACK_NEEDS_WHITELIST = False  # wokeignore:rule=whitelist
    CALLBACK_NEEDS_ENABLED = False

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
