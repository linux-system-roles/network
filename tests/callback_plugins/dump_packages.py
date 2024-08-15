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
        if (
            fields["action"] in ["package", "dnf", "yum"]
            and fields["args"].get("state") != "absent"
        ):
            packages = set()
            if "invocation" in result._result:
                results = [result._result]
            elif "results" in result._result and isinstance(
                result._result["results"], list
            ):
                results = result._result["results"]
            for item in results:
                pkgs = item["invocation"]["module_args"]["name"]
                if isinstance(pkgs, list):
                    for ii in pkgs:
                        packages.add(ii)
                else:
                    packages.add(pkgs)
            # tell python black that this line is ok
            # fmt: off
            self._display.display("lsrpackages: " + " ".join(sorted(list(packages))))
            # fmt: on
