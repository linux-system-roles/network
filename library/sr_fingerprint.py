#!/usr/bin/python

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: sr_fingerprint
short_description: Write a message string to syslog using Ansible C(module.log) function.
description:
    - Writes the given string to the system log using Ansible C(module.log) function.
    - Intended for role-internal or diagnostic use.
author: Rich Megginson (@richm)
options:
    sr_message:
        description: Text to record in syslog.
        type: str
        required: true
"""

EXAMPLES = """
- name: Record a fingerprint message in syslog
  sr_fingerprint:
    sr_message: "system_role:ROLENAME"
"""

RETURN = r""" # """

from ansible.module_utils.basic import AnsibleModule

import datetime


def _local_iso8601_no_microseconds():
    """System local wall clock with local tz offset, ISO 8601, seconds only."""
    try:
        utc = datetime.timezone.utc
    except AttributeError:
        import time

        return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime())
    # Prefer the local clock interpreted in the system timezone (not UTC displayed).
    now = datetime.datetime.now()
    astimezone = getattr(now, "astimezone", None)
    if astimezone is not None:
        try:
            return astimezone().replace(microsecond=0).isoformat()
        except (OSError, TypeError, ValueError):
            pass
    return datetime.datetime.now(utc).astimezone().replace(microsecond=0).isoformat()


def run_module():
    module_args = dict(
        sr_message=dict(type="str", required=True),
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
    )

    log_message = "%s %s" % (
        module.params["sr_message"],
        _local_iso8601_no_microseconds(),
    )

    if module.check_mode:
        module.exit_json(
            changed=False,
            message="Check mode: message not logged - [%s]" % log_message,
        )

    module.log(log_message)

    # we don't actually change anything, so we're not changed - writing a log message
    # is not considered a change
    # also, we don't want to report changed every time the role runs
    module.exit_json(changed=False)


def main():
    run_module()


if __name__ == "__main__":
    main()
