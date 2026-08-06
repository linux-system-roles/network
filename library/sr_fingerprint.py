#!/usr/bin/python

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: sr_fingerprint
short_description: Write role fingerprint data to syslog and optionally to a JSONL log file
description:
    - Collects role fingerprint data into a canonical record and writes it to
      syslog using Ansible C(module.log) as C(key=value) pairs.
    - Optionally appends the same record as a JSON line to a log file
      (one JSON object per line, JSONL format), by default
      C(/var/log/sysroles.jsonl).
    - Playbook variables are not available inside modules automatically. Roles
      pass C(role_name), C(role_path), C(ansible_play_hosts_all),
      C(distribution), and C(distribution_version) from the task.
    - C(ansible_check_mode) is collected from the module execution context.
    - Intended for role-internal or diagnostic use.
author: Rich Megginson (@richm)
options:
    status:
        description: Role execution status.
        type: str
        required: true
        choices:
            - begin
            - success
    write_log_file:
        description: >-
            If C(true), append fingerprint data to the JSONL log file.
            Defaults to C(false).
        type: bool
        default: false
    log_file:
        description: >-
            Path to the JSONL log file. A lock sidecar (C(<log_file>.lock))
            is created next to the log file for cross-process safety.
        type: path
        default: /var/log/sysroles.jsonl
    max_log_size:
        description: >-
            Maximum log file size in bytes. When appending a new record
            would exceed this limit, the oldest records are removed first.
            Set to C(0) to disable trimming.
        type: int
        default: 2000000
    role_name:
        description: Name of the role, typically C({{ role_name }}).
        type: str
        required: true
    role_path:
        description: Path to the role, typically C({{ role_path }}).
        type: path
        required: true
    ansible_play_hosts_all:
        description: >-
            All hosts in the play, typically C({{ ansible_play_hosts_all }}).
            Used to derive C(play_hosts_number).
        type: list
        elements: str
        required: true
    distribution:
        description: >-
            OS distribution name, typically
            C({{ ansible_facts["distribution"] }}).
        type: str
        default: ""
    distribution_version:
        description: >-
            OS distribution version, typically
            C({{ ansible_facts["distribution_version"] }}).
        type: str
        default: ""
"""

EXAMPLES = """
- name: Record role begin fingerprint to syslog only (not log file)
  sr_fingerprint:
    status: begin
    role_name: bootloader
    role_path: "{{ role_path }}"
    ansible_play_hosts_all: "{{ ansible_play_hosts_all }}"
    distribution: "{{ ansible_facts['distribution'] }}"
    distribution_version: "{{ ansible_facts['distribution_version'] }}"
    write_log_file: false

- name: Record role success fingerprint
  sr_fingerprint:
    status: success
    role_name: bootloader
    role_path: "{{ role_path }}"
    ansible_play_hosts_all: "{{ ansible_play_hosts_all }}"
    distribution: "{{ ansible_facts['distribution'] }}"
    distribution_version: "{{ ansible_facts['distribution_version'] }}"
    write_log_file: true
"""

RETURN = r"""
fingerprint:
    description: The fingerprint record written to syslog and optionally to the log file.
    returned: always
    type: dict
    sample:
        date: "2026-08-03T10:15:00+02:00"
        role_name: network
        role_path: /usr/share/ansible/roles/linux-system-roles.network
        status: success
        ansible_version: "2.16.3"
        managed_node_distro: RedHat-9.4
        play_hosts_number: 3
        ansible_check_mode: false
message:
    description: Informational message shown in check mode.
    returned: check mode
    type: str
    sample: "Check mode: message not logged - [date=... role_name=...]"
jsonl_row:
    description: The JSON line that would be appended to the log file.
    returned: check mode and O(write_log_file=true)
    type: str
log_file:
    description: Path to the log file that would be written.
    returned: check mode and O(write_log_file=true)
    type: str
"""

from ansible.module_utils.basic import AnsibleModule

import datetime
import errno
import fcntl
import json
import os
import stat
import tempfile

FINGERPRINT_FIELDS = (
    "date",
    "role_name",
    "role_path",
    "status",
    "ansible_version",
    "managed_node_distro",
    "play_hosts_number",
    "ansible_check_mode",
)

FINGERPRINT_SYSLOG_SEPARATOR = " "


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


def _ensure_parent_dir(path):
    parent = os.path.dirname(path)
    if not parent:
        return
    if os.path.isdir(parent):
        return
    try:
        os.makedirs(parent)
    except OSError as exc:
        # another process may have created the directory
        if exc.errno != errno.EEXIST or not os.path.isdir(parent):
            raise


def _format_fingerprint_jsonl(record):
    """Format the canonical fingerprint record as a single JSON line."""
    return json.dumps(record, separators=(",", ":"), sort_keys=False)


def _trim_log_file(log_file, size_needed):
    """Remove oldest records until the file can accommodate size_needed bytes."""
    with open(log_file, "r") as log_fd:
        lines = log_fd.readlines()
    size_removed = 0
    while lines and size_removed < size_needed:
        size_removed += len(lines.pop(0))
    orig_stat = os.stat(log_file)
    dir_name = os.path.dirname(log_file) or "."
    fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp")
    try:
        os.fchmod(fd, stat.S_IMODE(orig_stat.st_mode))
        try:
            os.fchown(fd, orig_stat.st_uid, orig_stat.st_gid)
        except OSError:
            # not running as root; keep default ownership
            pass
        with os.fdopen(fd, "w") as tmp_fd:
            tmp_fd.writelines(lines)
            tmp_fd.flush()
            os.fsync(tmp_fd.fileno())
        os.rename(tmp_path, log_file)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            # already removed or never created
            pass
        raise


def _write_jsonl_log(log_file, record, max_size=0):
    _ensure_parent_dir(log_file)
    new_line = _format_fingerprint_jsonl(record) + "\n"
    lock_path = log_file + ".lock"
    lock_fd = open(lock_path, "w")
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        try:
            cur_size = os.path.getsize(log_file)
        except OSError:
            # file does not exist yet
            cur_size = 0
        if max_size > 0 and cur_size + len(new_line) > max_size and cur_size > 0:
            _trim_log_file(log_file, len(new_line))
        with open(log_file, "a") as log_fd:
            log_fd.write(new_line)
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        lock_fd.close()


def _get_managed_node_distro(distribution, distribution_version):
    if distribution and distribution_version:
        return "%s-%s" % (distribution, distribution_version)
    return "unknown"


def _get_play_hosts_number(play_hosts_all):
    return len(play_hosts_all)


def _get_ansible_version(module):
    version = getattr(module, "ansible_version", None)
    if version:
        return version
    return "unknown"


def _get_check_mode(module):
    return bool(getattr(module, "check_mode", False))


def _collect_fingerprint_record(module, status):
    """Build the canonical fingerprint record used by all output formatters."""
    return {
        "date": _local_iso8601_no_microseconds(),
        "role_name": module.params["role_name"],
        "role_path": module.params["role_path"],
        "status": status,
        "ansible_version": _get_ansible_version(module),
        "managed_node_distro": _get_managed_node_distro(
            module.params["distribution"], module.params["distribution_version"]
        ),
        "play_hosts_number": _get_play_hosts_number(
            module.params["ansible_play_hosts_all"]
        ),
        "ansible_check_mode": _get_check_mode(module),
    }


def _fingerprint_record_items(record):
    return [(field, record[field]) for field in FINGERPRINT_FIELDS]


def _format_fingerprint_key_value(field, value):
    text = "" if value is None else str(value)
    if any(char in text for char in ' "='):
        return '%s="%s"' % (field, text.replace('"', '""'))
    return "%s=%s" % (field, text)


def _format_fingerprint_syslog(record):
    """Format the canonical fingerprint record as key=value syslog text."""
    pairs = [
        _format_fingerprint_key_value(field, value)
        for field, value in _fingerprint_record_items(record)
    ]
    return FINGERPRINT_SYSLOG_SEPARATOR.join(pairs)


def _handle_fingerprint(module):
    max_log_size = module.params["max_log_size"]
    if max_log_size < 0:
        module.fail_json(
            msg="max_log_size must be 0 or a positive integer, got %d" % max_log_size
        )

    fingerprint_record = _collect_fingerprint_record(module, module.params["status"])
    log_message = _format_fingerprint_syslog(fingerprint_record)

    if module.check_mode:
        result = dict(
            changed=False,
            message="Check mode: message not logged - [%s]" % log_message,
            fingerprint=fingerprint_record,
        )
        if module.params["write_log_file"]:
            result["jsonl_row"] = _format_fingerprint_jsonl(fingerprint_record)
            result["log_file"] = module.params["log_file"]
        module.exit_json(**result)

    module.log(log_message)

    if module.params["write_log_file"]:
        log_file = module.params["log_file"]
        try:
            _write_jsonl_log(
                log_file, fingerprint_record, module.params["max_log_size"]
            )
        except (IOError, OSError) as exc:
            module.fail_json(
                msg="Failed to write fingerprint log file %s: %s" % (log_file, exc)
            )

    module.exit_json(changed=False, fingerprint=fingerprint_record)


def run_module():
    module_args = dict(
        status=dict(type="str", required=True, choices=["begin", "success"]),
        write_log_file=dict(type="bool", default=False),
        log_file=dict(type="path", default="/var/log/sysroles.jsonl"),
        max_log_size=dict(type="int", default=2000000),
        role_name=dict(type="str", required=True),
        role_path=dict(type="path", required=True),
        ansible_play_hosts_all=dict(type="list", elements="str", required=True),
        distribution=dict(type="str", default=""),
        distribution_version=dict(type="str", default=""),
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
    )

    _handle_fingerprint(module)


def main():
    run_module()


if __name__ == "__main__":
    main()
