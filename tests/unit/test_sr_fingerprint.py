# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Red Hat, Inc.
# SPDX-License-Identifier: MIT
"""Unit tests for sr_fingerprint module helpers."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json
import os
import re
import tempfile
import unittest

import sr_fingerprint


class _ExitJsonException(Exception):
    def __init__(self, kwargs):
        self.kwargs = kwargs


class _FailJsonException(Exception):
    def __init__(self, kwargs):
        self.kwargs = kwargs


class _FakeModule(object):
    ansible_version = "2.16.3"

    def __init__(self, params=None, check_mode=False):
        self.params = params or {}
        self.check_mode = check_mode
        self.logged = []

    def log(self, msg):
        self.logged.append(msg)

    def exit_json(self, **kwargs):
        raise _ExitJsonException(kwargs)

    def fail_json(self, **kwargs):
        raise _FailJsonException(kwargs)


def _cleanup_log(log_file):
    for path in (log_file, log_file + ".lock"):
        try:
            os.unlink(path)
        except OSError:
            # file may not exist
            pass


def _sample_fingerprint_record():
    return {
        "date": "2026-06-10T12:00:00+00:00",
        "role_name": "systemd",
        "role_path": "/usr/share/ansible/roles/linux-system-roles.systemd",
        "status": "begin",
        "ansible_version": "2.16.3",
        "managed_node_distro": "RedHat-9.4",
        "play_hosts_number": 3,
        "ansible_check_mode": False,
    }


class TestSrFingerprint(unittest.TestCase):
    def test_fingerprint_fields_match_record_keys(self):
        record = _sample_fingerprint_record()
        self.assertEqual(set(sr_fingerprint.FINGERPRINT_FIELDS), set(record.keys()))

    def test_format_fingerprint_syslog(self):
        record = _sample_fingerprint_record()
        message = sr_fingerprint._format_fingerprint_syslog(record)
        self.assertEqual(
            message,
            "date=2026-06-10T12:00:00+00:00 role_name=systemd "
            "role_path=/usr/share/ansible/roles/linux-system-roles.systemd status=begin "
            "ansible_version=2.16.3 managed_node_distro=RedHat-9.4 "
            "play_hosts_number=3 ansible_check_mode=False",
        )
        for field in sr_fingerprint.FINGERPRINT_FIELDS:
            self.assertIn("%s=" % field, message)

    def test_format_fingerprint_jsonl(self):
        record = _sample_fingerprint_record()
        line = sr_fingerprint._format_fingerprint_jsonl(record)
        parsed = json.loads(line)
        self.assertEqual(parsed, record)

    def test_collect_fingerprint_record_from_passed_inputs(self):
        module = _FakeModule(
            {
                "role_name": "systemd",
                "role_path": "/usr/share/ansible/roles/linux-system-roles.systemd",
                "ansible_play_hosts_all": ["host1", "host2", "host3"],
                "distribution": "RedHat",
                "distribution_version": "9.4",
            },
            check_mode=True,
        )
        record = sr_fingerprint._collect_fingerprint_record(module, "begin")
        self.assertEqual(record["role_name"], "systemd")
        self.assertEqual(
            record["role_path"], "/usr/share/ansible/roles/linux-system-roles.systemd"
        )
        self.assertEqual(record["managed_node_distro"], "RedHat-9.4")
        self.assertEqual(record["play_hosts_number"], 3)
        self.assertTrue(record["ansible_check_mode"])
        self.assertEqual(
            set(record.keys()),
            set(sr_fingerprint.FINGERPRINT_FIELDS),
        )

    def test_get_managed_node_distro_from_params(self):
        distro = sr_fingerprint._get_managed_node_distro("Fedora", "42")
        self.assertEqual(distro, "Fedora-42")

    def test_get_managed_node_distro_missing(self):
        self.assertEqual(sr_fingerprint._get_managed_node_distro("", ""), "unknown")

    def test_get_play_hosts_number(self):
        self.assertEqual(
            sr_fingerprint._get_play_hosts_number(["a", "b"]),
            2,
        )
        self.assertEqual(sr_fingerprint._get_play_hosts_number([]), 0)

    def test_format_fingerprint_syslog_quotes_values_with_spaces(self):
        record = _sample_fingerprint_record()
        record["role_path"] = (
            "/usr/share/ansible/roles/linux-system-roles.systemd extra"
        )
        message = sr_fingerprint._format_fingerprint_syslog(record)
        self.assertIn(
            'role_path="/usr/share/ansible/roles/linux-system-roles.systemd extra"',
            message,
        )

    def test_write_jsonl_log_appends_valid_json_lines(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".jsonl") as tmp:
            log_file = tmp.name

        try:
            record = _sample_fingerprint_record()
            sr_fingerprint._write_jsonl_log(log_file, record)
            sr_fingerprint._write_jsonl_log(log_file, record)

            with open(log_file, "r") as log_fd:
                lines = log_fd.read().splitlines()

            self.assertEqual(len(lines), 2)
            for line in lines:
                parsed = json.loads(line)
                self.assertEqual(parsed, record)
        finally:
            _cleanup_log(log_file)

    def test_write_jsonl_log_creates_parent_dir(self):
        tmpdir = tempfile.mkdtemp()
        log_file = os.path.join(tmpdir, "subdir", "fingerprint.jsonl")

        try:
            record = _sample_fingerprint_record()
            sr_fingerprint._write_jsonl_log(log_file, record)

            with open(log_file, "r") as log_fd:
                parsed = json.loads(log_fd.readline())
            self.assertEqual(parsed["role_name"], "systemd")
        finally:
            subdir = os.path.dirname(log_file)
            for name in os.listdir(subdir):
                os.unlink(os.path.join(subdir, name))
            os.rmdir(subdir)
            os.rmdir(tmpdir)

    def test_write_jsonl_log_preserves_types(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".jsonl") as tmp:
            log_file = tmp.name

        try:
            record = _sample_fingerprint_record()
            sr_fingerprint._write_jsonl_log(log_file, record)

            with open(log_file, "r") as log_fd:
                parsed = json.loads(log_fd.readline())

            self.assertIsInstance(parsed["play_hosts_number"], int)
            self.assertIsInstance(parsed["ansible_check_mode"], bool)
        finally:
            _cleanup_log(log_file)

    def test_trim_removes_oldest_lines(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".jsonl") as tmp:
            log_file = tmp.name

        try:
            record = _sample_fingerprint_record()
            sample = dict(record, role_name="role_0")
            line_size = len(sr_fingerprint._format_fingerprint_jsonl(sample) + "\n")
            max_size = line_size * 5
            for _i in range(10):
                record_copy = dict(record, role_name="role_%d" % _i)
                sr_fingerprint._write_jsonl_log(
                    log_file, record_copy, max_size=max_size
                )

            with open(log_file, "r") as log_fd:
                lines = log_fd.read().splitlines()

            self.assertEqual(len(lines), 5)
            first = json.loads(lines[0])
            last = json.loads(lines[-1])
            self.assertEqual(first["role_name"], "role_5")
            self.assertEqual(last["role_name"], "role_9")
        finally:
            _cleanup_log(log_file)

    def test_trim_multiple_lines(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".jsonl") as tmp:
            log_file = tmp.name

        try:
            record = _sample_fingerprint_record()
            sample = dict(record, role_name="role_0")
            line_size = len(sr_fingerprint._format_fingerprint_jsonl(sample) + "\n")
            # Log contains more than 3 lines.
            n_initial = 4
            max_size = line_size * n_initial
            for _i in range(n_initial):
                sr_fingerprint._write_jsonl_log(
                    log_file,
                    dict(record, role_name="role_%d" % _i),
                    max_size=max_size,
                )

            with open(log_file, "r") as log_fd:
                initial_lines = log_fd.read().splitlines()
            self.assertEqual(len(initial_lines), n_initial)

            # New record larger than one existing line (up to two) via a very
            # long role_path, so trim removes exactly two oldest records.
            base_record = dict(record, role_name="role_long", role_path="")
            base_size = len(
                sr_fingerprint._format_fingerprint_jsonl(base_record) + "\n"
            )
            path_len = 2 * line_size - base_size
            self.assertGreater(path_len, 0)
            long_path = "x" * path_len
            long_record = dict(record, role_name="role_long", role_path=long_path)
            new_line = sr_fingerprint._format_fingerprint_jsonl(long_record) + "\n"
            self.assertGreater(len(new_line), line_size)
            self.assertLessEqual(len(new_line), 2 * line_size)

            sr_fingerprint._write_jsonl_log(log_file, long_record, max_size=max_size)

            with open(log_file, "r") as log_fd:
                lines = log_fd.read().splitlines()

            # Exactly two oldest records removed; new record appended.
            self.assertEqual(len(lines), n_initial - 2 + 1)
            parsed = [json.loads(line) for line in lines]
            role_names = [entry["role_name"] for entry in parsed]
            self.assertEqual(role_names, ["role_2", "role_3", "role_long"])
            self.assertEqual(parsed[-1], long_record)
            self.assertEqual(parsed[-1]["role_path"], long_path)
            self.assertNotIn("role_0", role_names)
            self.assertNotIn("role_1", role_names)
        finally:
            _cleanup_log(log_file)

    def test_trim_disabled_when_zero(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".jsonl") as tmp:
            log_file = tmp.name

        try:
            record = _sample_fingerprint_record()
            for _i in range(20):
                sr_fingerprint._write_jsonl_log(log_file, record, max_size=0)

            with open(log_file, "r") as log_fd:
                lines = log_fd.read().splitlines()

            self.assertEqual(len(lines), 20)
        finally:
            _cleanup_log(log_file)

    def test_trim_no_op_when_under_limit(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".jsonl") as tmp:
            log_file = tmp.name

        try:
            record = _sample_fingerprint_record()
            for _i in range(3):
                sr_fingerprint._write_jsonl_log(log_file, record, max_size=2000000)

            with open(log_file, "r") as log_fd:
                lines = log_fd.read().splitlines()

            self.assertEqual(len(lines), 3)
        finally:
            _cleanup_log(log_file)

    def test_handle_fingerprint_check_mode_without_log_file(self):
        module = _FakeModule(
            {
                "status": "begin",
                "write_log_file": False,
                "max_log_size": 2000000,
                "role_name": "systemd",
                "role_path": "/usr/share/ansible/roles/linux-system-roles.systemd",
                "ansible_play_hosts_all": ["host1"],
                "distribution": "RedHat",
                "distribution_version": "9.4",
            },
            check_mode=True,
        )
        with self.assertRaises(_ExitJsonException) as ctx:
            sr_fingerprint._handle_fingerprint(module)
        result = ctx.exception.kwargs
        self.assertFalse(result["changed"])
        self.assertIn("Check mode", result["message"])
        self.assertIn("fingerprint", result)
        self.assertNotIn("jsonl_row", result)

    def test_handle_fingerprint_check_mode_with_log_file(self):
        log_path = os.path.join(tempfile.gettempdir(), "test_sr_fingerprint.jsonl")
        module = _FakeModule(
            {
                "status": "success",
                "write_log_file": True,
                "log_file": log_path,
                "max_log_size": 2000000,
                "role_name": "systemd",
                "role_path": "/usr/share/ansible/roles/linux-system-roles.systemd",
                "ansible_play_hosts_all": ["host1"],
                "distribution": "RedHat",
                "distribution_version": "9.4",
            },
            check_mode=True,
        )
        with self.assertRaises(_ExitJsonException) as ctx:
            sr_fingerprint._handle_fingerprint(module)
        result = ctx.exception.kwargs
        self.assertIn("jsonl_row", result)
        self.assertEqual(result["log_file"], log_path)
        parsed = json.loads(result["jsonl_row"])
        self.assertEqual(parsed["role_name"], "systemd")

    def test_handle_fingerprint_write_failure_calls_fail_json(self):
        log_path = os.path.join(tempfile.gettempdir(), "test_write_fail.jsonl")
        module = _FakeModule(
            {
                "status": "success",
                "write_log_file": True,
                "log_file": log_path,
                "max_log_size": 2000000,
                "role_name": "systemd",
                "role_path": "/usr/share/ansible/roles/linux-system-roles.systemd",
                "ansible_play_hosts_all": ["host1"],
                "distribution": "RedHat",
                "distribution_version": "9.4",
            },
            check_mode=False,
        )
        original = sr_fingerprint._write_jsonl_log

        def _raise_ioerror(*args, **kwargs):
            raise IOError("disk full")

        sr_fingerprint._write_jsonl_log = _raise_ioerror
        try:
            with self.assertRaises(_FailJsonException) as ctx:
                sr_fingerprint._handle_fingerprint(module)
            self.assertIn(
                "Failed to write fingerprint log file", ctx.exception.kwargs["msg"]
            )
        finally:
            sr_fingerprint._write_jsonl_log = original

    def test_handle_fingerprint_rejects_negative_max_log_size(self):
        module = _FakeModule(
            {
                "status": "begin",
                "write_log_file": False,
                "max_log_size": -1,
                "role_name": "systemd",
                "role_path": "/usr/share/ansible/roles/linux-system-roles.systemd",
                "ansible_play_hosts_all": ["host1"],
                "distribution": "RedHat",
                "distribution_version": "9.4",
            },
            check_mode=False,
        )
        with self.assertRaises(_FailJsonException) as ctx:
            sr_fingerprint._handle_fingerprint(module)
        self.assertIn(
            "max_log_size must be 0 or a positive integer",
            ctx.exception.kwargs["msg"],
        )

    def test_local_iso8601_no_microseconds_has_no_fraction(self):
        timestamp = sr_fingerprint._local_iso8601_no_microseconds()
        match = re.match(
            r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:?\d{2}$", timestamp
        )
        self.assertIsNotNone(match)


if __name__ == "__main__":
    unittest.main()
