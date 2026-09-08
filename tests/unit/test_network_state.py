# -*- coding: utf-8 -*-
# SPDX-License-Identifier: BSD-3-Clause
"""Unit tests for network_state module helpers."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os
import shutil
import sys
import tempfile
import unittest

try:
    from unittest import mock
except ImportError:  # py2
    import mock

sys.modules["ansible.module_utils.basic"] = mock.Mock()
sys.modules["libnmstate"] = mock.Mock()

# pylint: disable=import-error, wrong-import-position

import network_state


class _FailJson(Exception):
    """Raised by the mocked fail_json to stop the module."""


class TestNmGlobalDnsConfig(unittest.TestCase):
    """Tests for the NetworkManager global DNS config check."""

    def setUp(self):
        """Point the module at a temporary NetworkManager config tree."""
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        self.config_file = os.path.join(self.root, "NetworkManager.conf")
        self.dirs = [os.path.join(self.root, d) for d in ("lib", "run", "etc")]
        for d in self.dirs:
            os.mkdir(d)
        self._write(self.config_file, "[main]\nplugins=keyfile\n")
        for name, value in (
            ("NM_CONFIG_FILE", self.config_file),
            ("NM_CONFIG_DIRS", self.dirs),
        ):
            patcher = mock.patch.object(network_state, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.libnmstate = network_state.libnmstate
        self.libnmstate.reset_mock()
        self.module = mock.Mock()
        self.module.fail_json.side_effect = _FailJson

    def _write(self, path, content, mode="w"):
        """Write content to path."""
        with open(path, mode) as f:
            f.write(content)

    def _find(self):
        """Run find_nm_global_dns_config against the temporary tree."""
        return network_state.find_nm_global_dns_config()

    def _run(self, desired_state):
        """Run NetworkState.run with desired_state and the mocked module."""
        self.module.params = {"desired_state": desired_state}
        network_state.NetworkState(self.module, "network_state").run()

    def test_no_global_dns(self):
        """No files match without a global-dns section."""
        self._write(os.path.join(self.dirs[2], "10-logging.conf"), "[logging]\n")
        self.assertEqual(self._find(), [])

    def test_global_dns_in_main_file(self):
        """NetworkManager.conf itself is reported."""
        self._write(self.config_file, "[main]\n[global-dns]\noptions=no-aaaa\n")
        self.assertEqual(self._find(), [self.config_file])

    def test_global_dns_in_snippet(self):
        """A conf.d snippet is reported."""
        path = os.path.join(self.dirs[2], "90-dns-servers.conf")
        self._write(path, "[global-dns]\noptions=no-aaaa\n")
        self.assertEqual(self._find(), [path])

    def test_global_dns_domain_section(self):
        """global-dns-domain-* sections count as global DNS."""
        path = os.path.join(self.dirs[1], "50-dns.conf")
        self._write(path, "[global-dns-domain-example.com]\nservers=192.0.2.1\n")
        self.assertEqual(self._find(), [path])

    def test_similar_section_name_ignored(self):
        """Sections merely starting with global-dns do not match."""
        self._write(os.path.join(self.dirs[2], "x.conf"), "[global-dnsfoo]\n")
        self.assertEqual(self._find(), [])

    def test_intern_section_ignored(self):
        """D-Bus-written [.intern.global-dns] groups do not match."""
        path = os.path.join(self.dirs[2], "intern.conf")
        self._write(path, "[.intern.global-dns]\nsearches=example.com\n")
        self.assertEqual(self._find(), [])

    def test_shadowed_snippet_ignored(self):
        """A same-named snippet in a later dir hides the earlier one."""
        self._write(
            os.path.join(self.dirs[0], "dns.conf"), "[global-dns]\noptions=no-aaaa\n"
        )
        self._write(os.path.join(self.dirs[2], "dns.conf"), "[main]\n")
        self.assertEqual(self._find(), [])

    def test_non_utf8_content(self):
        """Non-UTF-8 bytes in a config file do not break matching."""
        path = os.path.join(self.dirs[2], "dns.conf")
        self._write(path, b"# \xff\n[global-dns]\n", "wb")
        self.assertEqual(self._find(), [path])

    def test_missing_files_skipped(self):
        """A missing config file is skipped."""
        os.remove(self.config_file)
        self.assertEqual(self._find(), [])

    def test_run_rejects_dns_resolver_with_global_dns(self):
        """run fails before apply when global DNS is configured."""
        self._write(self.config_file, "[global-dns]\n")
        with self.assertRaises(_FailJson):
            self._run({"dns-resolver": {"config": {}}})
        self.assertFalse(self.libnmstate.apply.called)

    def test_run_applies_dns_resolver_without_global_dns(self):
        """run applies dns-resolver when no global DNS is configured."""
        self._run({"dns-resolver": {"config": {}}})
        self.libnmstate.apply.assert_called_once_with({"dns-resolver": {"config": {}}})

    def test_run_ignores_global_dns_without_dns_resolver(self):
        """run applies states without dns-resolver regardless of global DNS."""
        self._write(self.config_file, "[global-dns]\n")
        self._run({"interfaces": []})
        self.assertTrue(self.libnmstate.apply.called)


if __name__ == "__main__":
    unittest.main()
