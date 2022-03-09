# -*- coding: utf-8 -*
# SPDX-License-Identifier: BSD-3-Clause
import logging
import os
import subprocess

import pytest

try:
    from unittest import mock
except ImportError:
    import mock

parent_dir = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))

with mock.patch.dict(
    "sys.modules",
    {
        "ansible.module_utils.basic": mock.Mock(),
    },
):
    import network_connections as nc


class PytestRunEnvironment(nc.RunEnvironment):
    def log(self, connections, idx, severity, msg, **kwargs):
        if severity == nc.LogLevel.ERROR:
            logging.error("Error: %s", connections[idx])
            raise RuntimeError(msg)
        else:
            logging.debug("Log: %s", connections[idx])

    def run_command(self, argv, encoding=None):
        command = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        return_code = command.wait()
        out, err = command.communicate()
        return return_code, out.decode("utf-8"), err.decode("utf-8")

    def _check_mode_changed(self, *args, **kwargs):
        pass


def _configure_network(connections, provider):
    cmd = nc.Cmd.create(
        provider,
        run_env=PytestRunEnvironment(),
        connections_unvalidated=connections,
        connection_validator=nc.ArgValidator_ListConnections(),
    )
    cmd.run()


@pytest.fixture(scope="session")
def provider(request):
    return request.config.getoption("--provider")


@pytest.fixture
def testnic1():
    veth_name = "testeth"
    try:
        subprocess.call(
            [
                "ip",
                "link",
                "add",
                veth_name,
                "type",
                "veth",
                "peer",
                "name",
                veth_name + "peer",
            ],
            close_fds=True,
        )
        yield veth_name
    finally:
        subprocess.call(["ip", "link", "delete", veth_name])
        if os.path.isfile("/etc/sysconfig/network-scripts/ifcfg-" + veth_name):
            os.unlink("/etc/sysconfig/network-scripts/ifcfg-" + veth_name)
            subprocess.call(
                [
                    "nmcli",
                    "con",
                    "reload",
                ]
            )


def _get_ip_addresses(interface):
    ip_address = subprocess.check_output(["ip", "address", "show", interface])
    return ip_address.decode("UTF-8")


@pytest.fixture
def network_lsr_nm_mock():
    with mock.patch.dict(
        "sys.modules",
        {
            "ansible.module_utils.basic": mock.Mock(),
        },
    ):
        yield


def test_static_ip_with_ethernet(testnic1, provider, network_lsr_nm_mock):
    ip_address = "192.0.2.127/24"
    connections = [
        {
            "name": testnic1,
            "type": "ethernet",
            "state": "up",
            "ip": {"address": [ip_address]},
        }
    ]
    _configure_network(connections, provider)
    assert ip_address in _get_ip_addresses(testnic1)
    if provider == "initscripts":
        assert os.path.exists("/etc/sysconfig/network-scripts/ifcfg-" + testnic1)
    else:
        subprocess.check_call(["nmcli", "connection", "show", testnic1])
