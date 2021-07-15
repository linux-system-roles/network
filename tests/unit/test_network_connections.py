#!/usr/bin/env python
""" Tests for network_connections Ansible module """
# SPDX-License-Identifier: BSD-3-Clause
import copy
import itertools
import os
import pprint as pprint_
import socket
import sys
import unittest

try:
    from unittest import mock
except ImportError:  # py2
    import mock

sys.modules["ansible.module_utils.basic"] = mock.Mock()

try:
    import network_lsr
except ImportError:
    sys.path.append(os.path.join(os.path.dirname(__file__), "fake_env"))
    import network_lsr

import network_lsr.argument_validator
from network_connections import IfcfgUtil, NMUtil, SysUtil, Util
from network_lsr.argument_validator import ValidationError

try:
    my_test_skipIf = unittest.skipIf
except AttributeError:
    # python 2.6 workaround
    def my_test_skipIf(condition, reason):
        if condition:
            return lambda x: None
        else:
            return lambda x: x


try:
    nmutil = NMUtil()
    assert nmutil
except Exception:
    # NMUtil is not supported, for example on RHEL 6 or without
    # pygobject.
    nmutil = None

if nmutil:
    NM = Util.NM()
    GObject = Util.GObject()


def pprint(msg, obj):
    print("PRINT: %s\n" % (msg))

    p = pprint_.PrettyPrinter(indent=4)
    p.pprint(obj)
    if nmutil is not None and isinstance(obj, NM.Connection):
        obj.dump()


ARGS_CONNECTIONS = network_lsr.argument_validator.ArgValidator_ListConnections()
VALIDATE_ONE_MODE_INITSCRIPTS = ARGS_CONNECTIONS.VALIDATE_ONE_MODE_INITSCRIPTS
VALIDATE_ONE_MODE_NM = ARGS_CONNECTIONS.VALIDATE_ONE_MODE_NM

ETHTOOL_FEATURES_DEFAULTS = {
    "esp_hw_offload": None,
    "esp_tx_csum_hw_offload": None,
    "fcoe_mtu": None,
    "gro": None,
    "gso": None,
    "highdma": None,
    "hw_tc_offload": None,
    "l2_fwd_offload": None,
    "loopback": None,
    "lro": None,
    "ntuple": None,
    "rx": None,
    "rx_all": None,
    "rx_fcs": None,
    "rx_gro_hw": None,
    "rx_udp_tunnel_port_offload": None,
    "rx_vlan_filter": None,
    "rx_vlan_stag_filter": None,
    "rx_vlan_stag_hw_parse": None,
    "rxhash": None,
    "rxvlan": None,
    "sg": None,
    "tls_hw_record": None,
    "tls_hw_tx_offload": None,
    "tso": None,
    "tx": None,
    "tx_checksum_fcoe_crc": None,
    "tx_checksum_ip_generic": None,
    "tx_checksum_ipv4": None,
    "tx_checksum_ipv6": None,
    "tx_checksum_sctp": None,
    "tx_esp_segmentation": None,
    "tx_fcoe_segmentation": None,
    "tx_gre_csum_segmentation": None,
    "tx_gre_segmentation": None,
    "tx_gso_partial": None,
    "tx_gso_robust": None,
    "tx_ipxip4_segmentation": None,
    "tx_ipxip6_segmentation": None,
    "tx_nocache_copy": None,
    "tx_scatter_gather": None,
    "tx_scatter_gather_fraglist": None,
    "tx_sctp_segmentation": None,
    "tx_tcp_ecn_segmentation": None,
    "tx_tcp_mangleid_segmentation": None,
    "tx_tcp_segmentation": None,
    "tx_tcp6_segmentation": None,
    "tx_udp_segmentation": None,
    "tx_udp_tnl_csum_segmentation": None,
    "tx_udp_tnl_segmentation": None,
    "tx_vlan_stag_hw_insert": None,
    "txvlan": None,
}


ETHTOOL_COALESCE_DEFAULTS = {
    "adaptive_rx": None,
    "adaptive_tx": None,
    "pkt_rate_high": None,
    "pkt_rate_low": None,
    "rx_frames": None,
    "rx_frames_high": None,
    "rx_frames_irq": None,
    "rx_frames_low": None,
    "rx_usecs": None,
    "rx_usecs_high": None,
    "rx_usecs_irq": None,
    "rx_usecs_low": None,
    "sample_interval": None,
    "stats_block_usecs": None,
    "tx_frames": None,
    "tx_frames_high": None,
    "tx_frames_irq": None,
    "tx_frames_low": None,
    "tx_usecs": None,
    "tx_usecs_high": None,
    "tx_usecs_irq": None,
    "tx_usecs_low": None,
}

ETHTOOL_RING_DEFAULTS = {
    "rx": None,
    "rx_jumbo": None,
    "rx_mini": None,
    "tx": None,
}


ETHTOOL_DEFAULTS = {
    "features": ETHTOOL_FEATURES_DEFAULTS,
    "coalesce": ETHTOOL_COALESCE_DEFAULTS,
    "ring": ETHTOOL_RING_DEFAULTS,
}

ETHERNET_DEFAULTS = {"autoneg": None, "duplex": None, "speed": 0}


class TestValidator(unittest.TestCase):
    def setUp(self):
        # default values when "type" is specified and state is not
        self.default_connection_settings = {
            "autoconnect": True,
            "check_iface_exists": True,
            "ethernet": ETHERNET_DEFAULTS,
            "ethtool": ETHTOOL_DEFAULTS,
            "ignore_errors": None,
            "ip": {
                "gateway6": None,
                "gateway4": None,
                "route_metric4": None,
                "auto6": True,
                "ipv6_disabled": False,
                "dhcp4": True,
                "address": [],
                "auto_gateway": None,
                "route_append_only": False,
                "rule_append_only": False,
                "route": [],
                "route_metric6": None,
                "dhcp4_send_hostname": None,
                "dns": [],
                "dns_options": [],
                "dns_search": [],
            },
            "mac": None,
            "controller": None,
            "ieee802_1x": None,
            "wireless": None,
            "mtu": None,
            "name": "5",
            "parent": None,
            "port_type": None,
            "zone": None,
        }

    def assertValidationError(self, v, value):
        self.assertRaises(ValidationError, v.validate, value)

    def assert_nm_connection_routes_expected(self, connection, route_list_expected):
        parser = network_lsr.argument_validator.ArgValidatorIPRoute("route[?]")
        route_list_exp = [parser.validate(r) for r in route_list_expected]
        route_list_new = itertools.chain(
            nmutil.setting_ip_config_get_routes(
                connection.get_setting(NM.SettingIP4Config)
            ),
            nmutil.setting_ip_config_get_routes(
                connection.get_setting(NM.SettingIP6Config)
            ),
        )
        route_list_new = [
            {
                "family": r.get_family(),
                "network": r.get_dest(),
                "prefix": int(r.get_prefix()),
                "gateway": r.get_next_hop(),
                "metric": int(r.get_metric()),
            }
            for r in route_list_new
        ]
        self.assertEqual(route_list_exp, route_list_new)

    def do_connections_check_invalid(self, input_connections):
        self.assertValidationError(ARGS_CONNECTIONS, input_connections)

    def do_connections_validate_nm(self, input_connections, **kwargs):
        if not nmutil:
            return
        connections = ARGS_CONNECTIONS.validate(input_connections)
        for connection in connections:
            if "type" in connection:
                connection["nm.exists"] = False
                connection["nm.uuid"] = Util.create_uuid()

        mode = VALIDATE_ONE_MODE_NM
        for idx, connection in enumerate(connections):
            try:
                ARGS_CONNECTIONS.validate_connection_one(mode, connections, idx)
            except ValidationError:
                continue
            if "type" in connection:
                con_new = nmutil.connection_create(connections, idx)
                self.assertTrue(con_new)
                self.assertTrue(con_new.verify())
                if "nm_route_list_current" in kwargs:
                    parser = network_lsr.argument_validator.ArgValidatorIPRoute(
                        "route[?]"
                    )
                    s4 = con_new.get_setting(NM.SettingIP4Config)
                    s6 = con_new.get_setting(NM.SettingIP6Config)
                    s4.clear_routes()
                    s6.clear_routes()
                    for r in kwargs["nm_route_list_current"][idx]:
                        r = parser.validate(r)
                        r = NM.IPRoute.new(
                            r["family"],
                            r["network"],
                            r["prefix"],
                            r["gateway"],
                            r["metric"],
                        )
                        if r.get_family() == socket.AF_INET:
                            s4.add_route(r)
                        else:
                            s6.add_route(r)
                    con_new = nmutil.connection_create(
                        connections, idx, connection_current=con_new
                    )
                    self.assertTrue(con_new)
                    self.assertTrue(con_new.verify())
                if "nm_route_list_expected" in kwargs:
                    self.assert_nm_connection_routes_expected(
                        con_new, kwargs["nm_route_list_expected"][idx]
                    )

    def do_connections_validate_ifcfg(self, input_connections, **kwargs):
        mode = VALIDATE_ONE_MODE_INITSCRIPTS
        connections = ARGS_CONNECTIONS.validate(input_connections)
        for idx, connection in enumerate(connections):
            try:
                ARGS_CONNECTIONS.validate_connection_one(mode, connections, idx)
            except ValidationError:
                continue
            if "type" not in connection:
                continue
            if (
                connection["type"] in ["macvlan", "wireless"]
                or connection["ieee802_1x"]
            ):
                # initscripts do not support this type. Skip the test.
                continue
            content_current = kwargs.get("initscripts_content_current", None)
            if content_current:
                content_current = content_current[idx]
            c = IfcfgUtil.ifcfg_create(
                connections, idx, content_current=content_current
            )
            # pprint("con[%s] = \"%s\"" % (idx, connections[idx]['name']), c)
            exp = kwargs.get("initscripts_dict_expected", None)
            if exp is not None:
                self.assertEqual(exp[idx], c)

    def do_connections_validate(
        self, expected_connections, input_connections, **kwargs
    ):
        connections = ARGS_CONNECTIONS.validate(input_connections)
        self.assertEqual(expected_connections, connections)
        self.do_connections_validate_nm(input_connections, **kwargs)
        self.do_connections_validate_ifcfg(input_connections, **kwargs)

    def test_validate_str(self):

        v = network_lsr.argument_validator.ArgValidatorStr("state")
        self.assertEqual("a", v.validate("a"))
        self.assertValidationError(v, 1)
        self.assertValidationError(v, None)

        v = network_lsr.argument_validator.ArgValidatorStr("state", required=True)
        self.assertValidationError(v, None)

        v = network_lsr.argument_validator.ArgValidatorStr(
            "test_max_length", max_length=13
        )
        self.assertEqual("less_than_13", v.validate("less_than_13"))
        self.assertValidationError(v, "longer_than_13")

        v = network_lsr.argument_validator.ArgValidatorStr(
            "test_min_length", min_length=13
        )
        self.assertEqual("longer_than_13", v.validate("longer_than_13"))
        self.assertValidationError(v, "less_than_13")

        v = network_lsr.argument_validator.ArgValidatorStr(
            "test_min_max_length", min_length=10, max_length=15
        )
        self.assertEqual("13_characters", v.validate("13_characters"))
        self.assertValidationError(v, "too_short")
        self.assertValidationError(v, "string_is_too_long")

        self.assertRaises(
            ValueError,
            network_lsr.argument_validator.ArgValidatorStr,
            "non_int",
            min_length="string",
        )
        self.assertRaises(
            ValueError,
            network_lsr.argument_validator.ArgValidatorStr,
            "non_int",
            max_length="string",
        )
        self.assertRaises(
            ValueError,
            network_lsr.argument_validator.ArgValidatorStr,
            "negative_int",
            min_length=-5,
        )
        self.assertRaises(
            ValueError,
            network_lsr.argument_validator.ArgValidatorStr,
            "negative_int",
            max_length=-5,
        )

    def test_validate_int(self):

        v = network_lsr.argument_validator.ArgValidatorNum(
            "state", default_value=None, numeric_type=float
        )
        self.assertEqual(1, v.validate(1))
        self.assertEqual(1.5, v.validate(1.5))
        self.assertEqual(1.5, v.validate("1.5"))
        self.assertValidationError(v, None)
        self.assertValidationError(v, "1a")

        v = network_lsr.argument_validator.ArgValidatorNum("state", default_value=None)
        self.assertEqual(1, v.validate(1))
        self.assertEqual(1, v.validate(1.0))
        self.assertEqual(1, v.validate("1"))
        self.assertValidationError(v, None)
        self.assertValidationError(v, None)
        self.assertValidationError(v, 1.5)
        self.assertValidationError(v, "1.5")

        v = network_lsr.argument_validator.ArgValidatorNum("state", required=True)
        self.assertValidationError(v, None)
        self.assertValidationError(v, False)
        self.assertValidationError(v, True)

    def test_validate_bool(self):

        v = network_lsr.argument_validator.ArgValidatorBool("state")
        self.assertEqual(True, v.validate("yes"))
        self.assertEqual(True, v.validate("yeS"))
        self.assertEqual(True, v.validate("Y"))
        self.assertEqual(True, v.validate(True))
        self.assertEqual(True, v.validate("True"))
        self.assertEqual(True, v.validate("1"))
        self.assertEqual(True, v.validate(1))

        self.assertEqual(False, v.validate("no"))
        self.assertEqual(False, v.validate("nO"))
        self.assertEqual(False, v.validate("N"))
        self.assertEqual(False, v.validate(False))
        self.assertEqual(False, v.validate("False"))
        self.assertEqual(False, v.validate("0"))
        self.assertEqual(False, v.validate(0))

        self.assertValidationError(v, 2)
        self.assertValidationError(v, -1)
        self.assertValidationError(v, "Ye")
        self.assertValidationError(v, "")
        self.assertValidationError(v, None)
        v = network_lsr.argument_validator.ArgValidatorBool("state", required=True)
        self.assertValidationError(v, None)

    def test_validate_dict(self):

        v = network_lsr.argument_validator.ArgValidatorDict(
            "dict",
            nested=[
                network_lsr.argument_validator.ArgValidatorNum("i", required=True),
                network_lsr.argument_validator.ArgValidatorStr(
                    "s", required=False, default_value="s_default"
                ),
                network_lsr.argument_validator.ArgValidatorStr(
                    "l",
                    required=False,
                    default_value=network_lsr.argument_validator.ArgValidator.MISSING,
                ),
            ],
        )

        self.assertEqual({"i": 5, "s": "s_default"}, v.validate({"i": "5"}))
        self.assertEqual(
            {"i": 5, "s": "s_default", "l": "6"}, v.validate({"i": "5", "l": "6"})
        )
        self.assertValidationError(v, {"k": 1})

    def test_validate_list(self):

        v = network_lsr.argument_validator.ArgValidatorList(
            "list", nested=network_lsr.argument_validator.ArgValidatorNum("i")
        )
        self.assertEqual([1, 5], v.validate(["1", 5]))
        self.assertValidationError(v, [1, "s"])

    def test_empty(self):
        self.maxDiff = None
        self.do_connections_validate([], [])

    def test_ethernet_two_defaults(self):
        self.maxDiff = None
        self.do_connections_validate(
            [
                {
                    "actions": ["present"],
                    "autoconnect": True,
                    "check_iface_exists": True,
                    "ethernet": ETHERNET_DEFAULTS,
                    "ethtool": ETHTOOL_DEFAULTS,
                    "ignore_errors": None,
                    "interface_name": "5",
                    "ip": {
                        "gateway6": None,
                        "gateway4": None,
                        "route_metric4": None,
                        "auto6": True,
                        "ipv6_disabled": False,
                        "dhcp4": True,
                        "address": [],
                        "auto_gateway": None,
                        "route_append_only": False,
                        "rule_append_only": False,
                        "route": [],
                        "route_metric6": None,
                        "dhcp4_send_hostname": None,
                        "dns": [],
                        "dns_options": [],
                        "dns_search": [],
                    },
                    "mac": None,
                    "controller": None,
                    "ieee802_1x": None,
                    "wireless": None,
                    "mtu": None,
                    "name": "5",
                    "parent": None,
                    "persistent_state": "present",
                    "port_type": None,
                    "state": None,
                    "type": "ethernet",
                    "zone": None,
                },
                {
                    "actions": ["present"],
                    "ignore_errors": None,
                    "name": "5",
                    "persistent_state": "present",
                    "state": None,
                },
            ],
            [{"name": "5", "type": "ethernet"}, {"name": "5"}],
        )

    def test_up_ethernet(self):
        self.maxDiff = None
        self.do_connections_validate(
            [
                {
                    "actions": ["present", "up"],
                    "autoconnect": True,
                    "check_iface_exists": True,
                    "ethernet": ETHERNET_DEFAULTS,
                    "ethtool": ETHTOOL_DEFAULTS,
                    "force_state_change": None,
                    "ignore_errors": None,
                    "interface_name": "5",
                    "ip": {
                        "gateway6": None,
                        "gateway4": None,
                        "route_metric4": None,
                        "auto6": True,
                        "ipv6_disabled": False,
                        "dhcp4": True,
                        "address": [],
                        "auto_gateway": None,
                        "route_append_only": False,
                        "rule_append_only": False,
                        "route": [],
                        "dns": [],
                        "dns_options": [],
                        "dns_search": [],
                        "route_metric6": None,
                        "dhcp4_send_hostname": None,
                    },
                    "mac": None,
                    "controller": None,
                    "ieee802_1x": None,
                    "wireless": None,
                    "mtu": None,
                    "name": "5",
                    "parent": None,
                    "persistent_state": "present",
                    "port_type": None,
                    "state": "up",
                    "type": "ethernet",
                    "wait": None,
                    "zone": None,
                }
            ],
            [{"name": "5", "state": "up", "type": "ethernet"}],
        )

    def test_up_ethernet_no_autoconnect(self):
        self.maxDiff = None
        self.do_connections_validate(
            [
                {
                    "actions": ["present", "up"],
                    "autoconnect": False,
                    "check_iface_exists": True,
                    "ethernet": ETHERNET_DEFAULTS,
                    "ethtool": ETHTOOL_DEFAULTS,
                    "force_state_change": None,
                    "ignore_errors": None,
                    "interface_name": "5",
                    "ip": {
                        "gateway6": None,
                        "gateway4": None,
                        "route_metric4": None,
                        "auto6": True,
                        "ipv6_disabled": False,
                        "dhcp4": True,
                        "address": [],
                        "auto_gateway": None,
                        "route_append_only": False,
                        "rule_append_only": False,
                        "route": [],
                        "dns": [],
                        "dns_options": [],
                        "dns_search": [],
                        "route_metric6": None,
                        "dhcp4_send_hostname": None,
                    },
                    "mac": None,
                    "controller": None,
                    "ieee802_1x": None,
                    "wireless": None,
                    "mtu": None,
                    "name": "5",
                    "parent": None,
                    "persistent_state": "present",
                    "port_type": None,
                    "state": "up",
                    "type": "ethernet",
                    "wait": None,
                    "zone": None,
                }
            ],
            [{"name": "5", "state": "up", "type": "ethernet", "autoconnect": "no"}],
            initscripts_dict_expected=[
                {
                    "ifcfg": {
                        "BOOTPROTO": "dhcp",
                        "IPV6INIT": "yes",
                        "IPV6_AUTOCONF": "yes",
                        "NM_CONTROLLED": "no",
                        "ONBOOT": "no",
                        "TYPE": "Ethernet",
                        "DEVICE": "5",
                    },
                    "keys": None,
                    "route": None,
                    "route6": None,
                    "rule": None,
                    "rule6": None,
                }
            ],
        )

    def test_invalid_autoconnect(self):
        self.maxDiff = None
        self.do_connections_check_invalid([{"name": "a", "autoconnect": True}])

    def test_absent(self):
        self.maxDiff = None
        self.do_connections_validate(
            [
                {
                    "actions": ["absent"],
                    "ignore_errors": None,
                    "name": "5",
                    "persistent_state": "absent",
                    "state": None,
                }
            ],
            [{"name": "5", "persistent_state": "absent"}],
        )

    def test_up_ethernet_mac_mtu_static_ip(self):
        self.maxDiff = None
        self.do_connections_validate(
            [
                {
                    "actions": ["present", "up"],
                    "autoconnect": True,
                    "check_iface_exists": True,
                    "ethernet": ETHERNET_DEFAULTS,
                    "ethtool": ETHTOOL_DEFAULTS,
                    "force_state_change": None,
                    "ignore_errors": None,
                    "interface_name": None,
                    "ip": {
                        "dhcp4": False,
                        "route_metric6": None,
                        "route_metric4": None,
                        "dns_options": [],
                        "dns_search": [],
                        "dhcp4_send_hostname": None,
                        "gateway6": None,
                        "gateway4": None,
                        "auto6": True,
                        "ipv6_disabled": False,
                        "dns": [],
                        "address": [
                            {
                                "prefix": 24,
                                "family": socket.AF_INET,
                                "address": "192.168.174.5",
                            }
                        ],
                        "auto_gateway": None,
                        "route_append_only": False,
                        "rule_append_only": False,
                        "route": [],
                    },
                    "mac": "52:54:00:44:9f:ba",
                    "controller": None,
                    "ieee802_1x": None,
                    "wireless": None,
                    "mtu": 1450,
                    "name": "prod1",
                    "parent": None,
                    "persistent_state": "present",
                    "port_type": None,
                    "state": "up",
                    "type": "ethernet",
                    "wait": None,
                    "zone": None,
                }
            ],
            [
                {
                    "name": "prod1",
                    "state": "up",
                    "type": "ethernet",
                    "autoconnect": "yes",
                    "mac": "52:54:00:44:9f:ba",
                    "mtu": 1450,
                    "ip": {"address": "192.168.174.5/24"},
                }
            ],
        )

    def test_up_single_v4_dns(self):
        self.maxDiff = None
        # set single IPv4 DNS server
        self.do_connections_validate(
            [
                {
                    "actions": ["present", "up"],
                    "autoconnect": True,
                    "check_iface_exists": True,
                    "ethernet": ETHERNET_DEFAULTS,
                    "ethtool": ETHTOOL_DEFAULTS,
                    "force_state_change": None,
                    "ignore_errors": None,
                    "interface_name": "prod1",
                    "ip": {
                        "dhcp4": False,
                        "route_metric6": None,
                        "route_metric4": None,
                        "dns_options": [],
                        "dns_search": [],
                        "dhcp4_send_hostname": None,
                        "gateway6": None,
                        "gateway4": None,
                        "auto6": True,
                        "ipv6_disabled": False,
                        "dns": [{"address": "192.168.174.1", "family": socket.AF_INET}],
                        "address": [
                            {
                                "prefix": 24,
                                "family": socket.AF_INET,
                                "address": "192.168.174.5",
                            }
                        ],
                        "auto_gateway": None,
                        "route_append_only": False,
                        "rule_append_only": False,
                        "route": [],
                    },
                    "mac": None,
                    "controller": None,
                    "ieee802_1x": None,
                    "wireless": None,
                    "mtu": None,
                    "name": "prod1",
                    "parent": None,
                    "persistent_state": "present",
                    "port_type": None,
                    "state": "up",
                    "type": "ethernet",
                    "wait": None,
                    "zone": None,
                }
            ],
            [
                {
                    "name": "prod1",
                    "state": "up",
                    "type": "ethernet",
                    "autoconnect": "yes",
                    "ip": {"address": "192.168.174.5/24", "dns": "192.168.174.1"},
                }
            ],
        )

    def test_ipv6_static(self):
        self.maxDiff = None
        self.do_connections_validate(
            [
                {
                    "actions": ["present", "up"],
                    "autoconnect": True,
                    "check_iface_exists": True,
                    "ethernet": ETHERNET_DEFAULTS,
                    "ethtool": ETHTOOL_DEFAULTS,
                    "force_state_change": None,
                    "ignore_errors": None,
                    "interface_name": "prod1",
                    "ip": {
                        "gateway6": "2001:db8::1",
                        "gateway4": None,
                        "route_metric4": None,
                        "auto6": False,
                        "ipv6_disabled": False,
                        "dhcp4": False,
                        "address": [
                            {
                                "address": "2001:db8::2",
                                "family": socket.AF_INET6,
                                "prefix": 32,
                            },
                            {
                                "address": "2001:db8::3",
                                "family": socket.AF_INET6,
                                "prefix": 32,
                            },
                            {
                                "address": "2001:db8::4",
                                "family": socket.AF_INET6,
                                "prefix": 32,
                            },
                        ],
                        "auto_gateway": None,
                        "route_append_only": False,
                        "rule_append_only": False,
                        "route": [],
                        "dns": [],
                        "dns_options": [],
                        "dns_search": [],
                        "route_metric6": None,
                        "dhcp4_send_hostname": None,
                    },
                    "mac": None,
                    "controller": None,
                    "ieee802_1x": None,
                    "wireless": None,
                    "mtu": None,
                    "name": "prod1",
                    "parent": None,
                    "persistent_state": "present",
                    "port_type": None,
                    "state": "up",
                    "type": "ethernet",
                    "wait": None,
                    "zone": None,
                }
            ],
            [
                {
                    "name": "prod1",
                    "state": "up",
                    "type": "ethernet",
                    "ip": {
                        "dhcp4": "no",
                        "auto6": "no",
                        "address": [
                            "2001:db8::2/32",
                            "2001:db8::3/32",
                            "2001:db8::4/32",
                        ],
                        "gateway6": "2001:db8::1",
                    },
                }
            ],
            initscripts_dict_expected=[
                {
                    "ifcfg": {
                        "BOOTPROTO": "none",
                        "IPV6INIT": "yes",
                        "IPV6_AUTOCONF": "no",
                        "IPV6ADDR": "2001:db8::2/32",
                        "IPV6ADDR_SECONDARIES": "2001:db8::3/32 2001:db8::4/32",
                        "IPV6_DEFAULTGW": "2001:db8::1",
                        "NM_CONTROLLED": "no",
                        "ONBOOT": "yes",
                        "TYPE": "Ethernet",
                        "DEVICE": "prod1",
                    },
                    "keys": None,
                    "route": None,
                    "route6": None,
                    "rule": None,
                    "rule6": None,
                }
            ],
        )

    def test_routes(self):
        self.maxDiff = None
        self.do_connections_validate(
            [
                {
                    "actions": ["present", "up"],
                    "autoconnect": True,
                    "check_iface_exists": True,
                    "ethernet": ETHERNET_DEFAULTS,
                    "ethtool": ETHTOOL_DEFAULTS,
                    "force_state_change": None,
                    "ignore_errors": None,
                    "interface_name": None,
                    "ip": {
                        "dhcp4": False,
                        "auto6": True,
                        "ipv6_disabled": False,
                        "address": [
                            {
                                "prefix": 24,
                                "family": socket.AF_INET,
                                "address": "192.168.176.5",
                            },
                            {
                                "prefix": 24,
                                "family": socket.AF_INET,
                                "address": "192.168.177.5",
                            },
                        ],
                        "auto_gateway": None,
                        "route_append_only": False,
                        "rule_append_only": False,
                        "route": [],
                        "route_metric6": None,
                        "route_metric4": None,
                        "dns_options": [],
                        "dns_search": [],
                        "dhcp4_send_hostname": None,
                        "gateway6": None,
                        "gateway4": None,
                        "dns": [],
                    },
                    "mac": "52:54:00:44:9f:ba",
                    "controller": None,
                    "ieee802_1x": None,
                    "wireless": None,
                    "mtu": 1450,
                    "name": "prod1",
                    "parent": None,
                    "persistent_state": "present",
                    "port_type": None,
                    "state": "up",
                    "type": "ethernet",
                    "wait": None,
                    "zone": None,
                },
                {
                    "actions": ["present", "up"],
                    "autoconnect": True,
                    "check_iface_exists": True,
                    "ethernet": ETHERNET_DEFAULTS,
                    "ethtool": ETHTOOL_DEFAULTS,
                    "force_state_change": None,
                    "ignore_errors": None,
                    "interface_name": "prod.100",
                    "ip": {
                        "dhcp4": False,
                        "route_metric6": None,
                        "route_metric4": None,
                        "dns_options": [],
                        "dns_search": [],
                        "dhcp4_send_hostname": None,
                        "gateway6": None,
                        "gateway4": None,
                        "auto6": False,
                        "ipv6_disabled": False,
                        "dns": [],
                        "address": [
                            {
                                "prefix": 24,
                                "family": socket.AF_INET,
                                "address": "192.168.174.5",
                            },
                            {
                                "prefix": 65,
                                "family": socket.AF_INET6,
                                "address": "a:b:c::6",
                            },
                        ],
                        "auto_gateway": None,
                        "route_append_only": False,
                        "rule_append_only": False,
                        "route": [
                            {
                                "family": socket.AF_INET,
                                "network": "192.168.5.0",
                                "prefix": 24,
                                "gateway": None,
                                "metric": -1,
                            }
                        ],
                    },
                    "mac": None,
                    "controller": None,
                    "ieee802_1x": None,
                    "wireless": None,
                    "mtu": None,
                    "name": "prod.100",
                    "parent": "prod1",
                    "persistent_state": "present",
                    "port_type": None,
                    "state": "up",
                    "type": "vlan",
                    "vlan": {"id": 100},
                    "wait": None,
                    "zone": None,
                },
            ],
            [
                {
                    "name": "prod1",
                    "state": "up",
                    "type": "ethernet",
                    "autoconnect": "yes",
                    "mac": "52:54:00:44:9f:ba",
                    "mtu": 1450,
                    "ip": {"address": "192.168.176.5/24 192.168.177.5/24"},
                },
                {
                    "name": "prod.100",
                    "state": "up",
                    "type": "vlan",
                    "parent": "prod1",
                    "vlan": {"id": "100"},
                    "ip": {
                        "address": [
                            "192.168.174.5/24",
                            {"address": "a:b:c::6", "prefix": 65},
                        ],
                        "route_append_only": False,
                        "rule_append_only": False,
                        "route": [{"network": "192.168.5.0"}],
                    },
                },
            ],
        )

    def test_auto_gateway_true(self):
        self.maxDiff = None
        self.do_connections_validate(
            [
                {
                    "actions": ["present", "up"],
                    "autoconnect": True,
                    "check_iface_exists": True,
                    "ethernet": ETHERNET_DEFAULTS,
                    "ethtool": ETHTOOL_DEFAULTS,
                    "force_state_change": None,
                    "ignore_errors": None,
                    "interface_name": "prod1",
                    "ip": {
                        "dhcp4": True,
                        "route_metric6": None,
                        "route_metric4": None,
                        "dns_options": [],
                        "dns_search": [],
                        "dhcp4_send_hostname": None,
                        "gateway6": None,
                        "gateway4": None,
                        "auto6": True,
                        "ipv6_disabled": False,
                        "dns": [],
                        "address": [],
                        "auto_gateway": True,
                        "route_append_only": False,
                        "rule_append_only": False,
                        "route": [],
                    },
                    "mac": None,
                    "controller": None,
                    "ieee802_1x": None,
                    "wireless": None,
                    "mtu": None,
                    "name": "prod1",
                    "parent": None,
                    "persistent_state": "present",
                    "port_type": None,
                    "state": "up",
                    "type": "ethernet",
                    "wait": None,
                    "zone": None,
                }
            ],
            [
                {
                    "name": "prod1",
                    "state": "up",
                    "type": "ethernet",
                    "ip": {"auto_gateway": True},
                }
            ],
            initscripts_dict_expected=[
                {
                    "ifcfg": {
                        "BOOTPROTO": "dhcp",
                        "DEFROUTE": "yes",
                        "IPV6INIT": "yes",
                        "IPV6_AUTOCONF": "yes",
                        "NM_CONTROLLED": "no",
                        "ONBOOT": "yes",
                        "DEVICE": "prod1",
                        "TYPE": "Ethernet",
                    },
                    "keys": None,
                    "route": None,
                    "route6": None,
                    "rule": None,
                    "rule6": None,
                }
            ],
        )

    def test_auto_gateway_false(self):
        self.maxDiff = None
        self.do_connections_validate(
            [
                {
                    "actions": ["present", "up"],
                    "autoconnect": True,
                    "check_iface_exists": True,
                    "ethernet": ETHERNET_DEFAULTS,
                    "ethtool": ETHTOOL_DEFAULTS,
                    "force_state_change": None,
                    "ignore_errors": None,
                    "interface_name": "prod1",
                    "ip": {
                        "dhcp4": True,
                        "route_metric6": None,
                        "route_metric4": None,
                        "dns_options": [],
                        "dns_search": [],
                        "dhcp4_send_hostname": None,
                        "gateway6": None,
                        "gateway4": None,
                        "auto6": True,
                        "ipv6_disabled": False,
                        "dns": [],
                        "address": [],
                        "auto_gateway": False,
                        "route_append_only": False,
                        "rule_append_only": False,
                        "route": [],
                    },
                    "mac": None,
                    "controller": None,
                    "ieee802_1x": None,
                    "wireless": None,
                    "mtu": None,
                    "name": "prod1",
                    "parent": None,
                    "persistent_state": "present",
                    "port_type": None,
                    "state": "up",
                    "type": "ethernet",
                    "wait": None,
                    "zone": None,
                }
            ],
            [
                {
                    "name": "prod1",
                    "state": "up",
                    "type": "ethernet",
                    "ip": {"auto_gateway": False},
                }
            ],
            initscripts_dict_expected=[
                {
                    "ifcfg": {
                        "BOOTPROTO": "dhcp",
                        "DEFROUTE": "no",
                        "IPV6INIT": "yes",
                        "IPV6_AUTOCONF": "yes",
                        "NM_CONTROLLED": "no",
                        "ONBOOT": "yes",
                        "DEVICE": "prod1",
                        "TYPE": "Ethernet",
                    },
                    "keys": None,
                    "route": None,
                    "route6": None,
                    "rule": None,
                    "rule6": None,
                }
            ],
        )

    def test_auto_gateway_no_gateway(self):
        self.maxDiff = None
        self.do_connections_check_invalid(
            [
                {
                    "name": "eth0",
                    "state": "up",
                    "type": "ethernet",
                    "ip": {
                        "dhcp4": "no",
                        "auto6": "no",
                        "auto_gateway": "true",
                        "address": "192.168.176.5/24",
                    },
                }
            ]
        )

    def test_vlan(self):
        self.maxDiff = None
        self.do_connections_validate(
            [
                {
                    "actions": ["present", "up"],
                    "autoconnect": True,
                    "check_iface_exists": True,
                    "ethernet": ETHERNET_DEFAULTS,
                    "ethtool": ETHTOOL_DEFAULTS,
                    "force_state_change": None,
                    "ignore_errors": None,
                    "interface_name": None,
                    "ip": {
                        "dhcp4": False,
                        "auto6": True,
                        "address": [
                            {
                                "prefix": 24,
                                "family": socket.AF_INET,
                                "address": "192.168.176.5",
                            },
                            {
                                "prefix": 24,
                                "family": socket.AF_INET,
                                "address": "192.168.177.5",
                            },
                        ],
                        "auto_gateway": None,
                        "route_append_only": False,
                        "rule_append_only": False,
                        "route": [],
                        "route_metric6": None,
                        "route_metric4": None,
                        "dns_options": [],
                        "dns_search": [],
                        "dhcp4_send_hostname": None,
                        "gateway6": None,
                        "gateway4": None,
                        "ipv6_disabled": False,
                        "dns": [],
                    },
                    "mac": "52:54:00:44:9f:ba",
                    "controller": None,
                    "ieee802_1x": None,
                    "wireless": None,
                    "mtu": 1450,
                    "name": "prod1",
                    "parent": None,
                    "persistent_state": "present",
                    "port_type": None,
                    "state": "up",
                    "type": "ethernet",
                    "wait": None,
                    "zone": None,
                },
                {
                    "actions": ["present", "up"],
                    "autoconnect": True,
                    "check_iface_exists": True,
                    "ethernet": ETHERNET_DEFAULTS,
                    "ethtool": ETHTOOL_DEFAULTS,
                    "force_state_change": None,
                    "ignore_errors": None,
                    "interface_name": "prod.100",
                    "ip": {
                        "dhcp4": False,
                        "route_metric6": None,
                        "route_metric4": None,
                        "dns_options": [],
                        "dns_search": [],
                        "dhcp4_send_hostname": None,
                        "gateway6": None,
                        "gateway4": None,
                        "ipv6_disabled": False,
                        "auto6": False,
                        "dns": [],
                        "address": [
                            {
                                "prefix": 24,
                                "family": socket.AF_INET,
                                "address": "192.168.174.5",
                            },
                            {
                                "prefix": 65,
                                "family": socket.AF_INET6,
                                "address": "a:b:c::6",
                            },
                        ],
                        "auto_gateway": None,
                        "route_append_only": False,
                        "rule_append_only": False,
                        "route": [
                            {
                                "family": socket.AF_INET,
                                "network": "192.168.5.0",
                                "prefix": 24,
                                "gateway": None,
                                "metric": -1,
                            }
                        ],
                    },
                    "mac": None,
                    "controller": None,
                    "ieee802_1x": None,
                    "wireless": None,
                    "mtu": None,
                    "name": "prod.100",
                    "parent": "prod1",
                    "persistent_state": "present",
                    "port_type": None,
                    "state": "up",
                    "type": "vlan",
                    "vlan": {"id": 101},
                    "wait": None,
                    "zone": None,
                },
            ],
            [
                {
                    "name": "prod1",
                    "state": "up",
                    "type": "ethernet",
                    "autoconnect": "yes",
                    "mac": "52:54:00:44:9f:ba",
                    "mtu": 1450,
                    "ip": {"address": "192.168.176.5/24 192.168.177.5/24"},
                },
                {
                    "name": "prod.100",
                    "state": "up",
                    "type": "vlan",
                    "parent": "prod1",
                    "vlan_id": 101,
                    "ip": {
                        "address": [
                            "192.168.174.5/24",
                            {"address": "a:b:c::6", "prefix": 65},
                        ],
                        "route_append_only": False,
                        "rule_append_only": False,
                        "route": [{"network": "192.168.5.0"}],
                    },
                },
            ],
        )

    def test_macvlan(self):
        self.maxDiff = None
        self.do_connections_validate(
            [
                {
                    "actions": ["present", "up"],
                    "autoconnect": True,
                    "check_iface_exists": True,
                    "ethernet": ETHERNET_DEFAULTS,
                    "ethtool": ETHTOOL_DEFAULTS,
                    "force_state_change": None,
                    "ignore_errors": None,
                    "interface_name": "eth0",
                    "ip": {
                        "dhcp4": False,
                        "auto6": False,
                        "address": [
                            {
                                "prefix": 24,
                                "family": socket.AF_INET,
                                "address": "192.168.122.3",
                            }
                        ],
                        "auto_gateway": None,
                        "route_append_only": False,
                        "rule_append_only": False,
                        "route": [],
                        "route_metric6": None,
                        "route_metric4": None,
                        "dns_options": [],
                        "ipv6_disabled": False,
                        "dns_search": [],
                        "dhcp4_send_hostname": None,
                        "gateway6": None,
                        "gateway4": None,
                        "dns": [],
                    },
                    "mac": "33:24:10:24:2f:b9",
                    "controller": None,
                    "ieee802_1x": None,
                    "wireless": None,
                    "mtu": 1450,
                    "name": "eth0-parent",
                    "parent": None,
                    "persistent_state": "present",
                    "port_type": None,
                    "state": "up",
                    "type": "ethernet",
                    "wait": None,
                    "zone": None,
                },
                {
                    "actions": ["present", "up"],
                    "autoconnect": True,
                    "check_iface_exists": True,
                    "ethtool": ETHTOOL_DEFAULTS,
                    "force_state_change": None,
                    "ignore_errors": None,
                    "interface_name": "veth0",
                    "ip": {
                        "dhcp4": False,
                        "route_metric6": None,
                        "route_metric4": None,
                        "dns_options": [],
                        "ipv6_disabled": False,
                        "dns_search": [],
                        "dhcp4_send_hostname": None,
                        "gateway6": None,
                        "gateway4": None,
                        "auto6": False,
                        "dns": [],
                        "address": [
                            {
                                "prefix": 24,
                                "family": socket.AF_INET,
                                "address": "192.168.244.1",
                            }
                        ],
                        "auto_gateway": None,
                        "route_append_only": False,
                        "rule_append_only": False,
                        "route": [
                            {
                                "family": socket.AF_INET,
                                "network": "192.168.244.0",
                                "prefix": 24,
                                "gateway": None,
                                "metric": -1,
                            }
                        ],
                    },
                    "mac": None,
                    "macvlan": {"mode": "bridge", "promiscuous": True, "tap": False},
                    "controller": None,
                    "ieee802_1x": None,
                    "wireless": None,
                    "mtu": None,
                    "name": "veth0.0",
                    "parent": "eth0-parent",
                    "persistent_state": "present",
                    "port_type": None,
                    "state": "up",
                    "type": "macvlan",
                    "wait": None,
                    "zone": None,
                },
                {
                    "actions": ["present", "up"],
                    "autoconnect": True,
                    "check_iface_exists": True,
                    "ethtool": ETHTOOL_DEFAULTS,
                    "force_state_change": None,
                    "ignore_errors": None,
                    "interface_name": "veth1",
                    "ip": {
                        "dhcp4": False,
                        "route_metric6": None,
                        "route_metric4": None,
                        "dns_options": [],
                        "dns_search": [],
                        "dhcp4_send_hostname": None,
                        "gateway6": None,
                        "gateway4": None,
                        "ipv6_disabled": False,
                        "auto6": False,
                        "dns": [],
                        "address": [
                            {
                                "prefix": 24,
                                "family": socket.AF_INET,
                                "address": "192.168.245.7",
                            }
                        ],
                        "auto_gateway": None,
                        "route_append_only": False,
                        "rule_append_only": False,
                        "route": [
                            {
                                "family": socket.AF_INET,
                                "network": "192.168.245.0",
                                "prefix": 24,
                                "gateway": None,
                                "metric": -1,
                            }
                        ],
                    },
                    "mac": None,
                    "macvlan": {"mode": "passthru", "promiscuous": False, "tap": True},
                    "controller": None,
                    "ieee802_1x": None,
                    "wireless": None,
                    "mtu": None,
                    "name": "veth0.1",
                    "parent": "eth0-parent",
                    "persistent_state": "present",
                    "port_type": None,
                    "state": "up",
                    "type": "macvlan",
                    "wait": None,
                    "zone": None,
                },
            ],
            [
                {
                    "name": "eth0-parent",
                    "state": "up",
                    "type": "ethernet",
                    "autoconnect": "yes",
                    "interface_name": "eth0",
                    "mac": "33:24:10:24:2f:b9",
                    "mtu": 1450,
                    "ip": {"address": "192.168.122.3/24", "auto6": False},
                },
                {
                    "name": "veth0.0",
                    "state": "up",
                    "type": "macvlan",
                    "parent": "eth0-parent",
                    "interface_name": "veth0",
                    "macvlan": {"mode": "bridge", "promiscuous": True, "tap": False},
                    "ip": {
                        "address": "192.168.244.1/24",
                        "auto6": False,
                        "route_append_only": False,
                        "rule_append_only": False,
                        "route": [{"network": "192.168.244.0"}],
                    },
                },
                {
                    "name": "veth0.1",
                    "state": "up",
                    "type": "macvlan",
                    "parent": "eth0-parent",
                    "interface_name": "veth1",
                    "macvlan": {"mode": "passthru", "promiscuous": False, "tap": True},
                    "ip": {
                        "address": "192.168.245.7/24",
                        "auto6": False,
                        "route_append_only": False,
                        "rule_append_only": False,
                        "route": [{"network": "192.168.245.0"}],
                    },
                },
            ],
        )

    def test_bridge_no_dhcp4_auto6(self):
        self.maxDiff = None
        self.do_connections_validate(
            [
                {
                    "actions": ["present", "up"],
                    "autoconnect": True,
                    "check_iface_exists": True,
                    "ethernet": ETHERNET_DEFAULTS,
                    "ethtool": ETHTOOL_DEFAULTS,
                    "force_state_change": None,
                    "ignore_errors": None,
                    "interface_name": "bridge2",
                    "ip": {
                        "address": [],
                        "auto_gateway": None,
                        "auto6": False,
                        "dhcp4": False,
                        "dhcp4_send_hostname": None,
                        "dns": [],
                        "dns_options": [],
                        "dns_search": [],
                        "gateway4": None,
                        "gateway6": None,
                        "ipv6_disabled": False,
                        "route": [],
                        "route_append_only": False,
                        "route_metric4": None,
                        "route_metric6": None,
                        "rule_append_only": False,
                    },
                    "mac": None,
                    "controller": None,
                    "ieee802_1x": None,
                    "wireless": None,
                    "mtu": None,
                    "name": "prod2",
                    "parent": None,
                    "persistent_state": "present",
                    "port_type": None,
                    "state": "up",
                    "type": "bridge",
                    "wait": None,
                    "zone": None,
                },
                {
                    "actions": ["present", "up"],
                    "autoconnect": True,
                    "check_iface_exists": True,
                    "ethernet": ETHERNET_DEFAULTS,
                    "ethtool": ETHTOOL_DEFAULTS,
                    "force_state_change": None,
                    "ignore_errors": None,
                    "interface_name": "eth1",
                    "ip": {
                        "address": [],
                        "auto_gateway": None,
                        "auto6": True,
                        "dhcp4": True,
                        "dhcp4_send_hostname": None,
                        "dns": [],
                        "dns_options": [],
                        "dns_search": [],
                        "gateway4": None,
                        "gateway6": None,
                        "ipv6_disabled": False,
                        "route": [],
                        "route_append_only": False,
                        "route_metric4": None,
                        "route_metric6": None,
                        "rule_append_only": False,
                    },
                    "mac": None,
                    "controller": "prod2",
                    "ieee802_1x": None,
                    "wireless": None,
                    "mtu": None,
                    "name": "prod2-port1",
                    "parent": None,
                    "persistent_state": "present",
                    "port_type": "bridge",
                    "state": "up",
                    "type": "ethernet",
                    "wait": None,
                    "zone": None,
                },
            ],
            [
                {
                    "name": "prod2",
                    "state": "up",
                    "type": "bridge",
                    "interface_name": "bridge2",
                    "ip": {"dhcp4": False, "auto6": False},
                },
                {
                    "name": "prod2-port1",
                    "state": "up",
                    "type": "ethernet",
                    "interface_name": "eth1",
                    "controller": "prod2",
                },
            ],
        )

    def test_bond(self):
        self.maxDiff = None
        self.do_connections_validate(
            [
                {
                    "actions": ["present", "up"],
                    "autoconnect": True,
                    "bond": {"mode": "balance-rr", "miimon": None},
                    "check_iface_exists": True,
                    "ethernet": ETHERNET_DEFAULTS,
                    "ethtool": ETHTOOL_DEFAULTS,
                    "force_state_change": None,
                    "ignore_errors": None,
                    "interface_name": "bond1",
                    "ip": {
                        "dhcp4": True,
                        "route_metric6": None,
                        "route_metric4": None,
                        "dns_options": [],
                        "dns_search": [],
                        "dhcp4_send_hostname": None,
                        "gateway6": None,
                        "gateway4": None,
                        "auto6": True,
                        "ipv6_disabled": False,
                        "dns": [],
                        "address": [],
                        "auto_gateway": None,
                        "route_append_only": False,
                        "rule_append_only": False,
                        "route": [],
                    },
                    "mac": None,
                    "controller": None,
                    "ieee802_1x": None,
                    "wireless": None,
                    "mtu": None,
                    "name": "bond1",
                    "parent": None,
                    "persistent_state": "present",
                    "port_type": None,
                    "state": "up",
                    "type": "bond",
                    "wait": None,
                    "zone": None,
                }
            ],
            [{"name": "bond1", "state": "up", "type": "bond"}],
        )

    def test_bond_active_backup(self):
        self.maxDiff = None
        self.do_connections_validate(
            [
                {
                    "actions": ["present", "up"],
                    "autoconnect": True,
                    "bond": {"mode": "active-backup", "miimon": None},
                    "check_iface_exists": True,
                    "ethernet": ETHERNET_DEFAULTS,
                    "ethtool": ETHTOOL_DEFAULTS,
                    "force_state_change": None,
                    "ignore_errors": None,
                    "interface_name": "bond1",
                    "ip": {
                        "dhcp4": True,
                        "route_metric6": None,
                        "route_metric4": None,
                        "dns_options": [],
                        "dns_search": [],
                        "dhcp4_send_hostname": None,
                        "gateway6": None,
                        "gateway4": None,
                        "auto6": True,
                        "ipv6_disabled": False,
                        "dns": [],
                        "address": [],
                        "auto_gateway": None,
                        "route_append_only": False,
                        "rule_append_only": False,
                        "route": [],
                    },
                    "mac": None,
                    "controller": None,
                    "ieee802_1x": None,
                    "wireless": None,
                    "mtu": None,
                    "name": "bond1",
                    "parent": None,
                    "persistent_state": "present",
                    "port_type": None,
                    "state": "up",
                    "type": "bond",
                    "wait": None,
                    "zone": None,
                }
            ],
            [
                {
                    "name": "bond1",
                    "state": "up",
                    "type": "bond",
                    "bond": {"mode": "active-backup"},
                }
            ],
        )

    def test_invalid_values(self):
        self.maxDiff = None
        self.do_connections_check_invalid([{}])
        self.do_connections_check_invalid([{"name": "b", "xxx": 5}])

    def test_ethernet_mac_address(self):
        self.maxDiff = None
        self.do_connections_validate(
            [
                {
                    "actions": ["present"],
                    "autoconnect": True,
                    "check_iface_exists": True,
                    "ethernet": ETHERNET_DEFAULTS,
                    "ethtool": ETHTOOL_DEFAULTS,
                    "ignore_errors": None,
                    "interface_name": None,
                    "ip": {
                        "address": [],
                        "auto_gateway": None,
                        "route_append_only": False,
                        "rule_append_only": False,
                        "route": [],
                        "auto6": True,
                        "ipv6_disabled": False,
                        "dhcp4": True,
                        "dhcp4_send_hostname": None,
                        "gateway4": None,
                        "gateway6": None,
                        "route_metric4": None,
                        "route_metric6": None,
                        "dns": [],
                        "dns_options": [],
                        "dns_search": [],
                    },
                    "mac": "aa:bb:cc:dd:ee:ff",
                    "controller": None,
                    "ieee802_1x": None,
                    "wireless": None,
                    "mtu": None,
                    "name": "5",
                    "parent": None,
                    "persistent_state": "present",
                    "port_type": None,
                    "state": None,
                    "type": "ethernet",
                    "zone": None,
                }
            ],
            [{"name": "5", "type": "ethernet", "mac": "AA:bb:cC:DD:ee:FF"}],
        )

    def test_ethernet_speed_settings(self):
        self.maxDiff = None
        self.do_connections_validate(
            [
                {
                    "actions": ["present", "up"],
                    "autoconnect": True,
                    "check_iface_exists": True,
                    "ethernet": {"autoneg": False, "duplex": "half", "speed": 400},
                    "ethtool": ETHTOOL_DEFAULTS,
                    "force_state_change": None,
                    "ignore_errors": None,
                    "interface_name": "5",
                    "ip": {
                        "gateway6": None,
                        "gateway4": None,
                        "route_metric4": None,
                        "auto6": True,
                        "ipv6_disabled": False,
                        "dhcp4": True,
                        "address": [],
                        "auto_gateway": None,
                        "route_append_only": False,
                        "rule_append_only": False,
                        "route": [],
                        "dns": [],
                        "dns_options": [],
                        "dns_search": [],
                        "route_metric6": None,
                        "dhcp4_send_hostname": None,
                    },
                    "mac": None,
                    "controller": None,
                    "ieee802_1x": None,
                    "wireless": None,
                    "mtu": None,
                    "name": "5",
                    "parent": None,
                    "persistent_state": "present",
                    "port_type": None,
                    "state": "up",
                    "type": "ethernet",
                    "wait": None,
                    "zone": None,
                }
            ],
            [
                {
                    "name": "5",
                    "state": "up",
                    "type": "ethernet",
                    "ip": {},
                    "ethernet": {"duplex": "half", "speed": 400},
                }
            ],
            initscripts_dict_expected=[
                {
                    "ifcfg": {
                        "BOOTPROTO": "dhcp",
                        "ETHTOOL_OPTS": "autoneg off speed 400 duplex half",
                        "IPV6INIT": "yes",
                        "IPV6_AUTOCONF": "yes",
                        "NM_CONTROLLED": "no",
                        "ONBOOT": "yes",
                        "TYPE": "Ethernet",
                        "DEVICE": "5",
                    },
                    "keys": None,
                    "route": None,
                    "route6": None,
                    "rule": None,
                    "rule6": None,
                }
            ],
        )

    def test_bridge2(self):
        self.maxDiff = None
        self.do_connections_validate(
            [
                {
                    "actions": ["present", "up"],
                    "autoconnect": True,
                    "check_iface_exists": True,
                    "ethernet": ETHERNET_DEFAULTS,
                    "ethtool": ETHTOOL_DEFAULTS,
                    "force_state_change": None,
                    "ignore_errors": None,
                    "interface_name": "6643-controller",
                    "ip": {
                        "address": [],
                        "auto_gateway": None,
                        "auto6": True,
                        "ipv6_disabled": False,
                        "dhcp4": True,
                        "dhcp4_send_hostname": None,
                        "dns": [],
                        "dns_options": [],
                        "dns_search": [],
                        "gateway4": None,
                        "gateway6": None,
                        "route": [],
                        "route_append_only": False,
                        "route_metric4": None,
                        "route_metric6": None,
                        "rule_append_only": False,
                    },
                    "mac": None,
                    "controller": None,
                    "ieee802_1x": None,
                    "wireless": None,
                    "mtu": None,
                    "name": "6643-controller",
                    "parent": None,
                    "persistent_state": "present",
                    "port_type": None,
                    "state": "up",
                    "type": "bridge",
                    "wait": None,
                    "zone": None,
                },
                {
                    "actions": ["present", "up"],
                    "autoconnect": True,
                    "check_iface_exists": True,
                    "ethernet": ETHERNET_DEFAULTS,
                    "ethtool": ETHTOOL_DEFAULTS,
                    "force_state_change": None,
                    "ignore_errors": None,
                    "interface_name": "6643",
                    "ip": {
                        "address": [],
                        "auto_gateway": None,
                        "auto6": True,
                        "dhcp4_send_hostname": None,
                        "dhcp4": True,
                        "dns": [],
                        "dns_options": [],
                        "dns_search": [],
                        "gateway4": None,
                        "gateway6": None,
                        "ipv6_disabled": False,
                        "route": [],
                        "route_append_only": False,
                        "route_metric4": None,
                        "route_metric6": None,
                        "rule_append_only": False,
                    },
                    "mac": None,
                    "controller": "6643-controller",
                    "ieee802_1x": None,
                    "wireless": None,
                    "mtu": None,
                    "name": "6643",
                    "parent": None,
                    "persistent_state": "present",
                    "port_type": "bridge",
                    "state": "up",
                    "type": "ethernet",
                    "wait": None,
                    "zone": None,
                },
            ],
            [
                {"name": "6643-controller", "state": "up", "type": "bridge"},
                {
                    "name": "6643",
                    "state": "up",
                    "type": "ethernet",
                    "controller": "6643-controller",
                },
            ],
        )

    def test_infiniband(self):
        self.maxDiff = None
        self.do_connections_validate(
            [
                {
                    "actions": ["present", "up"],
                    "autoconnect": True,
                    "check_iface_exists": True,
                    "ethtool": ETHTOOL_DEFAULTS,
                    "force_state_change": None,
                    "ignore_errors": None,
                    "infiniband": {"p_key": -1, "transport_mode": "datagram"},
                    "interface_name": None,
                    "ip": {
                        "address": [],
                        "auto_gateway": None,
                        "auto6": True,
                        "dhcp4": True,
                        "dhcp4_send_hostname": None,
                        "dns": [],
                        "dns_options": [],
                        "dns_search": [],
                        "gateway4": None,
                        "gateway6": None,
                        "ipv6_disabled": False,
                        "route": [],
                        "route_append_only": False,
                        "route_metric4": None,
                        "route_metric6": None,
                        "rule_append_only": False,
                    },
                    "mac": None,
                    "controller": None,
                    "ieee802_1x": None,
                    "wireless": None,
                    "mtu": None,
                    "name": "infiniband.1",
                    "parent": None,
                    "persistent_state": "present",
                    "port_type": None,
                    "state": "up",
                    "type": "infiniband",
                    "wait": None,
                    "zone": None,
                }
            ],
            [
                {
                    "name": "infiniband.1",
                    "interface_name": "",
                    "state": "up",
                    "type": "infiniband",
                }
            ],
            initscripts_dict_expected=[
                {
                    "ifcfg": {
                        "BOOTPROTO": "dhcp",
                        "CONNECTED_MODE": "no",
                        "IPV6INIT": "yes",
                        "IPV6_AUTOCONF": "yes",
                        "NM_CONTROLLED": "no",
                        "ONBOOT": "yes",
                        "TYPE": "InfiniBand",
                    },
                    "keys": None,
                    "route": None,
                    "route6": None,
                    "rule": None,
                    "rule6": None,
                }
            ],
        )

    def test_infiniband2(self):
        self.maxDiff = None
        self.do_connections_validate(
            [
                {
                    "actions": ["present", "up"],
                    "autoconnect": True,
                    "check_iface_exists": True,
                    "ethtool": ETHTOOL_DEFAULTS,
                    "force_state_change": None,
                    "ignore_errors": None,
                    "infiniband": {"p_key": 5, "transport_mode": "datagram"},
                    "interface_name": None,
                    "ip": {
                        "address": [],
                        "auto_gateway": None,
                        "auto6": True,
                        "dhcp4": True,
                        "dhcp4_send_hostname": None,
                        "dns": [],
                        "dns_options": [],
                        "dns_search": [],
                        "gateway4": None,
                        "gateway6": None,
                        "ipv6_disabled": False,
                        "route": [],
                        "route_append_only": False,
                        "route_metric4": None,
                        "route_metric6": None,
                        "rule_append_only": False,
                    },
                    "mac": "11:22:33:44:55:66:77:88:99:00:"
                    "11:22:33:44:55:66:77:88:99:00",
                    "controller": None,
                    "ieee802_1x": None,
                    "wireless": None,
                    "mtu": None,
                    "name": "infiniband.2",
                    "parent": None,
                    "persistent_state": "present",
                    "port_type": None,
                    "state": "up",
                    "type": "infiniband",
                    "wait": None,
                    "zone": None,
                }
            ],
            [
                {
                    "name": "infiniband.2",
                    "state": "up",
                    "type": "infiniband",
                    "mac": "11:22:33:44:55:66:77:88:99:00:"
                    "11:22:33:44:55:66:77:88:99:00",
                    "infiniband_p_key": 5,
                }
            ],
            initscripts_dict_expected=[
                {
                    "ifcfg": {
                        "BOOTPROTO": "dhcp",
                        "CONNECTED_MODE": "no",
                        "HWADDR": "11:22:33:44:55:66:77:88:99:00:"
                        "11:22:33:44:55:66:77:88:99:00",
                        "IPV6INIT": "yes",
                        "IPV6_AUTOCONF": "yes",
                        "NM_CONTROLLED": "no",
                        "ONBOOT": "yes",
                        "PKEY": "yes",
                        "PKEY_ID": "5",
                        "TYPE": "InfiniBand",
                    },
                    "keys": None,
                    "route": None,
                    "route6": None,
                    "rule": None,
                    "rule6": None,
                }
            ],
        )

    def test_route_metric_prefix(self):
        self.maxDiff = None
        self.do_connections_validate(
            [
                {
                    "actions": ["present", "up"],
                    "autoconnect": True,
                    "check_iface_exists": True,
                    "ethernet": ETHERNET_DEFAULTS,
                    "ethtool": ETHTOOL_DEFAULTS,
                    "force_state_change": None,
                    "ignore_errors": None,
                    "interface_name": "555",
                    "ip": {
                        "gateway6": None,
                        "gateway4": None,
                        "route_metric4": None,
                        "auto6": True,
                        "ipv6_disabled": False,
                        "dhcp4": True,
                        "address": [],
                        "auto_gateway": None,
                        "route_append_only": False,
                        "rule_append_only": False,
                        "route": [
                            {
                                "family": socket.AF_INET,
                                "network": "192.168.45.0",
                                "prefix": 24,
                                "gateway": None,
                                "metric": 545,
                            },
                            {
                                "family": socket.AF_INET,
                                "network": "192.168.46.0",
                                "prefix": 30,
                                "gateway": None,
                                "metric": -1,
                            },
                        ],
                        "dns": [],
                        "dns_options": [],
                        "dns_search": ["aa", "bb"],
                        "route_metric6": None,
                        "dhcp4_send_hostname": None,
                    },
                    "mac": None,
                    "controller": None,
                    "ieee802_1x": None,
                    "wireless": None,
                    "mtu": None,
                    "name": "555",
                    "parent": None,
                    "persistent_state": "present",
                    "port_type": None,
                    "state": "up",
                    "type": "ethernet",
                    "wait": None,
                    "zone": None,
                }
            ],
            [
                {
                    "name": "555",
                    "state": "up",
                    "type": "ethernet",
                    "ip": {
                        "dns_search": ["aa", "bb"],
                        "route": [
                            {"network": "192.168.45.0", "metric": 545},
                            {"network": "192.168.46.0", "prefix": 30},
                        ],
                    },
                }
            ],
            initscripts_dict_expected=[
                {
                    "ifcfg": {
                        "BOOTPROTO": "dhcp",
                        "DOMAIN": "aa bb",
                        "IPV6INIT": "yes",
                        "IPV6_AUTOCONF": "yes",
                        "NM_CONTROLLED": "no",
                        "ONBOOT": "yes",
                        "TYPE": "Ethernet",
                        "DEVICE": "555",
                    },
                    "keys": None,
                    "route": "192.168.45.0/24 metric 545\n192.168.46.0/30\n",
                    "route6": None,
                    "rule": None,
                    "rule6": None,
                }
            ],
        )

    def test_route_v6(self):
        self.maxDiff = None
        self.do_connections_validate(
            [
                {
                    "actions": ["present", "up"],
                    "autoconnect": True,
                    "check_iface_exists": True,
                    "ethernet": ETHERNET_DEFAULTS,
                    "ethtool": ETHTOOL_DEFAULTS,
                    "force_state_change": None,
                    "ignore_errors": None,
                    "interface_name": "e556",
                    "ip": {
                        "gateway6": None,
                        "gateway4": None,
                        "route_metric4": None,
                        "auto6": True,
                        "ipv6_disabled": False,
                        "dhcp4": True,
                        "address": [],
                        "auto_gateway": None,
                        "route_append_only": True,
                        "rule_append_only": False,
                        "route": [
                            {
                                "family": socket.AF_INET,
                                "network": "192.168.45.0",
                                "prefix": 24,
                                "gateway": None,
                                "metric": 545,
                            },
                            {
                                "family": socket.AF_INET,
                                "network": "192.168.46.0",
                                "prefix": 30,
                                "gateway": None,
                                "metric": -1,
                            },
                            {
                                "family": socket.AF_INET6,
                                "network": "a:b:c:d::",
                                "prefix": 64,
                                "gateway": None,
                                "metric": -1,
                            },
                        ],
                        "dns": [],
                        "dns_options": [],
                        "dns_search": ["aa", "bb"],
                        "route_metric6": None,
                        "dhcp4_send_hostname": None,
                    },
                    "mac": None,
                    "controller": None,
                    "ieee802_1x": None,
                    "wireless": None,
                    "mtu": None,
                    "name": "e556",
                    "parent": None,
                    "persistent_state": "present",
                    "port_type": None,
                    "state": "up",
                    "type": "ethernet",
                    "wait": None,
                    "zone": "external",
                }
            ],
            [
                {
                    "name": "e556",
                    "state": "up",
                    "type": "ethernet",
                    "zone": "external",
                    "ip": {
                        "dns_search": ["aa", "bb"],
                        "route_append_only": True,
                        "rule_append_only": False,
                        "route": [
                            {"network": "192.168.45.0", "metric": 545},
                            {"network": "192.168.46.0", "prefix": 30},
                            {"network": "a:b:c:d::"},
                        ],
                    },
                }
            ],
            nm_route_list_current=[
                [
                    {"network": "192.168.40.0", "prefix": 24, "metric": 545},
                    {"network": "192.168.46.0", "prefix": 30},
                    {"network": "a:b:c:f::"},
                ]
            ],
            nm_route_list_expected=[
                [
                    {"network": "192.168.40.0", "prefix": 24, "metric": 545},
                    {"network": "192.168.46.0", "prefix": 30},
                    {"network": "192.168.45.0", "prefix": 24, "metric": 545},
                    {"network": "a:b:c:f::"},
                    {"network": "a:b:c:d::"},
                ]
            ],
            initscripts_content_current=[
                {
                    "ifcfg": "",
                    "keys": None,
                    "route": "192.168.40.0/24 metric 545\n192.168.46.0/30",
                    "route6": "a:b:c:f::/64",
                    "rule": None,
                    "rule6": None,
                }
            ],
            initscripts_dict_expected=[
                {
                    "ifcfg": {
                        "BOOTPROTO": "dhcp",
                        "DOMAIN": "aa bb",
                        "IPV6INIT": "yes",
                        "IPV6_AUTOCONF": "yes",
                        "NM_CONTROLLED": "no",
                        "ONBOOT": "yes",
                        "TYPE": "Ethernet",
                        "ZONE": "external",
                        "DEVICE": "e556",
                    },
                    "keys": None,
                    "route": "192.168.40.0/24 metric 545\n192.168.46.0/30\n"
                    "192.168.45.0/24 metric 545\n",
                    "route6": "a:b:c:f::/64\na:b:c:d::/64\n",
                    "rule": None,
                    "rule6": None,
                }
            ],
        )

    def test_802_1x_1(self):
        """
        Test private key with password
        """
        self.maxDiff = None
        self.do_connections_validate(
            [
                {
                    "actions": ["present", "up"],
                    "autoconnect": True,
                    "check_iface_exists": True,
                    "ethernet": ETHERNET_DEFAULTS,
                    "ethtool": ETHTOOL_DEFAULTS,
                    "force_state_change": None,
                    "ignore_errors": None,
                    "interface_name": "eth0",
                    "ip": {
                        "gateway6": None,
                        "gateway4": None,
                        "route_metric4": None,
                        "auto6": True,
                        "ipv6_disabled": False,
                        "dhcp4": True,
                        "address": [],
                        "auto_gateway": None,
                        "route_append_only": False,
                        "rule_append_only": False,
                        "route": [],
                        "dns": [],
                        "dns_options": [],
                        "dns_search": [],
                        "route_metric6": None,
                        "dhcp4_send_hostname": None,
                    },
                    "mac": None,
                    "controller": None,
                    "ieee802_1x": {
                        "identity": "myhost",
                        "eap": "tls",
                        "private_key": "/etc/pki/tls/client.key",
                        "private_key_password": "p@55w0rD",
                        "private_key_password_flags": None,
                        "client_cert": "/etc/pki/tls/client.pem",
                        "ca_cert": "/etc/pki/tls/cacert.pem",
                        "ca_path": None,
                        "system_ca_certs": False,
                        "domain_suffix_match": None,
                    },
                    "wireless": None,
                    "mtu": None,
                    "name": "eth0",
                    "parent": None,
                    "persistent_state": "present",
                    "port_type": None,
                    "state": "up",
                    "type": "ethernet",
                    "wait": None,
                    "zone": None,
                }
            ],
            [
                {
                    "name": "eth0",
                    "state": "up",
                    "type": "ethernet",
                    "ieee802_1x": {
                        "identity": "myhost",
                        "eap": "tls",
                        "private_key": "/etc/pki/tls/client.key",
                        "private_key_password": "p@55w0rD",
                        "client_cert": "/etc/pki/tls/client.pem",
                        "ca_cert": "/etc/pki/tls/cacert.pem",
                    },
                }
            ],
        )

    def test_802_1x_2(self):
        """
        Test 802.1x profile with unencrypted private key,
        domain suffix match, and system ca certs
        """
        self.maxDiff = None
        self.do_connections_validate(
            [
                {
                    "actions": ["present", "up"],
                    "autoconnect": True,
                    "check_iface_exists": True,
                    "ethernet": ETHERNET_DEFAULTS,
                    "ethtool": ETHTOOL_DEFAULTS,
                    "force_state_change": None,
                    "ignore_errors": None,
                    "interface_name": "eth0",
                    "ip": {
                        "gateway6": None,
                        "gateway4": None,
                        "route_metric4": None,
                        "auto6": True,
                        "ipv6_disabled": False,
                        "dhcp4": True,
                        "address": [],
                        "auto_gateway": None,
                        "route_append_only": False,
                        "rule_append_only": False,
                        "route": [],
                        "dns": [],
                        "dns_options": [],
                        "dns_search": [],
                        "route_metric6": None,
                        "dhcp4_send_hostname": None,
                    },
                    "mac": None,
                    "controller": None,
                    "ieee802_1x": {
                        "identity": "myhost",
                        "eap": "tls",
                        "private_key": "/etc/pki/tls/client.key",
                        "private_key_password": None,
                        "private_key_password_flags": ["not-required"],
                        "client_cert": "/etc/pki/tls/client.pem",
                        "ca_cert": None,
                        "ca_path": None,
                        "system_ca_certs": True,
                        "domain_suffix_match": "example.com",
                    },
                    "wireless": None,
                    "mtu": None,
                    "name": "eth0",
                    "parent": None,
                    "persistent_state": "present",
                    "port_type": None,
                    "state": "up",
                    "type": "ethernet",
                    "wait": None,
                    "zone": None,
                }
            ],
            [
                {
                    "name": "eth0",
                    "state": "up",
                    "type": "ethernet",
                    "ieee802_1x": {
                        "identity": "myhost",
                        "eap": "tls",
                        "private_key": "/etc/pki/tls/client.key",
                        "client_cert": "/etc/pki/tls/client.pem",
                        "private_key_password_flags": ["not-required"],
                        "system_ca_certs": True,
                        "domain_suffix_match": "example.com",
                    },
                }
            ],
        )

    def test_802_1x_3(self):
        """
        Test 802.1x profile with unencrypted private key and ca_path
        """
        self.maxDiff = None
        self.do_connections_validate(
            [
                {
                    "actions": ["present", "up"],
                    "autoconnect": True,
                    "check_iface_exists": True,
                    "ethernet": ETHERNET_DEFAULTS,
                    "ethtool": ETHTOOL_DEFAULTS,
                    "force_state_change": None,
                    "ignore_errors": None,
                    "interface_name": "eth0",
                    "ip": {
                        "gateway6": None,
                        "gateway4": None,
                        "route_metric4": None,
                        "auto6": True,
                        "ipv6_disabled": False,
                        "dhcp4": True,
                        "address": [],
                        "auto_gateway": None,
                        "route_append_only": False,
                        "rule_append_only": False,
                        "route": [],
                        "dns": [],
                        "dns_options": [],
                        "dns_search": [],
                        "route_metric6": None,
                        "dhcp4_send_hostname": None,
                    },
                    "mac": None,
                    "controller": None,
                    "ieee802_1x": {
                        "identity": "myhost",
                        "eap": "tls",
                        "private_key": "/etc/pki/tls/client.key",
                        "private_key_password": None,
                        "private_key_password_flags": ["not-required"],
                        "client_cert": "/etc/pki/tls/client.pem",
                        "ca_cert": None,
                        "ca_path": "/etc/pki/tls/my_ca_certs",
                        "system_ca_certs": False,
                        "domain_suffix_match": None,
                    },
                    "wireless": None,
                    "mtu": None,
                    "name": "eth0",
                    "parent": None,
                    "persistent_state": "present",
                    "port_type": None,
                    "state": "up",
                    "type": "ethernet",
                    "wait": None,
                    "zone": None,
                }
            ],
            [
                {
                    "name": "eth0",
                    "state": "up",
                    "type": "ethernet",
                    "ieee802_1x": {
                        "identity": "myhost",
                        "eap": "tls",
                        "private_key": "/etc/pki/tls/client.key",
                        "client_cert": "/etc/pki/tls/client.pem",
                        "private_key_password_flags": ["not-required"],
                        "ca_path": "/etc/pki/tls/my_ca_certs",
                    },
                }
            ],
        )

    def test_wireless_psk(self):
        """
        Test wireless connection with wpa-psk auth
        """
        self.maxDiff = None
        self.do_connections_validate(
            [
                {
                    "actions": ["present", "up"],
                    "autoconnect": True,
                    "check_iface_exists": True,
                    "ethtool": ETHTOOL_DEFAULTS,
                    "force_state_change": None,
                    "ignore_errors": None,
                    "interface_name": "wireless1",
                    "ip": {
                        "gateway6": None,
                        "gateway4": None,
                        "route_metric4": None,
                        "auto6": True,
                        "ipv6_disabled": False,
                        "dhcp4": True,
                        "address": [],
                        "auto_gateway": None,
                        "route_append_only": False,
                        "rule_append_only": False,
                        "route": [],
                        "dns": [],
                        "dns_options": [],
                        "dns_search": [],
                        "route_metric6": None,
                        "dhcp4_send_hostname": None,
                    },
                    "mac": None,
                    "controller": None,
                    "ieee802_1x": None,
                    "wireless": {
                        "ssid": "test wireless network",
                        "key_mgmt": "wpa-psk",
                        "password": "p@55w0rD",
                    },
                    "mtu": None,
                    "name": "wireless1",
                    "parent": None,
                    "persistent_state": "present",
                    "port_type": None,
                    "state": "up",
                    "type": "wireless",
                    "wait": None,
                    "zone": None,
                }
            ],
            [
                {
                    "name": "wireless1",
                    "state": "up",
                    "type": "wireless",
                    "wireless": {
                        "ssid": "test wireless network",
                        "key_mgmt": "wpa-psk",
                        "password": "p@55w0rD",
                    },
                }
            ],
        )

    def test_wireless_eap(self):
        """
        Test wireless connection with wpa-eap
        """
        self.maxDiff = None
        self.do_connections_validate(
            [
                {
                    "actions": ["present", "up"],
                    "autoconnect": True,
                    "check_iface_exists": True,
                    "ethtool": ETHTOOL_DEFAULTS,
                    "force_state_change": None,
                    "ignore_errors": None,
                    "interface_name": "wireless1",
                    "ip": {
                        "gateway6": None,
                        "gateway4": None,
                        "route_metric4": None,
                        "auto6": True,
                        "ipv6_disabled": False,
                        "dhcp4": True,
                        "address": [],
                        "auto_gateway": None,
                        "route_append_only": False,
                        "rule_append_only": False,
                        "route": [],
                        "dns": [],
                        "dns_options": [],
                        "dns_search": [],
                        "route_metric6": None,
                        "dhcp4_send_hostname": None,
                    },
                    "mac": None,
                    "controller": None,
                    "ieee802_1x": {
                        "identity": "myhost",
                        "eap": "tls",
                        "private_key": "/etc/pki/tls/client.key",
                        "private_key_password": "p@55w0rD",
                        "private_key_password_flags": None,
                        "client_cert": "/etc/pki/tls/client.pem",
                        "ca_cert": "/etc/pki/tls/cacert.pem",
                        "ca_path": None,
                        "system_ca_certs": False,
                        "domain_suffix_match": None,
                    },
                    "wireless": {
                        "ssid": "test wireless network",
                        "password": None,
                        "key_mgmt": "wpa-eap",
                    },
                    "mtu": None,
                    "name": "wireless1",
                    "parent": None,
                    "persistent_state": "present",
                    "port_type": None,
                    "state": "up",
                    "type": "wireless",
                    "wait": None,
                    "zone": None,
                }
            ],
            [
                {
                    "name": "wireless1",
                    "state": "up",
                    "type": "wireless",
                    "wireless": {
                        "ssid": "test wireless network",
                        "key_mgmt": "wpa-eap",
                    },
                    "ieee802_1x": {
                        "identity": "myhost",
                        "eap": "tls",
                        "private_key": "/etc/pki/tls/client.key",
                        "private_key_password": "p@55w0rD",
                        "client_cert": "/etc/pki/tls/client.pem",
                        "ca_cert": "/etc/pki/tls/cacert.pem",
                    },
                }
            ],
        )

    def test_invalid_cert_path(self):
        """
        should fail if a relative path is used for 802.1x certs/keys
        """
        self.maxDiff = None
        self.do_connections_check_invalid(
            [
                {
                    "name": "eth0",
                    "state": "up",
                    "type": "ethernet",
                    "ieee802_1x": {
                        "identity": "myhost",
                        "eap": "tls",
                        "private_key": "client.key",
                        "client_cert": "client.pem",
                        "private_key_password_flags": ["not-required"],
                        "system_ca_certs": True,
                    },
                }
            ]
        )

    def test_invalid_password_flag(self):
        """
        should fail if an invalid private key password flag is set
        """
        self.maxDiff = None
        self.do_connections_check_invalid(
            [
                {
                    "name": "eth0",
                    "state": "up",
                    "type": "ethernet",
                    "ieee802_1x": {
                        "identity": "myhost",
                        "eap": "tls",
                        "private_key": "/etc/pki/tls/client.key",
                        "client_cert": "/etc/pki/tls/client.pem",
                        "private_key_password_flags": ["bad-flag"],
                        "system_ca_certs": True,
                    },
                }
            ]
        )

    def test_802_1x_ca_path_and_system_ca_certs(self):
        """
        should fail if ca_path and system_ca_certs are used together
        """
        self.maxDiff = None
        self.do_connections_check_invalid(
            [
                {
                    "name": "eth0",
                    "state": "up",
                    "type": "ethernet",
                    "ieee802_1x": {
                        "identity": "myhost",
                        "eap": "tls",
                        "private_key": "/etc/pki/tls/client.key",
                        "client_cert": "/etc/pki/tls/client.pem",
                        "private_key_password_flags": ["not-required"],
                        "ca_path": "/etc/pki/my_ca_certs",
                        "system_ca_certs": True,
                    },
                }
            ]
        )

    def test_802_1x_initscripts(self):
        """
        should fail to create ieee802_1x connection with initscripts
        """
        input_connections = [
            {
                "name": "eth0",
                "state": "up",
                "type": "ethernet",
                "ieee802_1x": {
                    "identity": "myhost",
                    "eap": "tls",
                    "private_key": "/etc/pki/tls/client.key",
                    "client_cert": "/etc/pki/tls/client.pem",
                    "private_key_password_flags": ["not-required"],
                    "system_ca_certs": True,
                },
            }
        ]

        connections = ARGS_CONNECTIONS.validate(input_connections)

        self.assertRaises(
            ValidationError,
            ARGS_CONNECTIONS.validate_connection_one,
            VALIDATE_ONE_MODE_INITSCRIPTS,
            connections,
            0,
        )

    def test_802_1x_unsupported_type(self):
        """
        should fail if a non ethernet/wireless connection has 802.1x settings defined
        """
        self.do_connections_check_invalid(
            [
                {
                    "name": "bond0",
                    "state": "up",
                    "type": "bond",
                    "ieee802_1x": {
                        "identity": "myhost",
                        "eap": "tls",
                        "private_key": "/etc/pki/tls/client.key",
                        "client_cert": "/etc/pki/tls/client.pem",
                        "private_key_password_flags": ["not-required"],
                        "system_ca_certs": True,
                    },
                }
            ]
        )

    def test_wireless_initscripts(self):
        """
        should fail to create wireless connection with initscripts
        """
        input_connections = [
            {
                "name": "wireless1",
                "state": "up",
                "type": "wireless",
                "wireless": {
                    "ssid": "test wireless network",
                    "key_mgmt": "wpa-psk",
                    "password": "p@55w0rD",
                },
            }
        ]

        connections = ARGS_CONNECTIONS.validate(input_connections)

        self.assertRaises(
            ValidationError,
            ARGS_CONNECTIONS.validate_connection_one,
            VALIDATE_ONE_MODE_INITSCRIPTS,
            connections,
            0,
        )

    def test_wireless_unsupported_type(self):
        """
        should fail if a non wireless connection has wireless settings defined
        """
        self.do_connections_check_invalid(
            [
                {
                    "name": "wireless-bond",
                    "state": "up",
                    "type": "bond",
                    "wireless": {
                        "ssid": "test wireless network",
                        "key_mgmt": "wpa-psk",
                        "password": "p@55w0rD",
                    },
                }
            ]
        )

    def test_wireless_ssid_too_long(self):
        """
        should fail if ssid longer than 32 bytes
        """
        self.do_connections_check_invalid(
            [
                {
                    "name": "wireless1",
                    "state": "up",
                    "type": "wireless",
                    "wireless": {
                        "ssid": "test wireless network with ssid too long",
                        "key_mgmt": "wpa-psk",
                        "password": "p@55w0rD",
                    },
                }
            ]
        )

    def test_wireless_no_password(self):
        """
        should fail if wpa-psk is selected and no password provided
        """
        self.do_connections_check_invalid(
            [
                {
                    "name": "wireless1",
                    "state": "up",
                    "type": "wireless",
                    "wireless": {
                        "ssid": "test wireless network",
                        "key_mgmt": "wpa-psk",
                    },
                }
            ]
        )

    def test_wireless_password_too_long(self):
        """
        should fail if wpa-psk is selected and no password provided
        """
        self.do_connections_check_invalid(
            [
                {
                    "name": "wireless1",
                    "state": "up",
                    "type": "wireless",
                    "wireless": {
                        "ssid": "test wireless network",
                        "key_mgmt": "wpa-psk",
                        "password": "This password is too long and should "
                        "not be able to validate properly",
                    },
                }
            ]
        )

    def test_wireless_no_802_1x_for_wpa_eap(self):
        """
        should fail if no 802.1x parameters are defined for a wireless
        connection with key_mgmt=wpa-eap
        """
        self.do_connections_check_invalid(
            [
                {
                    "name": "wireless1",
                    "state": "up",
                    "type": "wireless",
                    "wireless": {
                        "ssid": "test wireless network",
                        "key_mgmt": "wpa-eap",
                    },
                }
            ]
        )

    def test_wireless_no_options_defined(self):
        """
        should fail if a connection of type='wireless' does not
        have any 'wireless' settings defined
        """
        self.do_connections_check_invalid(
            [{"name": "wireless1", "state": "up", "type": "wireless"}]
        )

    def test_invalid_mac(self):
        self.maxDiff = None
        self.do_connections_check_invalid(
            [{"name": "b", "type": "ethernet", "mac": "aa:b"}]
        )

    def test_interface_name_ethernet_default(self):
        """Use the profile name as interface_name for ethernet profiles"""
        cons_without_interface_name = [{"name": "eth0", "type": "ethernet"}]
        connections = ARGS_CONNECTIONS.validate(cons_without_interface_name)
        self.assertTrue(connections[0]["interface_name"] == "eth0")

    def test_interface_name_ethernet_mac(self):
        """Do not set interface_name when mac is specified"""
        cons_without_interface_name = [
            {"name": "eth0", "type": "ethernet", "mac": "3b:0b:88:16:6d:1a"}
        ]
        connections = ARGS_CONNECTIONS.validate(cons_without_interface_name)
        self.assertTrue(connections[0]["interface_name"] is None)

    def test_interface_name_ethernet_empty(self):
        """Allow not to restrict the profile to an interface"""
        network_connections = [
            {"name": "internal_network", "type": "ethernet", "interface_name": ""}
        ]
        connections = ARGS_CONNECTIONS.validate(network_connections)

        self.assertTrue(connections[0]["interface_name"] is None)

    def test_interface_name_ethernet_None(self):
        """Check that interface_name cannot be None"""
        network_connections = [
            {"name": "internal_network", "type": "ethernet", "interface_name": None}
        ]
        self.assertRaises(
            ValidationError, ARGS_CONNECTIONS.validate, network_connections
        )

    def test_interface_name_ethernet_explicit(self):
        """Use the explicitly provided interface name"""
        network_connections = [
            {"name": "internal", "type": "ethernet", "interface_name": "eth0"}
        ]
        connections = ARGS_CONNECTIONS.validate(network_connections)
        self.assertEqual(connections[0]["interface_name"], "eth0")

    def test_interface_name_ethernet_invalid_profile(self):
        """Require explicit interface_name when the profile name is not a
        valid interface_name"""
        network_connections = [{"name": "internal:main", "type": "ethernet"}]
        self.assertRaises(
            ValidationError, ARGS_CONNECTIONS.validate, network_connections
        )
        network_connections = [
            {"name": "internal:main", "type": "ethernet", "interface_name": "eth0"}
        ]
        connections = ARGS_CONNECTIONS.validate(network_connections)
        self.assertTrue(connections[0]["interface_name"] == "eth0")

    def test_interface_name_ethernet_invalid_interface_name(self):
        network_connections = [
            {"name": "internal", "type": "ethernet", "interface_name": "invalid:name"}
        ]
        self.assertRaises(
            ValidationError, ARGS_CONNECTIONS.validate, network_connections
        )

    def test_interface_name_bond_empty_interface_name(self):
        network_connections = [
            {"name": "internal", "type": "bond", "interface_name": "invalid:name"}
        ]
        self.assertRaises(
            ValidationError, ARGS_CONNECTIONS.validate, network_connections
        )

    def test_interface_name_bond_profile_as_interface_name(self):
        network_connections = [{"name": "internal", "type": "bond"}]
        connections = ARGS_CONNECTIONS.validate(network_connections)
        self.assertEqual(connections[0]["interface_name"], "internal")

    def check_connection(self, connection, expected):
        reduced_connection = {}
        for setting in expected:
            reduced_connection[setting] = connection[setting]
        self.assertEqual(reduced_connection, expected)

    def check_partial_connection_zero(self, network_config, expected):
        connections = ARGS_CONNECTIONS.validate([network_config])
        self.check_connection(connections[0], expected)

    def check_one_connection_with_defaults(
        self, network_config, expected_changed_settings
    ):
        self.maxDiff = None
        expected = self.default_connection_settings
        expected.update(expected_changed_settings)

        self.do_connections_validate([expected], [network_config])

    def test_default_states(self):
        self.check_partial_connection_zero(
            {"name": "eth0"},
            {"actions": ["present"], "persistent_state": "present", "state": None},
        )

    def test_invalid_persistent_state_up(self):
        network_connections = [{"name": "internal", "persistent_state": "up"}]
        self.assertRaises(
            ValidationError, ARGS_CONNECTIONS.validate, network_connections
        )

    def test_invalid_persistent_state_down(self):
        network_connections = [{"name": "internal", "persistent_state": "down"}]
        self.assertRaises(
            ValidationError, ARGS_CONNECTIONS.validate, network_connections
        )

    def test_invalid_state_test(self):
        network_connections = [{"name": "internal", "state": "test"}]
        self.assertRaises(
            ValidationError, ARGS_CONNECTIONS.validate, network_connections
        )

    def test_default_states_type(self):
        self.check_partial_connection_zero(
            {"name": "eth0", "type": "ethernet"},
            {"actions": ["present"], "persistent_state": "present", "state": None},
        )

    def test_persistent_state_present(self):
        self.check_partial_connection_zero(
            {"name": "eth0", "persistent_state": "present", "type": "ethernet"},
            {"actions": ["present"], "persistent_state": "present", "state": None},
        )

    def test_state_present(self):
        self.check_partial_connection_zero(
            {"name": "eth0", "state": "present", "type": "ethernet"},
            {"actions": ["present"], "persistent_state": "present", "state": None},
        )

    def test_state_absent(self):
        self.check_partial_connection_zero(
            {"name": "eth0", "state": "absent"},
            {"actions": ["absent"], "persistent_state": "absent", "state": None},
        )

    def test_persistent_state_absent(self):
        self.check_partial_connection_zero(
            {"name": "eth0", "persistent_state": "absent"},
            {"actions": ["absent"], "persistent_state": "absent", "state": None},
        )

    def test_state_present_up(self):
        self.check_partial_connection_zero(
            {
                "name": "eth0",
                "persistent_state": "present",
                "state": "up",
                "type": "ethernet",
            },
            {
                "actions": ["present", "up"],
                "persistent_state": "present",
                "state": "up",
            },
        )

    def test_state_present_down(self):
        self.check_partial_connection_zero(
            {
                "name": "eth0",
                "persistent_state": "present",
                "state": "down",
                "type": "ethernet",
            },
            {
                "actions": ["present", "down"],
                "persistent_state": "present",
                "state": "down",
            },
        )

    def test_state_absent_up_no_type(self):
        self.check_partial_connection_zero(
            {"name": "eth0", "persistent_state": "absent", "state": "up"},
            {"actions": ["absent", "up"], "persistent_state": "absent", "state": "up"},
        )

    def test_state_absent_up_type(self):
        # if type is specified, present should happen, too
        self.check_partial_connection_zero(
            {
                "name": "eth0",
                "persistent_state": "absent",
                "state": "up",
                "type": "ethernet",
            },
            {
                "actions": ["present", "absent", "up"],
                "persistent_state": "absent",
                "state": "up",
            },
        )

    def test_state_absent_down(self):
        # if type is specified, present should happen, too
        self.check_partial_connection_zero(
            {"name": "eth0", "persistent_state": "absent", "state": "down"},
            {
                "actions": ["absent", "down"],
                "persistent_state": "absent",
                "state": "down",
            },
        )

    def test_state_up_no_type(self):
        self.check_partial_connection_zero(
            {"name": "eth0", "state": "up"},
            {
                "actions": ["present", "up"],
                "persistent_state": "present",
                "state": "up",
            },
        )

    def test_state_up_type(self):
        self.check_partial_connection_zero(
            {"name": "eth0", "state": "up", "type": "ethernet"},
            {
                "actions": ["present", "up"],
                "persistent_state": "present",
                "state": "up",
            },
        )

    def test_state_down_no_type(self):
        self.check_partial_connection_zero(
            {"name": "eth0", "state": "down"},
            {
                "actions": ["present", "down"],
                "persistent_state": "present",
                "state": "down",
            },
        )

    def test_full_state_present_no_type(self):
        self.maxDiff = None
        self.do_connections_validate(
            [
                {
                    "actions": ["present"],
                    "ignore_errors": None,
                    "name": "eth0",
                    "state": None,
                    "persistent_state": "present",
                }
            ],
            [{"name": "eth0", "persistent_state": "present"}],
        )

    def test_full_state_present_type_defaults(self):
        self.check_one_connection_with_defaults(
            {"name": "eth0", "type": "ethernet", "persistent_state": "present"},
            {
                "actions": ["present"],
                "interface_name": "eth0",
                "name": "eth0",
                "persistent_state": "present",
                "state": None,
                "type": "ethernet",
            },
        )

    def test_full_state_absent_no_type(self):
        self.maxDiff = None
        self.do_connections_validate(
            [
                {
                    "actions": ["absent"],
                    "ignore_errors": None,
                    "name": "eth0",
                    "state": None,
                    "persistent_state": "absent",
                }
            ],
            [{"name": "eth0", "persistent_state": "absent"}],
        )

    def test_full_state_absent_defaults(self):
        self.maxDiff = None
        self.check_one_connection_with_defaults(
            {"name": "eth0", "persistent_state": "absent", "type": "ethernet"},
            {
                "actions": ["absent"],
                "ignore_errors": None,
                "name": "eth0",
                "state": None,
                "persistent_state": "absent",
                "type": "ethernet",
                "interface_name": "eth0",
            },
        )

    def _test_ethtool_changes(self, input_ethtool, expected_ethtool):
        """
        When passing a dictionary 'input_features' with each feature and their
        value to change, and a dictionary 'expected_features' with the expected
        result in the configuration, the expected and resulting connection are
        created and validated.
        """
        expected_ethtool_full = copy.deepcopy(ETHTOOL_DEFAULTS)
        for key in list(expected_ethtool_full):
            if key in expected_ethtool:
                expected_ethtool_full[key].update(expected_ethtool[key])

        input_connection = {
            "ethtool": input_ethtool,
            "name": "5",
            "persistent_state": "present",
            "type": "ethernet",
        }

        expected_connection = {
            "actions": ["present"],
            "ethtool": expected_ethtool_full,
            "interface_name": "5",
            "persistent_state": "present",
            "state": None,
            "type": "ethernet",
        }
        self.check_one_connection_with_defaults(input_connection, expected_connection)

    def test_set_ethtool_feature(self):
        """
        When passing the name of an non-deprecated ethtool feature, their
        current version is updated.
        """
        input_ethtool = {"features": {"tx_tcp_segmentation": "yes"}}
        expected_ethtool = {"features": {"tx_tcp_segmentation": True}}
        self._test_ethtool_changes(input_ethtool, expected_ethtool)

    def test_set_deprecated_ethtool_feature(self):
        """
        When passing a deprecated name, their current version is updated.
        """
        input_ethtool = {"features": {"esp-hw-offload": "yes"}}
        expected_ethtool = {"features": {"esp_hw_offload": True}}
        self._test_ethtool_changes(input_ethtool, expected_ethtool)

    def test_invalid_ethtool_settings(self):
        """
        When both the deprecated and current version of a feature are stated,
        a Validation Error is raised.
        """
        input_features = {"tx-tcp-segmentation": "yes", "tx_tcp_segmentation": "yes"}
        features_validator = (
            network_lsr.argument_validator.ArgValidator_DictEthtoolFeatures()
        )
        self.assertValidationError(features_validator, input_features)

    def test_deprecated_ethtool_names(self):
        """
        Test that for each validator in
        ArgValidator_DictEthtoolFeatures.nested there is another non-deprecated
        validator that has the name from the deprecated_by attribute"
        """
        validators = (
            network_lsr.argument_validator.ArgValidator_DictEthtoolFeatures().nested
        )
        for name, validator in validators.items():
            if isinstance(
                validator, network_lsr.argument_validator.ArgValidatorDeprecated
            ):
                assert validator.deprecated_by in validators.keys()

    def test_valid_persistent_state(self):
        """
        Test that when persistent_state is present and state is set to present
        or absent, a ValidationError raises.
        """
        validator = network_lsr.argument_validator.ArgValidator_DictConnection()
        input_connection = {
            "name": "test",
            "persistent_state": "present",
            "state": "present",
            "type": "ethernet",
        }
        self.assertValidationError(validator, input_connection)
        input_connection.update({"state": "absent"})
        self.assertValidationError(validator, input_connection)

    def test_dns_options_argvalidator(self):
        """
        Test that argvalidator for validating dns_options value is correctly defined.
        """
        validator = network_lsr.argument_validator.ArgValidator_DictIP()

        false_testcase_1 = {
            "dns_options": ["attempts:01"],
        }
        false_testcase_2 = {
            "dns_options": ["debug$"],
        }
        false_testcase_3 = {
            "dns_options": ["edns00"],
        }
        false_testcase_4 = {
            "dns_options": ["ndots:"],
        }
        false_testcase_5 = {
            "dns_options": ["no-check-name"],
        }
        false_testcase_6 = {
            "dns_options": ["no-rel0ad"],
        }
        false_testcase_7 = {
            "dns_options": ["bugno-tld-query"],
        }
        false_testcase_8 = {
            "dns_options": ["etator"],
        }
        false_testcase_9 = {
            "dns_options": ["singlerequest"],
        }
        false_testcase_10 = {
            "dns_options": ["single-request-reopen:2"],
        }
        false_testcase_11 = {
            "dns_options": ["timeout"],
        }
        false_testcase_12 = {
            "dns_options": ["*trust-ad*"],
        }
        false_testcase_13 = {
            "dns_options": ["use1-vc2-use-vc"],
        }

        self.assertValidationError(validator, false_testcase_1)
        self.assertValidationError(validator, false_testcase_2)
        self.assertValidationError(validator, false_testcase_3)
        self.assertValidationError(validator, false_testcase_4)
        self.assertValidationError(validator, false_testcase_5)
        self.assertValidationError(validator, false_testcase_6)
        self.assertValidationError(validator, false_testcase_7)
        self.assertValidationError(validator, false_testcase_8)
        self.assertValidationError(validator, false_testcase_9)
        self.assertValidationError(validator, false_testcase_10)
        self.assertValidationError(validator, false_testcase_11)
        self.assertValidationError(validator, false_testcase_12)
        self.assertValidationError(validator, false_testcase_13)

        true_testcase_1 = {
            "dns_options": ["attempts:3"],
        }
        true_testcase_2 = {
            "dns_options": ["debug"],
        }
        true_testcase_3 = {
            "dns_options": ["ndots:3", "single-request-reopen"],
        }
        true_testcase_4 = {
            "dns_options": ["ndots:2", "timeout:3"],
        }
        true_testcase_5 = {
            "dns_options": ["no-check-names"],
        }
        true_testcase_6 = {
            "dns_options": ["no-reload"],
        }
        true_testcase_7 = {
            "dns_options": ["no-tld-query"],
        }
        true_testcase_8 = {
            "dns_options": ["rotate"],
        }
        true_testcase_9 = {
            "dns_options": ["single-request"],
        }
        true_testcase_10 = {
            "dns_options": ["single-request-reopen"],
        }
        true_testcase_11 = {
            "dns_options": ["trust-ad"],
        }
        true_testcase_12 = {
            "dns_options": ["use-vc"],
        }

        self.assertEqual(
            validator.validate(true_testcase_1)["dns_options"], ["attempts:3"]
        )
        self.assertEqual(validator.validate(true_testcase_2)["dns_options"], ["debug"])
        self.assertEqual(
            validator.validate(true_testcase_3)["dns_options"],
            ["ndots:3", "single-request-reopen"],
        )
        self.assertEqual(
            validator.validate(true_testcase_4)["dns_options"], ["ndots:2", "timeout:3"]
        )
        self.assertEqual(
            validator.validate(true_testcase_5)["dns_options"], ["no-check-names"]
        )
        self.assertEqual(
            validator.validate(true_testcase_6)["dns_options"], ["no-reload"]
        )
        self.assertEqual(
            validator.validate(true_testcase_7)["dns_options"], ["no-tld-query"]
        )
        self.assertEqual(validator.validate(true_testcase_8)["dns_options"], ["rotate"])
        self.assertEqual(
            validator.validate(true_testcase_9)["dns_options"], ["single-request"]
        )
        self.assertEqual(
            validator.validate(true_testcase_10)["dns_options"],
            ["single-request-reopen"],
        )
        self.assertEqual(
            validator.validate(true_testcase_11)["dns_options"], ["trust-ad"]
        )
        self.assertEqual(
            validator.validate(true_testcase_12)["dns_options"], ["use-vc"]
        )

    def test_ipv4_dns_without_ipv4_config(self):
        """
        Test that configuring IPv4 DNS is not allowed when IPv4 is disabled.
        """
        validator = network_lsr.argument_validator.ArgValidator_ListConnections()
        ipv4_dns_without_ipv4_config = [
            {
                "name": "test_ipv4_dns",
                "type": "ethernet",
                "ip": {
                    "auto6": True,
                    "dhcp4": False,
                    "dns": ["198.51.100.5"],
                },
            }
        ]
        self.assertRaises(
            ValidationError,
            validator.validate_connection_one,
            "nm",
            validator.validate(ipv4_dns_without_ipv4_config),
            0,
        )

    def test_ipv6_dns_without_ipv6_config(self):
        """
        Test that configuring IPv6 DNS is not allowed when IPv6 is disabled.
        """
        validator = network_lsr.argument_validator.ArgValidator_ListConnections()
        ipv6_dns_without_ipv6_config = [
            {
                "name": "test_ipv6_dns",
                "type": "ethernet",
                "ip": {
                    "ipv6_disabled": True,
                    "dhcp4": True,
                    "dns": ["2001:db8::20"],
                },
            }
        ]
        self.assertRaises(
            ValidationError,
            validator.validate_connection_one,
            "nm",
            validator.validate(ipv6_dns_without_ipv6_config),
            0,
        )

    def test_ipv6_dns_options_without_ipv6_config(self):
        """
        Test that configuring IPv6 DNS options is not allowed when IPv6 is disabled.
        """
        validator = network_lsr.argument_validator.ArgValidator_ListConnections()
        ipv6_dns_options_without_ipv6_config = [
            {
                "name": "test_ipv6_dns",
                "type": "ethernet",
                "ip": {
                    "ipv6_disabled": True,
                    "dhcp4": True,
                    "dns_options": ["ip6-bytestring"],
                },
            }
        ]
        self.assertRaises(
            ValidationError,
            validator.validate_connection_one,
            "nm",
            validator.validate(ipv6_dns_options_without_ipv6_config),
            0,
        )

    def test_set_deprecated_master(self):
        """
        When passing the deprecated "master" it is updated to "controller".
        """
        input_connections = [
            {
                "name": "prod2",
                "state": "up",
                "type": "bridge",
            },
            {
                "name": "prod2-port1",
                "state": "up",
                "type": "ethernet",
                "interface_name": "eth1",
                "master": "prod2",
            },
        ]
        connections = ARGS_CONNECTIONS.validate(input_connections)
        self.assertTrue(len(connections) == 2)
        for connection in connections:
            self.assertTrue("controller" in connection)
            self.assertTrue("master" not in connection)

    def test_set_deprecated_slave_type(self):
        """
        When passing the deprecated "slave_type" it is updated to "port_type".
        """
        input_connections = [
            {
                "name": "prod2",
                "state": "up",
                "type": "bridge",
            },
            {
                "name": "prod2-port1",
                "state": "up",
                "type": "ethernet",
                "interface_name": "eth1",
                "controller": "prod2",
                "slave_type": "bridge",
            },
        ]
        connections = ARGS_CONNECTIONS.validate(input_connections)
        self.assertTrue(len(connections) == 2)
        for connection in connections:
            self.assertTrue("port_type" in connection)
            self.assertTrue("slave_type" not in connection)


@my_test_skipIf(nmutil is None, "no support for NM (libnm via pygobject)")
class TestNM(unittest.TestCase):
    def test_connection_ensure_setting(self):
        con = NM.SimpleConnection.new()
        self.assertIsNotNone(con)
        self.assertTrue(GObject.type_is_a(con, NM.Connection))

        s = nmutil.connection_ensure_setting(con, NM.SettingWired)
        self.assertIsNotNone(s)
        self.assertTrue(GObject.type_is_a(s, NM.SettingWired))

        s2 = nmutil.connection_ensure_setting(con, NM.SettingWired)
        self.assertIsNotNone(s2)
        self.assertIs(s, s2)
        self.assertTrue(GObject.type_is_a(s, NM.SettingWired))

    def test_connection_list(self):
        connections = nmutil.connection_list()
        self.assertIsNotNone(connections)

    def test_path_to_glib_bytes(self):
        result = Util.path_to_glib_bytes("/my/test/path")
        self.assertIsInstance(result, Util.GLib().Bytes)
        self.assertEqual(result.get_data(), b"file:///my/test/path\x00")


class TestUtils(unittest.TestCase):
    def test_mac_ntoa(self):
        mac_bytes = b"\xaa\xbb\xcc\xdd\xee\xff"
        self.assertEqual(Util.mac_ntoa(mac_bytes), "aa:bb:cc:dd:ee:ff")

    def test_convert_passwd_flags_nm(self):
        test_cases = [
            ([], 0),
            (["none"], 0),
            (["agent-owned"], 1),
            (["not-saved"], 2),
            (["agent-owned", "not-saved"], 3),
            (
                ["not-required"],
                4,
            ),
            (["agent-owned", "not-required"], 5),
            (["not-saved", "not-required"], 6),
            (["agent-owned", "not-saved", "not-required"], 7),
        ]

        for test_case in test_cases:
            result = Util.convert_passwd_flags_nm(test_case[0])
            self.assertEqual(result, test_case[1])


class TestSysUtils(unittest.TestCase):
    def test_link_read_permaddress(self):
        self.assertEqual(SysUtil._link_read_permaddress("lo"), "00:00:00:00:00:00")
        self.assertEqual(SysUtil._link_read_permaddress("fakeiface"), None)
        self.assertEqual(SysUtil._link_read_permaddress("morethansixteenchars"), None)


if __name__ == "__main__":
    unittest.main()
