#!/usr/bin/env python

import sys
import os
import unittest
import socket

sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))

import network_connections as n

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
    nmutil = n.NMUtil()
    assert(nmutil)
except:
    # NMUtil is not supported, for example on RHEL 6 or without
    # pygobject.
    nmutil = None

if nmutil:
    NM = n.Util.NM()
    GObject = n.Util.GObject()

def pprint(msg, obj):
    print('PRINT: %s\n' % (msg))
    import pprint
    p = pprint.PrettyPrinter(indent = 4)
    p.pprint(obj)
    if nmutil is not None and isinstance(obj, NM.Connection):
        obj.dump()

class TestValidator(unittest.TestCase):

    def assertValidationError(self, v, value):
        self.assertRaises(n.ValidationError,
                          v.validate,
                          value)

    def do_connections_check_invalid(self, input_connections):
        self.assertValidationError(n.AnsibleUtil.ARGS_CONNECTIONS, input_connections)

    def do_connections_validate_nm(self, input_connections):
        if not nmutil:
            return
        connections = n.AnsibleUtil.ARGS_CONNECTIONS.validate(input_connections)
        for connection in connections:
            if 'type' in connection:
                connection['nm.exists'] = False
                connection['nm.uuid'] = n.Util.create_uuid()
        mode = n.ArgValidator_ListConnections.VALIDATE_ONE_MODE_INITSCRIPTS
        for idx, connection in enumerate(connections):
            try:
                n.AnsibleUtil.ARGS_CONNECTIONS.validate_connection_one(mode, connections, idx)
            except n.ValidationError as e:
                continue
            if 'type' in connection:
                con_new = nmutil.connection_create(connections, idx)
                self.assertTrue(con_new)
                self.assertTrue(con_new.verify())

    def do_connections_validate_ifcfg(self, input_connections):
        mode = n.ArgValidator_ListConnections.VALIDATE_ONE_MODE_INITSCRIPTS
        connections = n.AnsibleUtil.ARGS_CONNECTIONS.validate(input_connections)
        for idx, connection in enumerate(connections):
            try:
                n.AnsibleUtil.ARGS_CONNECTIONS.validate_connection_one(mode, connections, idx)
            except n.ValidationError as e:
                continue
            if 'type' in connection:
                c = n.IfcfgUtil.ifcfg_create(connections, idx)

    def do_connections_validate(self, expected_connections, input_connections):
        connections = n.AnsibleUtil.ARGS_CONNECTIONS.validate(input_connections)
        self.assertEqual(expected_connections, connections)
        self.do_connections_validate_nm(input_connections)
        self.do_connections_validate_ifcfg(input_connections)

    def test_validate_str(self):

        v = n.ArgValidatorStr('state')
        self.assertEqual('a', v.validate('a'))
        self.assertValidationError(v, 1);
        self.assertValidationError(v, None);

        v = n.ArgValidatorStr('state', required = True)
        self.assertValidationError(v, None)

    def test_validate_int(self):

        v = n.ArgValidatorNum('state', default_value = None, numeric_type = float)
        self.assertEqual(1, v.validate(1))
        self.assertEqual(1.5, v.validate(1.5))
        self.assertEqual(1.5, v.validate("1.5"))
        self.assertValidationError(v, None)
        self.assertValidationError(v, "1a")

        v = n.ArgValidatorNum('state', default_value = None)
        self.assertEqual(1, v.validate(1))
        self.assertEqual(1, v.validate(1.0))
        self.assertEqual(1, v.validate("1"))
        self.assertValidationError(v, None)
        self.assertValidationError(v, None)
        self.assertValidationError(v, 1.5)
        self.assertValidationError(v, "1.5")

        v = n.ArgValidatorNum('state', required = True)
        self.assertValidationError(v, None)

    def test_validate_bool(self):

        v = n.ArgValidatorBool('state')
        self.assertEqual(True, v.validate(True))
        self.assertEqual(True, v.validate("True"))
        self.assertEqual(True, v.validate(1))
        self.assertEqual(False, v.validate(False))
        self.assertEqual(False, v.validate("False"))
        self.assertEqual(False, v.validate(0))
        self.assertValidationError(v, 2)

        self.assertValidationError(v, None)
        v = n.ArgValidatorBool('state', required = True)
        self.assertValidationError(v, None)

    def test_validate_dict(self):

        v = n.ArgValidatorDict(
            'dict',
            nested = [
                n.ArgValidatorNum('i', required = True),
                n.ArgValidatorStr('s', required = False, default_value = 's_default'),
                n.ArgValidatorStr('l', required = False, default_value = n.ArgValidator.MISSING),
            ])

        self.assertEqual(
            {
                'i': 5,
                's': 's_default',
            },
            v.validate({
                'i': '5',
            })
        )
        self.assertEqual(
            {
                'i': 5,
                's': 's_default',
                'l': '6',
            },
            v.validate({
                'i': '5',
                'l': '6',
            })
        )
        self.assertValidationError(v, { 'k': 1 })

    def test_validate_list(self):

        v = n.ArgValidatorList(
            'list',
            nested = n.ArgValidatorNum('i')
        )
        self.assertEqual(
            [ 1, 5 ],
            v.validate([ '1', 5 ])
        )
        self.assertValidationError(v, [1, 's'])

    def test_1(self):

        self.maxDiff = None

        self.do_connections_validate(
            [],
            [],
        )

        self.do_connections_validate(
            [
                {
                    'name': '5',
                    'state': 'present',
                    'type': 'ethernet',
                    'autoconnect': True,
                    'parent': None,
                    'ip': {
                        'gateway6': None,
                        'gateway4': None,
                        'route_metric4': None,
                        'auto6': True,
                        'dhcp4': True,
                        'address': [],
                        'route_metric6': None,
                        'dhcp4_send_hostname': None,
                        'dns': [],
                        'dns_search': [],
                    },
                    'mac': None,
                    'mtu': None,
                    'master': None,
                    'vlan_id': None,
                    'ignore_errors': None,
                    'interface_name': None,
                    'check_iface_exists': True,
                    'slave_type': None,
                    'infiniband_p_key': None,
                    'infiniband_transport_mode': None,
                },
                {
                    'name': '5',
                    'state': 'up',
                    'force_state_change': None,
                    'wait': None,
                    'ignore_errors': None,
                }
            ],
            [
                { 'name': '5',
                  'type': 'ethernet',
                },
                { 'name': '5' }
            ],
        )
        self.do_connections_validate(
            [
                {
                    'name': '5',
                    'state': 'up',
                    'type': 'ethernet',
                    'autoconnect': True,
                    'parent': None,
                    'ip': {
                        'gateway6': None,
                        'gateway4': None,
                        'route_metric4': None,
                        'auto6': True,
                        'dhcp4': True,
                        'address': [],
                        'dns': [],
                        'dns_search': [],
                        'route_metric6': None,
                        'dhcp4_send_hostname': None,
                    },
                    'mac': None,
                    'mtu': None,
                    'master': None,
                    'vlan_id': None,
                    'ignore_errors': None,
                    'interface_name': None,
                    'check_iface_exists': True,
                    'force_state_change': None,
                    'slave_type': None,
                    'wait': None,
                    'infiniband_p_key': None,
                    'infiniband_transport_mode': None,
                },
            ],
            [
                { 'name': '5',
                  'state': 'up',
                  'type': 'ethernet',
                },
            ],
        )

        self.do_connections_check_invalid([ { 'name': 'a', 'autoconnect': True }])

        self.do_connections_validate(
            [
                {
                    'name': '5',
                    'state': 'absent',
                    'ignore_errors': None,
                }
            ],
            [
                {
                    'name': '5',
                    'state': 'absent',
                }
            ],
        )

        self.do_connections_validate(
            [
                {
                    'autoconnect': True,
                    'name': 'prod1',
                    'parent': None,
                    'ip': {
                        'dhcp4': False,
                        'route_metric6': None,
                        'route_metric4': None,
                        'dns_search': [],
                        'dhcp4_send_hostname': None,
                        'gateway6': None,
                        'gateway4': None,
                        'auto6': True,
                        'dns': [],
                        'address': [
                            {
                                'prefix': 24,
                                'family': socket.AF_INET,
                                'address': '192.168.174.5'
                            }
                        ]
                    },
                    'state': 'up',
                    'mtu': 1450,
                    'check_iface_exists': True,
                    'force_state_change': None,
                    'mac': '52:54:00:44:9f:ba',
                    'master': None,
                    'vlan_id': None,
                    'ignore_errors': None,
                    'interface_name': None,
                    'type': 'ethernet',
                    'slave_type': None,
                    'wait': None,
                    'infiniband_p_key': None,
                    'infiniband_transport_mode': None,
                },
            ],
            [
                {
                    'name': 'prod1',
                    'state': 'up',
                    'type': 'ethernet',
                    'autoconnect': 'yes',
                    'mac': '52:54:00:44:9f:ba',
                    'mtu': 1450,
                    'ip': {
                        'address': '192.168.174.5/24',
                    }
                }
            ],
        )

        self.do_connections_validate(
            [
                {
                    'autoconnect': True,
                    'name': 'prod1',
                    'parent': None,
                    'ip': {
                        'dhcp4': False,
                        'auto6': True,
                        'address': [
                            {
                                'prefix': 24,
                                'family': socket.AF_INET,
                                'address': '192.168.176.5'
                            },
                            {
                                'prefix': 24,
                                'family': socket.AF_INET,
                                'address': '192.168.177.5'
                            }
                        ],
                        'route_metric6': None,
                        'route_metric4': None,
                        'dns_search': [],
                        'dhcp4_send_hostname': None,
                        'gateway6': None,
                        'gateway4': None,
                        'dns': []
                    },
                    'state': 'up',
                    'mtu': 1450,
                    'check_iface_exists': True,
                    'force_state_change': None,
                    'mac': '52:54:00:44:9f:ba',
                    'master': None,
                    'vlan_id': None,
                    'ignore_errors': None,
                    'interface_name': None,
                    'type': 'ethernet',
                    'slave_type': None,
                    'wait': None,
                    'infiniband_p_key': None,
                    'infiniband_transport_mode': None,
                },
                {
                    'autoconnect': True,
                    'name': 'prod.100',
                    'parent': 'prod1',
                    'ip': {
                        'dhcp4': False,
                        'route_metric6': None,
                        'route_metric4': None,
                        'dns_search': [],
                        'dhcp4_send_hostname': None,
                        'gateway6': None,
                        'gateway4': None,
                        'auto6': False,
                        'dns': [],
                        'address': [
                            {
                                'prefix': 24,
                                'family': socket.AF_INET,
                                'address': '192.168.174.5'
                            },
                            {
                                'prefix': 65,
                                'family': socket.AF_INET6,
                                'address': 'a:b:c::6',
                            },
                        ]
                    },
                    'mac': None,
                    'mtu': None,
                    'check_iface_exists': True,
                    'force_state_change': None,
                    'state': 'up',
                    'master': None,
                    'slave_type': None,
                    'ignore_errors': None,
                    'interface_name': 'prod.100',
                    'type': 'vlan',
                    'vlan_id': 100,
                    'wait': None,
                    'infiniband_p_key': None,
                    'infiniband_transport_mode': None,
                }
            ],
            [
                {
                    'name': 'prod1',
                    'state': 'up',
                    'type': 'ethernet',
                    'autoconnect': 'yes',
                    'mac': '52:54:00:44:9f:ba',
                    'mtu': 1450,
                    'ip': {
                        'address': '192.168.176.5/24 192.168.177.5/24',
                    }
                },
                {
                    'name': 'prod.100',
                    'state': 'up',
                    'type': 'vlan',
                    'parent': 'prod1',
                    'vlan_id': '100',
                    'ip': {
                        'address': [
                            '192.168.174.5/24',
                            {
                                'address': 'a:b:c::6',
                                'prefix': 65,
                            },
                        ],
                    }
                }
            ],
        )

        self.do_connections_validate(
            [
                {
                    'autoconnect': True,
                    'name': 'prod2',
                    'parent': None,
                    'ip': {
                        'dhcp4': False,
                        'route_metric6': None,
                        'route_metric4': None,
                        'dns_search': [],
                        'dhcp4_send_hostname': None,
                        'gateway6': None,
                        'gateway4': None,
                        'auto6': False,
                        'dns': [],
                        'address': []
                    },
                    'mac': None,
                    'mtu': None,
                    'check_iface_exists': True,
                    'force_state_change': None,
                    'state': 'up',
                    'master': None,
                    'vlan_id': None,
                    'ignore_errors': None,
                    'interface_name': 'bridge2',
                    'type': 'bridge',
                    'slave_type': None,
                    'wait': None,
                    'infiniband_p_key': None,
                    'infiniband_transport_mode': None,
                },
                {
                    'autoconnect': True,
                    'name': 'prod2-slave1',
                    'parent': None,
                    'ip': {
                        'dhcp4': True,
                        'auto6': True,
                        'address': [],
                        'route_metric6': None,
                        'route_metric4': None,
                        'dns_search': [],
                        'dhcp4_send_hostname': None,
                        'gateway6': None,
                        'gateway4': None,
                        'dns': []
                    },
                    'mac': None,
                    'mtu': None,
                    'check_iface_exists': True,
                    'force_state_change': None,
                    'state': 'up',
                    'master': 'prod2',
                    'vlan_id': None,
                    'ignore_errors': None,
                    'interface_name': 'eth1',
                    'type': 'ethernet',
                    'slave_type': 'bridge',
                    'wait': None,
                    'infiniband_p_key': None,
                    'infiniband_transport_mode': None,
                }
            ],
            [
                {
                    'name': 'prod2',
                    'state': 'up',
                    'type': 'bridge',
                    'interface_name': 'bridge2',
                    'ip': {
                      'dhcp4': False,
                      'auto6': False,
                    },
                },
                {
                    'name': 'prod2-slave1',
                    'state': 'up',
                    'type': 'ethernet',
                    'interface_name': 'eth1',
                    'master': 'prod2',
                }
            ],
        )

        self.do_connections_validate(
            [
                {
                    'autoconnect': True,
                    'name': 'bond1',
                    'parent': None,
                    'ip': {
                        'dhcp4': True,
                        'route_metric6': None,
                        'route_metric4': None,
                        'dns_search': [],
                        'dhcp4_send_hostname': None,
                        'gateway6': None,
                        'gateway4': None,
                        'auto6': True,
                        'dns': [],
                        'address': []
                    },
                    'mac': None,
                    'mtu': None,
                    'check_iface_exists': True,
                    'force_state_change': None,
                    'state': 'up',
                    'master': None,
                    'vlan_id': None,
                    'ignore_errors': None,
                    'interface_name': 'bond1',
                    'type': 'bond',
                    'slave_type': None,
                    'bond': {
                        'mode': 'balance-rr',
                        'miimon': None,
                    },
                    'wait': None,
                    'infiniband_p_key': None,
                    'infiniband_transport_mode': None,
                },
            ],
            [
                {
                    'name': 'bond1',
                    'state': 'up',
                    'type': 'bond',
                },
            ],
        )

        self.do_connections_validate(
            [
                {
                    'autoconnect': True,
                    'name': 'bond1',
                    'parent': None,
                    'ip': {
                        'dhcp4': True,
                        'route_metric6': None,
                        'route_metric4': None,
                        'dns_search': [],
                        'dhcp4_send_hostname': None,
                        'gateway6': None,
                        'gateway4': None,
                        'auto6': True,
                        'dns': [],
                        'address': []
                    },
                    'mac': None,
                    'mtu': None,
                    'check_iface_exists': True,
                    'force_state_change': None,
                    'state': 'up',
                    'master': None,
                    'vlan_id': None,
                    'ignore_errors': None,
                    'interface_name': 'bond1',
                    'type': 'bond',
                    'slave_type': None,
                    'bond': {
                        'mode': 'active-backup',
                        'miimon': None,
                    },
                    'wait': None,
                    'infiniband_p_key': None,
                    'infiniband_transport_mode': None,
                },
            ],
            [
                {
                    'name': 'bond1',
                    'state': 'up',
                    'type': 'bond',
                    'bond': {
                        'mode': 'active-backup',
                    },
                },
            ],
        )

        self.do_connections_check_invalid([ { } ])
        self.do_connections_check_invalid([ { 'name': 'b', 'xxx': 5 } ])

        self.do_connections_validate(
            [
                {
                    'autoconnect': True,
                    'interface_name': None,
                    'ip': {
                        'address': [],
                        'auto6': True,
                        'dhcp4': True,
                        'dhcp4_send_hostname': None,
                        'gateway4': None,
                        'gateway6': None,
                        'route_metric4': None,
                        'route_metric6': None,
                        'dns': [],
                        'dns_search': [],
                    },
                    'mac': 'aa:bb:cc:dd:ee:ff',
                    'mtu': None,
                    'master': None,
                    'check_iface_exists': True,
                    'name': '5',
                    'parent': None,
                    'ignore_errors': None,
                    'slave_type': None,
                    'state': 'present',
                    'type': 'ethernet',
                    'vlan_id': None,
                    'infiniband_p_key': None,
                    'infiniband_transport_mode': None,
                },
            ],
            [
                {
                    'name': '5',
                    'type': 'ethernet',
                    'mac': 'AA:bb:cC:DD:ee:FF',
                }
            ],
        )

        self.do_connections_validate(
            [
                {
                    'name': '5',
                    'state': 'up',
                    'type': 'ethernet',
                    'autoconnect': True,
                    'parent': None,
                    'ip': {
                        'gateway6': None,
                        'gateway4': None,
                        'route_metric4': None,
                        'auto6': True,
                        'dhcp4': True,
                        'address': [],
                        'dns': [],
                        'dns_search': [ ],
                        'route_metric6': None,
                        'dhcp4_send_hostname': None,
                    },
                    'mac': None,
                    'mtu': None,
                    'master': None,
                    'vlan_id': None,
                    'ignore_errors': None,
                    'interface_name': None,
                    'check_iface_exists': True,
                    'force_state_change': None,
                    'slave_type': None,
                    'wait': None,
                    'infiniband_p_key': None,
                    'infiniband_transport_mode': None,
                },
            ],
            [
                { 'name': '5',
                  'state': 'up',
                  'type': 'ethernet',
                },
            ],
        )

        self.do_connections_validate(
            [
                {
                    'name': '5',
                    'state': 'up',
                    'type': 'ethernet',
                    'autoconnect': True,
                    'parent': None,
                    'ip': {
                        'gateway6': None,
                        'gateway4': None,
                        'route_metric4': None,
                        'auto6': True,
                        'dhcp4': True,
                        'address': [],
                        'dns': [],
                        'dns_search': [ ],
                        'route_metric6': None,
                        'dhcp4_send_hostname': None,
                    },
                    'mac': None,
                    'mtu': None,
                    'master': None,
                    'vlan_id': None,
                    'ignore_errors': None,
                    'interface_name': None,
                    'check_iface_exists': True,
                    'force_state_change': None,
                    'slave_type': None,
                    'wait': None,
                    'infiniband_p_key': None,
                    'infiniband_transport_mode': None,
                },
            ],
            [
                { 'name': '5',
                  'state': 'up',
                  'type': 'ethernet',
                  'ip': {
                  },
                },
            ],
        )

        self.do_connections_validate(
            [
                {
                    'name': '5',
                    'state': 'up',
                    'type': 'ethernet',
                    'autoconnect': True,
                    'parent': None,
                    'ip': {
                        'gateway6': None,
                        'gateway4': None,
                        'route_metric4': None,
                        'auto6': True,
                        'dhcp4': True,
                        'address': [],
                        'dns': [],
                        'dns_search': [ 'aa', 'bb' ],
                        'route_metric6': None,
                        'dhcp4_send_hostname': None,
                    },
                    'mac': None,
                    'mtu': None,
                    'master': None,
                    'vlan_id': None,
                    'ignore_errors': None,
                    'interface_name': None,
                    'check_iface_exists': True,
                    'force_state_change': None,
                    'slave_type': None,
                    'wait': None,
                    'infiniband_p_key': None,
                    'infiniband_transport_mode': None,
                },
            ],
            [
                { 'name': '5',
                  'state': 'up',
                  'type': 'ethernet',
                  'ip': {
                      'dns_search': [ 'aa', 'bb' ],
                  },
                },
            ],
        )

        self.do_connections_check_invalid([ { 'name': 'b', 'type': 'ethernet', 'mac': 'aa:b' } ])

@my_test_skipIf(nmutil is None, 'no support for NM (libnm via pygobject)')
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

if __name__ == '__main__':
    unittest.main()
