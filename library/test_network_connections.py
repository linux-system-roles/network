#!/usr/bin/env python

import sys
import os
import unittest

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
except:
    # NMUtil is not supported, for example on RHEL 6 or without
    # pygobject.
    nmutil = None

class TestValidator(unittest.TestCase):

    def assertValidationError(self, v, value):
        self.assertRaises(n.ValidationError,
                          v.validate,
                          value)

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

        self.assertEqual(
            [],
            n.AnsibleUtil.ARGS_CONNECTIONS.validate([]),
        )

        self.assertEqual(
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
                        'ip_is_present': False,
                        'dhcp4_send_hostname': None,
                        'dns': [],
                        'dns_search': [],
                    },
                    'mac': None,
                    'master': None,
                    'vlan_id': None,
                    'ignore_errors': None,
                    'interface_name': None,
                    'check_iface_exists': True,
                    'slave_type': None,
                },
                {
                    'name': '5',
                    'state': 'up',
                    'wait': None,
                    'ignore_errors': None,
                }
            ],
            n.AnsibleUtil.ARGS_CONNECTIONS.validate([
                { 'name': '5',
                  'type': 'ethernet',
                },
                { 'name': '5' }
            ]),
        )
        self.assertEqual(
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
                        'ip_is_present': False,
                        'dhcp4_send_hostname': None,
                    },
                    'mac': None,
                    'master': None,
                    'vlan_id': None,
                    'ignore_errors': None,
                    'interface_name': None,
                    'check_iface_exists': True,
                    'slave_type': None,
                    'wait': None,
                },
            ],
            n.AnsibleUtil.ARGS_CONNECTIONS.validate([
                { 'name': '5',
                  'state': 'up',
                  'type': 'ethernet',
                },
            ]),
        )

        self.assertValidationError(n.AnsibleUtil.ARGS_CONNECTIONS,
                                   [ { 'name': 'a', 'autoconnect': True }])

        self.assertEqual(
            [
                {
                    'name': '5',
                    'state': 'absent',
                    'ignore_errors': None,
                }
            ],
            n.AnsibleUtil.ARGS_CONNECTIONS.validate([
                {
                    'name': '5',
                    'state': 'absent',
                }
            ]),
        )

        self.assertValidationError(n.AnsibleUtil.ARGS_CONNECTIONS,
                                   [ { } ])
        self.assertValidationError(n.AnsibleUtil.ARGS_CONNECTIONS,
                                   [ { 'name': 'b', 'xxx': 5 } ])

        self.assertEqual(
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
                        'ip_is_present': False,
                        'route_metric4': None,
                        'route_metric6': None,
                        'dns': [],
                        'dns_search': [],
                    },
                    'mac': 'aa:bb:cc',
                    'master': None,
                    'check_iface_exists': True,
                    'name': '5',
                    'parent': None,
                    'ignore_errors': None,
                    'slave_type': None,
                    'state': 'present',
                    'type': 'ethernet',
                    'vlan_id': None,
                },
            ],
            n.AnsibleUtil.ARGS_CONNECTIONS.validate([
                {
                    'name': '5',
                    'type': 'ethernet',
                    'mac': 'AA:bb:cC',
                }
            ]),
        )

        self.assertEqual(
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
                        'ip_is_present': False,
                        'dhcp4_send_hostname': None,
                    },
                    'mac': None,
                    'master': None,
                    'vlan_id': None,
                    'ignore_errors': None,
                    'interface_name': None,
                    'check_iface_exists': True,
                    'slave_type': None,
                    'wait': None,
                },
            ],
            n.AnsibleUtil.ARGS_CONNECTIONS.validate([
                { 'name': '5',
                  'state': 'up',
                  'type': 'ethernet',
                },
            ]),
        )

        self.assertEqual(
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
                        'ip_is_present': True,
                        'dhcp4_send_hostname': None,
                    },
                    'mac': None,
                    'master': None,
                    'vlan_id': None,
                    'ignore_errors': None,
                    'interface_name': None,
                    'check_iface_exists': True,
                    'slave_type': None,
                    'wait': None,
                },
            ],
            n.AnsibleUtil.ARGS_CONNECTIONS.validate([
                { 'name': '5',
                  'state': 'up',
                  'type': 'ethernet',
                  'ip': {
                  },
                },
            ]),
        )

        self.assertEqual(
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
                        'ip_is_present': True,
                        'dhcp4_send_hostname': None,
                    },
                    'mac': None,
                    'master': None,
                    'vlan_id': None,
                    'ignore_errors': None,
                    'interface_name': None,
                    'check_iface_exists': True,
                    'slave_type': None,
                    'wait': None,
                },
            ],
            n.AnsibleUtil.ARGS_CONNECTIONS.validate([
                { 'name': '5',
                  'state': 'up',
                  'type': 'ethernet',
                  'ip': {
                      'dns_search': [ 'aa', 'bb' ],
                  },
                },
            ]),
        )


        self.assertValidationError(n.AnsibleUtil.ARGS_CONNECTIONS,
                                   [ { 'name': 'b', 'type': 'ethernet', 'mac': 'aa:b' } ])

@my_test_skipIf(nmutil is None, 'no support for NM (libnm via pygobject)')
class TestNM(unittest.TestCase):

    def test_connection_ensure_setting(self):

        NM = n.Util.NM()
        GObject = n.Util.GObject()

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
