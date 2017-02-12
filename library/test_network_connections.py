#!/usr/bin/env python

import sys
import os
import unittest

sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))

import network_connections as n

class TestValidator(unittest.TestCase):

    def test_validate_str(self):

        v = n.ArgValidatorStr('state')
        self.assertEqual('a', v.validate('a'))
        with self.assertRaises(n.ValidationError):
            v.validate(1)
        with self.assertRaises(n.ValidationError):
            v.validate(None)

        v = n.ArgValidatorStr('state', required = True)
        with self.assertRaises(n.ValidationError):
            v.validate(None)

    def test_validate_int(self):

        v = n.ArgValidatorInt('state', default_value = None)
        self.assertEqual(1, v.validate(1))
        self.assertEqual(1, v.validate("1"))
        with self.assertRaises(n.ValidationError):
            v.validate(None)
        with self.assertRaises(n.ValidationError):
            v.validate("1a")

        v = n.ArgValidatorInt('state', required = True)
        with self.assertRaises(n.ValidationError):
            v.validate(None)

    def test_validate_bool(self):

        v = n.ArgValidatorBool('state')
        self.assertEqual(True, v.validate(True))
        self.assertEqual(True, v.validate("True"))
        self.assertEqual(True, v.validate(1))
        self.assertEqual(False, v.validate(False))
        self.assertEqual(False, v.validate("False"))
        self.assertEqual(False, v.validate(0))
        with self.assertRaises(n.ValidationError):
            v.validate(2)

        with self.assertRaises(n.ValidationError):
            v.validate(None)
        v = n.ArgValidatorBool('state', required = True)
        with self.assertRaises(n.ValidationError):
            v.validate(None)

    def test_validate_dict(self):

        v = n.ArgValidatorDict(
            'dict',
            nested = [
                n.ArgValidatorInt('i', required = True),
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
        with self.assertRaises(n.ValidationError):
            v.validate({ 'k': 1 })

    def test_validate_list(self):

        v = n.ArgValidatorList(
            'list',
            nested = n.ArgValidatorInt('i')
        )
        self.assertEqual(
            [ 1, 5 ],
            v.validate([ '1', 5 ])
        )
        with self.assertRaises(n.ValidationError):
            v.validate([1, 's'])

    def test_1(self):

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
                    'wait': 90,
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
                    'wait': 90,
                },
            ],
            n.AnsibleUtil.ARGS_CONNECTIONS.validate([
                { 'name': '5',
                  'state': 'up',
                  'type': 'ethernet',
                },
            ]),
        )

        with self.assertRaises(n.ValidationError):
            n.AnsibleUtil.ARGS_CONNECTIONS.validate([ { 'name': 'a', 'autoconnect': True }])

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

        with self.assertRaises(n.ValidationError):
            n.AnsibleUtil.ARGS_CONNECTIONS.validate([ { } ])
        with self.assertRaises(n.ValidationError):
            n.AnsibleUtil.ARGS_CONNECTIONS.validate([ { 'name': 'b', 'xxx': 5 } ])

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

        with self.assertRaises(n.ValidationError):
            n.AnsibleUtil.ARGS_CONNECTIONS.validate([ { 'name': 'b', 'type': 'ethernet', 'mac': 'aa:b' } ])


if __name__ == '__main__':
    unittest.main()
