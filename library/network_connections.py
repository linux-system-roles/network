#!/usr/bin/python
# -*- coding: utf-8 -*-

DOCUMENTATION='''
---
module: network_connections
author: "Thomas Haller (thaller@redhat.com)"
short_description: module for network role to manage connection profiles
requirements: for 'nm' provider requires pygobject, dbus and NetworkManager.
version_added: "2.0"
description: Manage networking profiles (connections) for NetworkManager and initscripts
  networking providers.
options: Documentation needs to be written. Note that the network_connections module
  tightly integrates with the network role and currently it is not expected to use
  this module outside the role. Thus, consule README.md for examples for the role.
'''

import socket
import sys
import traceback

PY3 = sys.version_info[0] == 3

if PY3:
    string_types = str,
else:
    string_types = basestring,

###############################################################################

class Util:

    @classmethod
    def create_uuid(cls):
        cls.NM()
        return str(cls._uuid.uuid4())

    @classmethod
    def NM(cls):
        n = getattr(cls, '_NM', None)
        if n is None:
            import gi
            gi.require_version('NM', '1.0')
            from gi.repository import NM, GLib, Gio
            cls._NM = NM
            cls._GLib = GLib
            cls._Gio = Gio
            n = NM
            import uuid
            cls._uuid = uuid
        return n

    @classmethod
    def GLib(cls):
        cls.NM()
        return cls._GLib

    @classmethod
    def Gio(cls):
        cls.NM()
        return cls._Gio

    @classmethod
    def Timestamp(cls):
        return cls.GLib().get_monotonic_time()

    @classmethod
    def GMainLoop(cls):
        gmainloop = getattr(cls, '_GMainLoop', None)
        if gmainloop is None:
            gmainloop = cls.GLib().MainLoop()
            cls._GMainLoop = gmainloop
        return gmainloop

    @classmethod
    def GMainLoop_iterate(cls, may_block = False):
        cls.GMainLoop().get_context().iteration(may_block)

    @classmethod
    def create_nm_client(cls):
        return cls.NM().Client.new(None)

    @staticmethod
    def kwargs_extend(d, **kwargs):
        d = dict(d)
        d.update(kwargs)
        return d

    @staticmethod
    def ifname_valid(ifname):
        # see dev_valid_name() in kernel's net/core/dev.c
        if not ifname:
            return False
        if ifname in [ '.', '..' ]:
            return False
        if len(ifname) >= 16:
            return False
        if any([c == '/' or c == ':' or c.isspace() for c in ifname]):
            return False
        # FIXME: encoding issues regarding python unicode string
        return True

    @staticmethod
    def parse_ip(addr, family=None):
        if addr is None:
            return (None, None)
        if family is not None:
            a = socket.inet_pton(family, addr)
        else:
            a = None
            family = None
            try:
                a = socket.inet_pton(socket.AF_INET, addr)
                family = socket.AF_INET
            except:
                a = socket.inet_pton(socket.AF_INET6, addr)
                family = socket.AF_INET6
        return (socket.inet_ntop(family, a), family)

    @staticmethod
    def parse_address(address):
        result = {}
        try:
            parts = address.split()
            addr_parts = parts[0].split('/')
            if len(addr_parts) != 2:
                raise Exception('expect two addr-parts: ADDR/PLEN')
            a, family = Util.parse_ip(addr_parts[0])
            result['address'] = a
            result['is_v4'] = (family == socket.AF_INET)
            result['family'] = family
            prefix = int(addr_parts[1])
            if not (prefix >=0 and prefix <= (32 if family == socket.AF_INET else 128)):
                raise Exception('invalid prefix %s' % (prefix))
            result['prefix'] = prefix
            if len(parts) > 1:
                raise Exception('too many parts')
        except Exception as e:
            raise Exception('invalid address "%s"' % (address))
        return result

###############################################################################

class _AnsibleUtil:

    ARGS = {
        'provider':       { 'required': True,  'default': None, 'type': 'str' },
        'name':           { 'required': True,  'default': None, 'type': 'str' },
        'state':          { 'required': False, 'default': None, 'type': 'str' },
        'wait':           { 'required': False, 'default': 0,    'type': 'int' },
        'type':           { 'required': False, 'default': None, 'type': 'str' },
        'autoconnect':    { 'required': False, 'default': True, 'type': 'bool' },
        'slave_type':     { 'required': False, 'default': None, 'type': 'str' },
        'master':         { 'required': False, 'default': None, 'type': 'str' },
        'interface_name': { 'required': False, 'default': None, 'type': 'str' },
        'mac':            { 'required': False, 'default': None, 'type': 'str' },
        'vlan_id':        { 'required': False, 'default': -1,   'type': 'int' },
        'parent':         { 'required': False, 'default': None, 'type': 'str' },
        'ip':             { 'required': False, 'default': None, 'type': 'dict' },
    }

    def __init__(self):
        from ansible.module_utils.basic import AnsibleModule

        self.AnsibleModule = AnsibleModule
        self._module = None
        self._rc = None
        self._warnings = list()

    @property
    def module(self):
        module = self._module
        if module is None:
            module = self.AnsibleModule(
                argument_spec = self.ARGS,
                supports_check_mode = True,
            )
            self._module = module
        return module

    @property
    def params(self):
        return self.module.params

    @property
    def params_wait(self):
        wait = AnsibleUtil.params['wait']
        if not (wait >= 0):
            wait = 90
        return wait

    @property
    def check_mode(self):
        return self.module.check_mode

    def warn(self, msg):
        self._warnings.append(msg)

    def check_type_boolean(self, key, value, allow_none = True):
        if allow_none and value is None:
            return None
        try:
            if isinstance(value, bool):
                return value
            if isinstance(value, string_types) or isinstance(value, int):
                return self.module.boolean(value)
        except:
            pass
        raise TypeError('%s must be a bool but is %s' % (key, value))

    def check_type_int(self, key, value, allow_none = True, val_min = None, val_max = None):
        if allow_none and value is None:
            return None
        v = None
        try:
            if isinstance(value, int):
                v = value
            if isinstance(value, string_types):
                v = int(value)
        except:
            pass
        if v is None:
            raise TypeError('%s must be an int but is %s' % (key, value))
        if val_min is not None and v < val_min:
            raise TypeError('%s is %s but cannot be less then %s' % (key, v, val_min))
        if val_max is not None and v > val_max:
            raise TypeError('%s is %s but cannot be greater then %s' % (key, v, val_max))
        return v

    @property
    def ansible_managed(self):
        return  '# this file was created by ansible'

    @property
    def rc(self):
        return self._rc

    @rc.setter
    def rc(self, value):
        if self._rc is not None:
            raise Exception('cannot set rc multiple times')
        value = int(value)
        self._rc = value

    def kwargs_whitelist(self, kwargs, allow_defaults, *allowed_args):
        s = set(allowed_args)
        if allow_defaults:
            s.update(['provider', 'name', 'state'])
        for key in kwargs:
            if key in self.ARGS:
                if kwargs[key] == self.ARGS[key]['default']:
                    continue
                if key in s:
                    continue
            raise Exception('command does not support variable %s' % (key))

    def kwargs_whitelist_check(self, allow_defaults, *allowed_args):
        try:
            self.kwargs_whitelist(self.params, allow_defaults, *allowed_args)
        except Exception as e:
            self.fail_json(str(e))

    def kwargs_check_connection_args_ip(self, ip):
        if ip is None:
            return {
                'ip_is_present': False,
                'dhcp4': True,
                'dhcp4_send_hostname': None,
                'gateway4': None,
                'route_metric4': None,
                'auto6': True,
                'gateway6': None,
                'route_metric6': None,
                'address': [],
            }
        valid_keys = [
            'dhcp4',
            'dhcp4_send_hostname',
            'gateway4',
            'route_metric4',
            'auto6',
            'gateway6',
            'route_metric6',
            'address',
        ]
        for key in ip.keys():
            if key not in valid_keys:
                raise Exception('invalid argument ip.%s' % (key))
        r = {
            'ip_is_present': True,
            'dhcp4':               self.check_type_boolean('ip.dhcp4', ip.get('dhcp4', None)),
            'dhcp4_send_hostname': self.check_type_boolean('ip.dhcp4_send_hostname', ip.get('dhcp4_send_hostname', None)),
            'gateway4':            Util.parse_ip(ip.get('gateway4', None), socket.AF_INET)[0],
            'route_metric4':       self.check_type_int('route_metric4', ip.get('route_metric4', None), val_min = -1, val_max = 0xFFFFFFFF),
            'auto6':               self.check_type_boolean('ip.auto6', ip.get('auto6', None)),
            'gateway6':            Util.parse_ip(ip.get('gateway6', None), socket.AF_INET6)[0],
            'route_metric6':       self.check_type_int('route_metric6', ip.get('route_metric6', None), val_min = -1, val_max = 0xFFFFFFFF),
            'address':             list([Util.parse_address(a) for a in ip.get('address',[])]),
        }
        if r['dhcp4'] is None:
            r['dhcp4'] = r['dhcp4_send_hostname'] is not None or not any([a for a in r['address'] if a['is_v4']])
        if r['auto6'] is None:
            r['auto6'] = not any([a for a in r['address'] if not a['is_v4']])
        if not r['dhcp4'] and r['dhcp4_send_hostname'] is not None:
            raise Exception('ip.dhcp4_send_hostname can only be set with ip.dhcp4')
        return r

    def kwargs_check_connection_args(self, kwargs):
        args = { }
        handled_keys = set()

        args['name'] = kwargs['name']
        handled_keys.add('name')

        if not kwargs['type']:
            raise Exception('missing "type" property')
        else:
            if kwargs['type'] not in [ 'ethernet', 'bridge', 'team', 'bond', 'vlan' ]:
                raise Exception('invalid type "%s"' % (kwargs['type']))
            args['type'] = kwargs['type']
        handled_keys.add('type')

        if kwargs['slave_type'] is not None:
            if kwargs['slave_type'] not in [ 'bridge', 'bond', 'team' ]:
                raise Exception('invalid slave_type "%s"' % (kwargs['slave_type']))
            if kwargs['master'] is None:
                raise Exception('A slave_type "%s" requires a master' % (kwargs['slave_type']))
            args['slave_type'] = kwargs['slave_type']
            args['master'] = kwargs['master']
        elif kwargs['master'] is not None:
            raise Exception('A slave with a "master" property needs a "slave_type" specified')
        handled_keys.add('slave_type')
        handled_keys.add('master')

        if 'slave_type' in args:
            if kwargs['ip'] is not None:
                raise Exception('slave type "%s" does not support an ip configuration' % (args['slave_type']))
        args['ip'] = self.kwargs_check_connection_args_ip(kwargs['ip'])
        handled_keys.add('ip')

        if kwargs['mac']:
            if kwargs['type'] not in [ 'ethernet' ]:
                raise Exception('mac is not supported for type "%s"' % (kwargs['type']))
        args['mac'] = kwargs['mac']
        handled_keys.add('mac')

        args['interface_name'] = kwargs['interface_name']
        handled_keys.add('interface_name')
        if not args['interface_name']:
            if kwargs['type'] in [ 'bridge', 'bond', 'team', 'vlan' ]:
                args['interface_name'] = kwargs['name']
        if args['interface_name'] is not None and not Util.ifname_valid(args['interface_name']):
            raise Exception('invalid interface-name "%s"' % (args['interface_name']))

        if args['type'] == 'vlan':
            if kwargs['vlan_id'] == -1:
                raise Exception('missing vlan_id')
            try:
                i = int(kwargs['vlan_id'])
                if i < 0 or i >= 4095:
                    i = None
            except:
                i = None
            if i is None:
                raise Exception('invalid vlan_id "%s"' % (kwargs['vlan_id']))
            args['vlan_id'] = str(i)
        elif kwargs['vlan_id'] != -1:
            raise Exception('vlan_id not allowed for type "%s"' % (args['type']))
        handled_keys.add('vlan_id')

        if args['type'] == 'vlan':
            if not kwargs['parent']:
                raise Exception('vlan needs a parent connection')
            args['parent'] = kwargs['parent']
        else:
            if kwargs['parent']:
                raise Exception('type "%s" does not support  needs a parent connection')
        handled_keys.add('parent')

        args['autoconnect'] = kwargs['autoconnect']
        handled_keys.add('autoconnect')

        for k in kwargs:
            if k in [ 'provider', 'state', 'wait' ]:
                continue
            if k not in handled_keys:
                raise Exception('unsupported key "%s"' % (k))

        return args

    def _complete_kwargs(self, kwargs):
        if 'warnings' in kwargs:
            kwargs['warnings'] = self._warnings + kwargs['warnings']
        else:
            kwargs['warnings'] = self._warnings
        if 'rc' in kwargs:
            self.rc = kwargs['rc']
            rc = self.rc
        else:
            rc = self.rc
        if rc is not None:
            kwargs['rc'] = rc
        return kwargs

    def exit_json(self, changed, **kwargs):
        kwargs['changed'] = changed
        self.module.exit_json(**self._complete_kwargs(kwargs))

    def fail_json(self, msg, **kwargs):
        kwargs['msg'] = msg
        self.module.fail_json(**self._complete_kwargs(kwargs))

AnsibleUtil = _AnsibleUtil()

###############################################################################

class IfcfgUtil:

    FILE_TYPES = [
        'ifcfg',
        'keys',
        'route',
        'route6',
        'rule',
        'rule6',
    ]

    @classmethod
    def _file_types(cls, file_type):
        if file_type is None:
            return cls.FILE_TYPES
        else:
            return [ file_type ]

    @classmethod
    def ifcfg_paths(cls, name, file_types = None):
        paths = []
        if file_types is None:
            file_types = cls.FILE_TYPES
        for f in file_types:
            paths.append(cls.ifcfg_path(name, f))
        return paths

    @classmethod
    def ifcfg_path(cls, name, file_type = None):
        n = str(name)
        if not name or \
           n == '.' or \
           n == '..' or \
           n.find('/') != -1:
            raise Exception('invalid ifcfg-name %s' % (name))
        if file_type is None:
            file_type = 'ifcfg'
        if file_type not in cls.FILE_TYPES:
            raise Exception('invalid file-type %s' % (file_type))
        return '/etc/sysconfig/network-scripts/' + file_type + '-' + n

    @classmethod
    def KeyValid(cls, name):
        r = getattr(cls, '_CHECKSTR_VALID_KEY', None)
        if r is None:
            import re
            r = re.compile('^[a-zA-Z][a-zA-Z0-9_]*$')
            cls._CHECKSTR_VALID_KEY = r
        return bool(r.match(name))

    @classmethod
    def ValueEscape(cls, value):

        r = getattr(cls, '_re_ValueEscape', None)
        if r is None:
            import re
            r = re.compile('^[a-zA-Z_0-9-.]*$')
            cls._re_ValueEscape = r

        if r.match(value):
            return value

        if any([ord(c) < ord(' ') for c in value]):
            # needs ansic escaping due to ANSI control caracters (newline)
            s = "$'"
            for c in value:
                if ord(c) < ord(c):
                    s += '\\' + str(ord(c))
                elif c == '\\' or c == "'":
                    s += '\\' + c
                else:
                    # non-unicode chars are fine too to take literally
                    # as utf8
                    s += c
            s += "'"
        else:
            # double quoting
            s = '"'
            for c in value:
                if c == '"' or c == '\\' or c == '$' or c == '`':
                    s += '\\' + c
                else:
                    # non-unicode chars are fine too to take literally
                    # as utf8
                    s += c
            s += '"'
        return s

    @classmethod
    def ifcfg_find_master_from_file(cls, args, field):
        content = cls.content_from_file(args[field], 'ifcfg')
        if content['ifcfg'] is None:
            raise Exception('cannot lookup %s connection from file "ifcfg-%s"' % (field, args[field]))
        cdict = cls.content_to_dict(content, 'ifcfg')
        ifcfg = cdict['ifcfg']
        if 'DEVICE' not in ifcfg:
            raise Exception('cannot lookup DEVICE in %s connection from file "ifcfg-%s"' % (field, args[field]))
        if not Util.ifname_valid(ifcfg['DEVICE']):
            raise Exception('invalid DEVICE for %s connection in file "ifcfg-%s"' % (field, args[field]))
        return ifcfg['DEVICE']

    @classmethod
    def ifcfg_find_master(cls, args, field, check_mode = False):
        try:
            return cls.ifcfg_find_master_from_file(args, field)
        except:
            if not check_mode:
                raise
            return None

    @classmethod
    def ifcfg_create(cls, check_mode, **kwargs):
        ifcfg_all = {}
        for file_type in cls.FILE_TYPES:
            ifcfg_all[file_type] = {}
        ifcfg = ifcfg_all['ifcfg']

        dirty = False

        args = AnsibleUtil.kwargs_check_connection_args(kwargs)
        ip = args['ip']

        if ip['dhcp4_send_hostname'] is not None:
            AnsibleUtil.warn('ip.dhcp4_send_hostname is not supported by initscripts provider')
        if ip['route_metric4'] is not None and ip['route_metric4'] >= 0:
            AnsibleUtil.warn('ip.route_metric4 is not supported by initscripts provider')
        if ip['route_metric6'] is not None and ip['route_metric6'] >= 0:
            AnsibleUtil.warn('ip.route_metric6 is not supported by initscripts provider')

        ifcfg['NM_CONTROLLED'] = 'no'

        if args['autoconnect']:
            ifcfg['ONBOOT'] = 'yes'

        ifcfg['DEVICE'] = args['interface_name']

        if args['type'] == 'ethernet':
            ifcfg['TYPE'] = 'Ethernet'
            ifcfg['HWADDR'] = args['mac']
        elif args['type'] == 'bridge':
            ifcfg['TYPE'] = 'Bridge'
        elif args['type'] == 'bond':
            ifcfg['TYPE'] = 'Bond'
            ifcfg['BONDING_MASTER'] = 'yes'
        elif args['type'] == 'team':
            ifcfg['DEVICETYPE'] = 'Team'
        elif args['type'] == 'vlan':
            ifcfg['VLAN'] = 'yes'
            ifcfg['TYPE'] = 'Vlan'
            m = cls.ifcfg_find_master(args, 'parent', check_mode)
            if m is None:
                dirty = True
            else:
                ifcfg['PHYSDEV'] = m
            ifcfg['VID'] = args['vlan_id']
        else:
            raise Exception('unsupported type %s' % (args['type']))

        if 'slave_type' in args:
            m = cls.ifcfg_find_master(args, 'master', check_mode)
            if m is None:
                dirty = True
            if args['slave_type'] == 'bridge':
                ifcfg['BRIDGE'] = m
            elif args['slave_type'] == 'bond':
                ifcfg['MASTER'] = m
                ifcfg['SLAVE'] = 'yes'
            elif args['slave_type'] == 'team':
                ifcfg['TEAM_MASTER'] = m
                if 'TYPE' in ifcfg:
                    del ifcfg['TYPE']
                if args['type'] != 'team':
                    ifcfg['DEVICETYPE'] = 'TeamPort'
            else:
                raise Exception('invalid slave_type "%s"' % (args['slave_type']))
        else:
            addrs4 = list([a for a in ip['address'] if     a['is_v4']])
            addrs6 = list([a for a in ip['address'] if not a['is_v4']])

            if ip['dhcp4']:
                ifcfg['BOOTPROTO'] = 'dhcp'
            elif addrs4:
                ifcfg['BOOTPROTO'] = 'static'
            else:
                ifcfg['BOOTPROTO'] = 'none'
            for i in range(0, len(addrs4)):
                a = addrs4[i]
                ifcfg['IPADDR' + ('' if i == 0 else str(i))] = a['address']
                ifcfg['PREFIX' + ('' if i == 0 else str(i))] = str(a['prefix'])
            if ip['gateway4']:
                ifcfg['GATEWAY'] = ip['gateway4']

            if ip['auto6']:
                ifcfg['IPV6INIT'] = 'yes'
                ifcfg['IPV6_AUTOCONF'] = 'yes'
            elif addrs6:
                ifcfg['IPV6INIT'] = 'yes'
                ifcfg['IPV6_AUTOCONF'] = 'no'
            else:
                ifcfg['IPV6INIT'] = 'no'
            if addrs6:
                ifcfg['IPVADDR'] = addrs6[0]['address'] + '/' + str(addrs6[0]['prefix'])
                if len(addrs6) > 1:
                    ifcfg['IPVADDR_SECONDARIES'] = ' '.join([a['address'] + '/' + str(a['prefix']) for a in addrs6[1:]])
            if ip['gateway6']:
                ifcfg['IPV6_DEFAULTGW'] = ip['gateway6']

        for file_type in cls.FILE_TYPES:
            h = ifcfg_all[file_type]
            for key in h.keys():
                if h[key] is None:
                    del h[key]
                    continue
                if type(h[key]) == type(True):
                    h[key] = 'yes' if h[key] else 'no'

        return (ifcfg_all, dirty)

    @classmethod
    def ifcfg_parse_line(cls, line):
        r1 = getattr(cls, '_re_parse_line1', None)
        if r1 is None:
            import re
            import shlex
            r1 = re.compile('^[ \t]*([a-zA-Z_][a-zA-Z_0-9]*)=(.*)$')
            cls._re_parse_line1 = r1
            cls._shlex = shlex
        m = r1.match(line)
        if not m:
            return None
        key = m.group(1)
        val = m.group(2)
        val = val.rstrip()

        # shlex isn't up to the task of parsing shell. Whatever,
        # we can only parse shell to a certain degree and this is
        # good enough for now.
        try:
            c = list(cls._shlex.split(val, comments=True, posix=True))
        except:
            return None
        if len(c) != 1:
            return None
        return (key, c[0])

    @classmethod
    def ifcfg_parse(cls, content):
        if content is None:
            return None
        ifcfg = {}
        for line in content.splitlines():
            val = cls.ifcfg_parse_line(line)
            if val:
                ifcfg[val[0]] = val[1]
        return ifcfg

    @classmethod
    def content_from_dict(cls, ifcfg_all, file_type = None):
        content = {}
        for file_type in cls._file_types(file_type):
            h = ifcfg_all[file_type]
            if not h:
                if file_type != 'ifcfg':
                    content[file_type] = None
                continue
            s = AnsibleUtil.ansible_managed + '\n'
            for key in sorted(h.keys()):
                value = h[key]
                if not cls.KeyValid(key):
                    raise Exception('invalid ifcfg key %s' % (key))
                if value is not None:
                    s += key + '=' + cls.ValueEscape(value) + '\n'
            content[file_type] = s
        return content

    @classmethod
    def content_to_dict(cls, content, file_type = None):
        ifcfg_all = {}
        for file_type in cls._file_types(file_type):
            ifcfg_all[file_type] = cls.ifcfg_parse(content[file_type])
        return ifcfg_all

    @classmethod
    def content_from_file(cls, name, file_type = None):
        content = {}
        for file_type in cls._file_types(file_type):
            path = cls.ifcfg_path(name, file_type)
            try:
                with open(path, 'r') as content_file:
                    i_content = content_file.read()
            except Exception as e:
                i_content = None
            content[file_type] = i_content
        return content

    @classmethod
    def content_to_file(cls, name, content, file_type = None):
        import os, errno
        for file_type in cls._file_types(file_type):
            path = cls.ifcfg_path(name, file_type)
            h = content[file_type]
            if h is None:
                try:
                    os.unlink(path)
                except OSError as e:
                    if e.errno != errno.ENOENT:
                        raise
            else:
                with open(path, 'w') as text_file:
                    text_file.write(h)

###############################################################################

class NMCmd:

    def __init__(self, nmclient):
        self.nmclient = nmclient

    def active_connection_list(self, connections = None, black_list = None):
        active_cons = self.nmclient.get_active_connections()
        if connections:
            connections = set(connections)
            active_cons = [ac for ac in active_cons if ac.get_connection() in connections]
        if black_list:
            active_cons = [ac for ac in active_cons if ac not in black_list]
        active_cons = list(active_cons)
        return active_cons;

    def connection_list(self, name = None, uuid = None, black_list = None):
        cons = self.nmclient.get_connections()
        if name is not None:
            cons = [c for c in cons if c.get_id() == name]
        if uuid is not None:
            cons = [c for c in cons if c.get_uuid() == uuid]

        if black_list:
            cons = [c for c in cons if c not in black_list]

        cons = list(cons)
        def _get_timestamp(connection):
            s_con = connection.get_setting_connection()
            if not s_con:
                return 0L
            return s_con.get_timestamp()
        cons.sort(key = _get_timestamp)
        return cons

    def connection_find_master_connection(self, args, field, expected_type = None):
        # we lookup the master/parent by the ID. That is different from NetworkManager, for
        # which connection.master either names the ifname of the parent interface
        # or the UUID of the parent connection.
        cons = self.connection_list(name = args[field])
        if not cons:
            raise Exception('a %s connection "%s" was not found' % (field, args[field]))
        if len(cons) != 1:
            raise Exception('a unique %s connection "%s" was not found, instead there are [ %s ]' % (field, args[field], ' '.join([c.get_uuid() for c in cons])))
        con = cons[0]
        if expected_type is not None and con.get_connection_type() != expected_type:
            raise Exception('the %s connection "%s" is expected to be of type %s but is %s (%s)' % (field, args[field], expected_type, con.get_connection_type(), con.get_uuid()))
        return con

    def connection_find_master(self, args, field, check_mode = False, expected_type = None):
        try:
            con = self.connection_find_master_connection(args, field, expected_type)
        except:
            if not check_mode:
                raise
            return None
        return con.get_uuid()

    def _ip_settings_create(self, ip, connection = None):
        NM = Util.NM()

        s_ip4 = NM.SettingIP4Config.new()
        s_ip6 = NM.SettingIP6Config.new()

        s_ip4.set_property(NM.SETTING_IP_CONFIG_METHOD, 'auto')
        s_ip6.set_property(NM.SETTING_IP_CONFIG_METHOD, 'auto')

        addrs4 = list([a for a in ip['address'] if     a['is_v4']])
        addrs6 = list([a for a in ip['address'] if not a['is_v4']])

        if ip['dhcp4']:
            s_ip4.set_property(NM.SETTING_IP_CONFIG_METHOD, 'auto')
            s_ip4.set_property(NM.SETTING_IP_CONFIG_DHCP_SEND_HOSTNAME, ip['dhcp4_send_hostname'] != False)
        elif addrs4:
           s_ip4.set_property(NM.SETTING_IP_CONFIG_METHOD, 'manual')
        else:
            s_ip4.set_property(NM.SETTING_IP_CONFIG_METHOD, 'disabled')
        for a in addrs4:
            s_ip4.add_address(NM.IPAddress.new(a['family'], a['address'], a['prefix']))
        if ip['gateway4']:
            s_ip4.set_property(NM.SETTING_IP_CONFIG_GATEWAY, ip['gateway4'])
        if ip['route_metric4'] is not None and ip['route_metric4'] >= 0:
            s_ip4.set_property(NM.SETTING_IP_CONFIG_ROUTE_METRIC, ip['route_metric4'])

        if ip['auto6']:
            s_ip6.set_property(NM.SETTING_IP_CONFIG_METHOD, 'auto')
        elif addrs6:
            s_ip6.set_property(NM.SETTING_IP_CONFIG_METHOD, 'manual')
        else:
            s_ip6.set_property(NM.SETTING_IP_CONFIG_METHOD, 'ignore')
        for a in addrs6:
            s_ip6.add_address(NM.IPAddress.new(a['family'], a['address'], a['prefix']))
        if ip['gateway6']:
            s_ip6.set_property(NM.SETTING_IP_CONFIG_GATEWAY, ip['gateway6'])
        if ip['route_metric6'] is not None and ip['route_metric6'] >= 0:
            s_ip6.set_property(NM.SETTING_IP_CONFIG_ROUTE_METRIC, ip['route_metric6'])

        if connection is not None:
            connection.add_setting(s_ip4)
            connection.add_setting(s_ip6)
        return (s_ip4, s_ip6)

    def connection_create(self, check_mode, uuid = None, **kwargs):
        NM = Util.NM()

        if uuid is None:
            uuid = Util.create_uuid()

        dirty = False

        args = AnsibleUtil.kwargs_check_connection_args(kwargs)

        connection = NM.SimpleConnection.new()
        s_con = NM.SettingConnection.new()
        connection.add_setting(s_con)

        s_con.set_property(NM.SETTING_CONNECTION_ID, args['name'])
        s_con.set_property(NM.SETTING_CONNECTION_UUID, uuid)
        s_con.set_property(NM.SETTING_CONNECTION_AUTOCONNECT, args['autoconnect'])
        s_con.set_property(NM.SETTING_CONNECTION_INTERFACE_NAME, args['interface_name'])

        if args['type'] == 'ethernet':
            s_wired = NM.SettingWired.new()
            connection.add_setting(s_wired)
            s_con.set_property(NM.SETTING_CONNECTION_TYPE, '802-3-ethernet')
            s_wired.set_property(NM.SETTING_WIRED_MAC_ADDRESS, args['mac'])
        elif args['type'] == 'bridge':
            s_con.set_property(NM.SETTING_CONNECTION_TYPE, 'bridge')
        elif args['type'] == 'bond':
            s_con.set_property(NM.SETTING_CONNECTION_TYPE, 'bond')
        elif args['type'] == 'team':
            s_con.set_property(NM.SETTING_CONNECTION_TYPE, 'team')
        elif args['type'] == 'vlan':
            s_vlan = NM.SettingVlan.new()
            connection.add_setting(s_vlan)
            s_vlan.set_property(NM.SETTING_VLAN_ID, int(args['vlan_id']))
            m = self.connection_find_master(args, 'parent', check_mode)
            if m is None:
                dirty = True
            else:
                s_vlan.set_property(NM.SETTING_VLAN_PARENT, m)
        else:
            raise Exception('unsupported type %s' % (args['type']))

        if 'slave_type' in args:
            s_con.set_property(NM.SETTING_CONNECTION_SLAVE_TYPE, args['slave_type'])
            m = self.connection_find_master(args, 'master', check_mode, args['slave_type'])
            if m is None:
                dirty = True
            else:
                s_con.set_property(NM.SETTING_CONNECTION_MASTER, m)
        else:
            self._ip_settings_create(args['ip'], connection)

        try:
            connection.normalize()
        except Exception as e:
            if not check_mode:
                raise Exception('failure to create normalized connection: %s' % (e))
        return (connection, dirty)


    def _connection_add_cb(self, client, result, cb_args):
        con = None
        try:
            con = client.add_connection_finish(result)
        except Exception as e:
            cb_args['error'] = str(e)
        cb_args['con'] = con
        Util.GMainLoop().quit()

    def connection_add(self, check_mode = False, **kwargs):
        connection, dirty = self.connection_create(check_mode, **kwargs)
        if check_mode:
            return True

        cb_args = {}
        self.nmclient.add_connection_async(connection, True,
                                           None, self._connection_add_cb, cb_args)
        Util.GMainLoop().run()
        if not cb_args.get('con', None):
            raise Exception('failure to add connection: %s' % (cb_args.get('error', 'unknown error')))
        return True


    def _connection_update_cb(self, connection, result, cb_args):
        success = False
        try:
            success = connection.commit_changes_finish(result)
        except Exception as e:
            cb_args['error'] = str(e)
        cb_args['success'] = success
        Util.GMainLoop().quit()

    def connection_update(self, connection, check_mode = False, **kwargs):
        NM = Util.NM()

        connection_new, dirty = self.connection_create(check_mode, **Util.kwargs_extend (kwargs, uuid = connection.get_uuid()))

        connection_cur = NM.SimpleConnection.new_clone(connection)
        try:
            connection_cur.normalize()
        except:
            pass
        changed = not connection_cur.compare (connection_new, NM.SettingCompareFlags.IGNORE_TIMESTAMP)

        if check_mode:
            return changed or dirty

        if not changed:
            return False

        connection.replace_settings_from_connection(connection_new)

        cb_args = {}
        connection.commit_changes_async(True, None, self._connection_update_cb, cb_args)
        Util.GMainLoop().run()
        if not cb_args.get('success', False):
            raise Exception('failure to update connection: %s' % (cb_args.get('error', 'unknown error')))
        return True


    def _connection_delete_cb(self, connection, result, cb_args):
        success = False
        try:
            success = connection.delete_finish(result)
        except Exception as e:
            cb_args['error'] = str(e)
        cb_args['success'] = success
        Util.GMainLoop().quit()

    def connection_delete(self, connection):
        cb_args = {}
        connection.delete_async(None, self._connection_delete_cb, cb_args)
        Util.GMainLoop().run()
        if not cb_args.get('success', False):
            raise Exception('failure to delete connection: %s' % (cb_args.get('error', 'unknown error')))


    def _connection_activate_cb(self, client, result, cb_args):
        active_connection = False
        try:
            active_connection = client.activate_connection_finish(result)
        except Exception as e:
            cb_args['error'] = str(e)
        cb_args['active_connection'] = active_connection
        Util.GMainLoop().quit()

    def connection_activate(self, connection):
        cb_args = {}
        self.nmclient.activate_connection_async(connection, None, None, None, self._connection_activate_cb, cb_args)
        Util.GMainLoop().run()
        if not cb_args.get('active_connection', None):
            raise Exception('failure to activate connection: %s' % (cb_args.get('error', 'unknown error')))
        return cb_args['active_connection']


    def _active_connection_deactivate_cb(self, client, result, cb_args):
        success = False
        try:
            success = client.deactivate_connection_finish(result)
        except Exception as e:
            cb_args['error'] = str(ex)
        cb_args['success'] = success
        Util.GMainLoop().quit()

    def active_connection_deactivate(self, ac):
        cb_args = {}
        self.nmclient.deactivate_connection_async(ac, None, self._active_connection_deactivate_cb, cb_args)
        Util.GMainLoop().run()
        if not cb_args.get('success', False):
            raise Exception('failure to deactivate connection: %s' % (cb_args.get('error', 'unknown error')))
        return True

###############################################################################

class Cmd:

    @staticmethod
    def create():
        provider = AnsibleUtil.params['provider']
        if provider == 'nm':
            return Cmd_nm()
        if provider == 'initscripts':
            return Cmd_initscripts()
        AnsibleUtil.fail_json('unsupported provider %s' % (provider))

    def run(self):
        state = AnsibleUtil.params['state']
        if state is None:
            if AnsibleUtil.params['type'] is None:
                state = 'up'
            else:
                state = 'present'
        if state == 'absent':
            AnsibleUtil.kwargs_whitelist_check(True)
            self.run_state_absent()
        elif state == 'present':
            self.run_state_present()
        elif state == 'up':
            AnsibleUtil.kwargs_whitelist_check(True, 'wait')
            self.run_state_up()
        elif state == 'down':
            AnsibleUtil.kwargs_whitelist_check(True)
            self.run_state_down()
        else:
            AnsibleUtil.fail_json('invalid state "%s"' % (state))

    def run_state_absent(self):
        AnsibleUtil.fail_json('state absent not implemented')

    def run_state_present(self):
        AnsibleUtil.fail_json('state present not implemented')

    def run_state_up(self):
        AnsibleUtil.fail_json('state up not implemented')

    def run_state_down(self):
        AnsibleUtil.fail_json('state down not implemented')

###############################################################################

class Cmd_nm(Cmd):

    def __init__(self):
        self._nmcmd = None

    @property
    def nmcmd(self):
        if self._nmcmd is None:
            try:
                nmclient = Util.create_nm_client()
            except Exception as e:
                AnsibleUtil.fail_json('failure loading libnm library: %s' % (e))
            self._nmcmd = NMCmd(nmclient)
        return self._nmcmd

    def run_state_absent(self):
        changed = False
        seen = set()
        while True:
            connections = self.nmcmd.connection_list(name = AnsibleUtil.params['name'], black_list = seen)
            if not connections:
                AnsibleUtil.exit_json(changed)
            if AnsibleUtil.check_mode:
                AnsibleUtil.exit_json(True)
            c = connections[-1]
            try:
                self.nmcmd.connection_delete(c)
            except Exception as e:
                AnsibleUtil.fail_json('delete connection failed: %s' % (e))
            changed = True
            seen.add(c)
            Util.GMainLoop_iterate()

    def run_state_present(self):
        connections = self.nmcmd.connection_list(name = AnsibleUtil.params['name'])
        if not connections:
            try:
                self.nmcmd.connection_add(check_mode = AnsibleUtil.check_mode,
                                          **AnsibleUtil.params)
            except Exception as e:
                AnsibleUtil.warn('exception: %s' % (traceback.format_exc()))
                AnsibleUtil.fail_json('failure adding connection: %s' % (e))
            AnsibleUtil.exit_json(True)

        changed = False
        connection = connections[0]
        try:
            changed = self.nmcmd.connection_update(connection,
                                                   check_mode = AnsibleUtil.check_mode,
                                                   **AnsibleUtil.params)
        except Exception as e:
            AnsibleUtil.warn('exception: %s' % (traceback.format_exc()))
            AnsibleUtil.fail_json('failure updating connection %s: %s' % (connection.get_id(), e))

        seen = set([connection])
        while True:
            Util.GMainLoop_iterate()
            connections = self.nmcmd.connection_list(name = AnsibleUtil.params['name'], black_list = seen)
            if not connections:
                AnsibleUtil.exit_json(changed)
            if AnsibleUtil.check_mode:
                AnsibleUtil.exit_json(True)
            c = connections[-1]
            try:
                self.nmcmd.connection_delete(c)
            except Exception as e:
                AnsibleUtil.fail_json('delete duplicate connection failed: %s' % (e))
            changed = True
            seen.add(c)

    def run_state_up(self):
        if AnsibleUtil.params_wait != 0:
            AnsibleUtil.warn('wait for activation is not yet implemented')
        connections = self.nmcmd.connection_list(name = AnsibleUtil.params['name'])
        if not connections:
            AnsibleUtil.fail_json('failure to up connection %s: does not exist' % (AnsibleUtil.params['name']))
        if AnsibleUtil.check_mode:
            AnsibleUtil.exit_json(True)
        active_connection = None
        try:
            active_connection = self.nmcmd.connection_activate (connections[0])
        except Exception as e:
            AnsibleUtil.fail_json('up connection failed: %s' % (e))
        AnsibleUtil.exit_json(True)

    def run_state_down(self):
        if AnsibleUtil.params_wait != 0:
            AnsibleUtil.warn('wait for activation is not yet implemented')
        connections = self.nmcmd.connection_list(name = AnsibleUtil.params['name'])
        if not connections:
            AnsibleUtil.fail_json('failure to down connection %s: does not exist' % (AnsibleUtil.params['name']))
        changed = False
        seen = set()
        while True:
            acons = self.nmcmd.active_connection_list(connections, black_list = seen)
            if not acons:
                break
            if AnsibleUtil.check_mode:
                AnsibleUtil.exit_json(True)
            ac = acons[0]
            seen.add(ac)
            del acons
            try:
                self.nmcmd.active_connection_deactivate(ac)
            except Exception as e:
                AnsibleUtil.fail_json('failure deactivating connection: %s' % (e))
            changed = True
            Util.GMainLoop_iterate()
        AnsibleUtil.exit_json(changed)

###############################################################################

class Cmd_initscripts(Cmd):

    @property
    def name(self):
        return AnsibleUtil.params['name']

    def check_name(self, name = None):
        if name is None:
            name = self.name
        try:
            f = self.ifcfg_path(name)
        except Exception as e:
            AnsibleUtil.fail_json('invalid name %s for connection' % (name))
        return f

    def ifcfg_paths(self, name = None, file_types = None):
        if name is None:
            name = self.name
        return IfcfgUtil.ifcfg_paths(name, file_types)

    def ifcfg_path(self, name = None, file_type = None):
        if name is None:
            name = self.name
        return IfcfgUtil.ifcfg_path(name, file_type)

    def run_state_absent(self):
        import os, errno
        self.check_name()
        paths = self.ifcfg_paths()
        changed = False
        for path in paths:
            if AnsibleUtil.check_mode:
                if os.path.isfile(path):
                    AnsibleUtil.exit_json(True)
            else:
                try:
                    try:
                        os.unlink(path)
                        changed = True
                    except OSError as e:
                        if e.errno != errno.ENOENT:
                            raise
                except Exception as e:
                    AnsibleUtil.fail_json('failure deleting ifcfg file %s: %s' % (path, e))
        AnsibleUtil.exit_json(changed)

    def run_state_present(self):
        self.check_name()

        try:
            ifcfg_all, dirty = IfcfgUtil.ifcfg_create(AnsibleUtil.check_mode, **AnsibleUtil.params)
        except Exception as e:
            AnsibleUtil.warn('exception: %s' % (traceback.format_exc()))
            AnsibleUtil.fail_json('failure constructing ifcfg file: %s' % (e))

        old_content = IfcfgUtil.content_from_file(self.name)
        new_content = IfcfgUtil.content_from_dict(ifcfg_all)

        if not dirty and old_content == new_content:
            AnsibleUtil.exit_json(False)
        if AnsibleUtil.check_mode:
            AnsibleUtil.exit_json(True)

        try:
            IfcfgUtil.content_to_file(self.name, new_content)
        except Exception as e:
            AnsibleUtil.warn('exception: %s' % (traceback.format_exc()))
            AnsibleUtil.fail_json('writing ifcfg file failed: %s' % (e))

        AnsibleUtil.exit_json(True)

    def _run_state_updown(self, cmd):
        import os
        import subprocess
        self.check_name()

        if AnsibleUtil.params_wait != 0:
            # initscripts don't support wait, they always block until the ifup/ifdown
            # command completes. Silently ignore the argument.
            pass

        path = self.ifcfg_path()
        if not os.path.isfile(path):
            AnsibleUtil.exit_json(False)
        if AnsibleUtil.check_mode:
            AnsibleUtil.exit_json(True)

        rc, out, err = AnsibleUtil.module.run_command([cmd, self.name], encoding=None)
        AnsibleUtil.exit_json(True, rc = rc, stdout = out, stderr = err)

    def run_state_up(self):
        self._run_state_updown('ifup')

    def run_state_down(self):
        self._run_state_updown('ifdown')

###############################################################################

if __name__ == '__main__':
    AnsibleUtil.module
    Cmd.create().run()
