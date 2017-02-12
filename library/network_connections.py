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
  this module outside the role. Thus, consult README.md for examples for the role.
'''

import socket
import sys
import traceback

###############################################################################

class CheckMode:
    DRY_RUN  = 'dry-run'
    PRE_RUN  = 'pre-run'
    REAL_RUN = 'real-run'
    DONE     = 'done'

class LogLevel:
    ERROR = 'error'
    WARN  = 'warn'
    INFO  = 'info'
    DEBUG = 'debug'

    @staticmethod
    def fmt(level):
        return '<%-6s' % (str(level) + '>')

class MyError(Exception):
    pass

class ValidationError(MyError):
    def __init__(self, name, message):
        Exception.__init__(self, name + ': ' + message)
        self.error_message = message
        self.name = name

class Util:

    PY3 = (sys.version_info[0] == 3)

    STRING_TYPE = (str if PY3 else basestring)

    @staticmethod
    def first(iterable, default = None, pred = None):
        for v in iterable:
            if pred is not None and pred(v):
                continue
            return v
        return default

    @staticmethod
    def check_output(argv, lang = None):
        # subprocess.check_output is python 2.7.
        with open('/dev/null', 'wb') as DEVNULL:
            import subprocess, os
            ev = os.environ.copy()
            ev['LANG'] = lang if lang is not None else 'C'
            p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=DEVNULL, env=ev)
            out = p.communicate()[0]
            if p.returncode != 0:
                raise MyError('failure calling %s: exit with %s' % (argv, p.returncode))
        return out

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
    def GMainLoop_run(cls, timeout = None):
        if timeout is None:
            cls.GMainLoop().run()
            return True

        GLib = cls.GLib()
        result = []
        loop = cls.GMainLoop()
        def _timeout_cb(unused):
            result.append(1)
            loop.quit()
            return False
        timeout_id = GLib.timeout_add(int(timeout * 1000), _timeout_cb, None)
        loop.run()
        if result:
            return False
        GLib.source_remove(timeout_id)
        return True

    @classmethod
    def GMainLoop_iterate(cls, may_block = False):
        return cls.GMainLoop().get_context().iteration(may_block)

    @classmethod
    def GMainLoop_iterate_all(cls):
        c = 0
        while cls.GMainLoop_iterate():
            c += 1
        return c

    @classmethod
    def create_cancellable(cls):
        return cls.Gio().Cancellable.new()

    @classmethod
    def error_is_cancelled(cls, e):
        GLib = cls.GLib()
        if isinstance(e, GLib.GError):
            if e.domain == 'g-io-error-quark' and e.code == cls.Gio().IOErrorEnum.CANCELLED:
                return True
        return False

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
    def mac_aton(mac_str, force_len=None):
        # we also accept None and '' for convenience.
        # - None yiels None
        # - '' yields []
        if mac_str is None:
            return mac_str
        i = 0
        b = []
        for c in mac_str:
            if i == 2:
                if c != ':':
                    raise MyError('not a valid MAC address: "%s"' % (mac_str))
                i = 0
                continue
            try:
                if i == 0:
                    n = int(c, 16) * 16
                    i = 1
                else:
                    assert(i == 1)
                    n = n + int(c, 16)
                    i = 2
                    b.append(n)
            except:
                raise MyError('not a valid MAC address: "%s"' % (mac_str))
        if i == 1:
            raise MyError('not a valid MAC address: "%s"' % (mac_str))
        if force_len is not None:
            if force_len != len(b):
                raise MyError('not a valid MAC address of length %s: "%s"' % (force_len, mac_str))
        return b

    @staticmethod
    def mac_ntoa(mac):
        if mac is None:
            return None
        return ':'.join(['%02x' % c for c in mac])

    @staticmethod
    def mac_norm(mac_str, force_len = None):
        return Util.mac_ntoa(Util.mac_aton(mac_str, force_len))

    @staticmethod
    def boolean(arg):
        import ansible.module_utils.basic as basic

        if arg is None or isinstance(arg, bool):
            return arg
        if isinstance(arg, Util.STRING_TYPE):
            arg = arg.lower()
        if arg in basic.BOOLEANS_TRUE:
            return True
        elif arg in basic.BOOLEANS_FALSE:
            return False
        else:
            raise MyError('value "%s" is not a boolean' % (arg))

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
    def addr_family_to_v(family):
        if family is None:
            return ''
        if family == socket.AF_INET:
            return 'v4'
        if family == socket.AF_INET6:
            return 'v6'
        raise MyError('invalid address family "%s"' % (family))

    @staticmethod
    def parse_address(address, family = None):
        result = {}
        try:
            parts = address.split()
            addr_parts = parts[0].split('/')
            if len(addr_parts) != 2:
                raise MyError('expect two addr-parts: ADDR/PLEN')
            a, family = Util.parse_ip(addr_parts[0], family)
            result['address'] = a
            result['is_v4'] = (family == socket.AF_INET)
            result['family'] = family
            prefix = int(addr_parts[1])
            if not (prefix >=0 and prefix <= (32 if family == socket.AF_INET else 128)):
                raise MyError('invalid prefix %s' % (prefix))
            result['prefix'] = prefix
            if len(parts) > 1:
                raise MyError('too many parts')
        except Exception as e:
            raise MyError('invalid address "%s"' % (address))
        return result

###############################################################################

class SysUtil:

    @staticmethod
    def _sysctl_read(filename):
        try_count = 0
        while True:
            try_count += 1
            try:
                with open(filename, 'r') as f:
                    return f.read()
            except Exception as e:
                if try_count < 5:
                    continue
                raise

    @staticmethod
    def _link_read_ifindex(ifname):
        c = SysUtil._sysctl_read('/sys/class/net/' + ifname + '/ifindex')
        return int(c.strip())

    @staticmethod
    def _link_read_address(ifname):
        c = SysUtil._sysctl_read('/sys/class/net/' + ifname + '/address')
        return Util.mac_norm(c.strip())

    @staticmethod
    def _link_read_permaddress(ifname):
        out = Util.check_output(['ethtool', '-P', ifname])
        import re
        m = re.match('^Permanent address: ([0-9A-Fa-f:]*)\n$', out)
        if not m:
            return None
        return Util.mac_norm(m.group(1))

    @staticmethod
    def _link_infos_fetch():
        import os
        links = {}
        for ifname in os.listdir('/sys/class/net/'):
            ifindex = SysUtil._link_read_ifindex(ifname)
            links[ifname] = {
                'ifindex': ifindex,
                'ifname': ifname,
                'address': SysUtil._link_read_address(ifname),
                'perm-address': SysUtil._link_read_permaddress(ifname),
            }
        return links

    @classmethod
    def link_infos(cls, refresh=False):
        if refresh:
            l = None
        else:
            l = getattr(cls, '_link_infos', None)
        if l is None:
            try_count = 0
            b = None
            while True:
                try:
                    # there is a race in that we lookup properties by ifname
                    # and interfaces can be renamed. Try to avoid that by fetching
                    # the info twice and repeat until we get the same result.
                    if b is None:
                        b = SysUtil._link_infos_fetch()
                    l = SysUtil._link_infos_fetch()
                    if l != b:
                        b = l
                        raise Exception("cannot read stable link-infos. They keep changing")
                except:
                    if try_count < 50:
                        raise
                    continue
                break
            cls._link_infos = l
        return l

    @classmethod
    def link_info_find(cls, refresh=False, mac = None, ifname = None):
        if mac is not None:
            mac = Util.mac_norm(mac)
        for li in cls.link_infos(refresh).values():
            if mac is not None and mac not in [li.get('perm-address', None), li.get('address', None)]:
                continue
            if ifname is not None and ifname != li.get('ifname', None):
                continue
            return li
        return None

###############################################################################

class ArgUtil:
    @staticmethod
    def connection_find_by_name(name, connections, n_connections = None):
        if not name:
            raise ValueError("missing name argument")
        c = None
        for idx, connection in enumerate(connections):
            if n_connections is not None and idx >= n_connections:
                break
            if 'name' not in connection or name != connection['name']:
                continue

            if connection['state'] == 'absent':
                c = None
            elif 'type' in connection:
                assert connection['state'] in ['up', 'present']
                c = connection
        return c

class ArgValidator:
    MISSING = object()

    def __init__(self, name = None, required = False, default_value = None):
        self.name = name
        self.required = required
        self.default_value = default_value

    def get_default_value(self):
        try:
            return self.default_value()
        except:
            return self.default_value

    def validate(self, value, name = None):
        name = name or self.name or ''
        v = self._validate(value, name)
        return self._validate_post(value, name, v)

    def _validate_post(self, value, name, result):
        return result

class ArgValidatorStr(ArgValidator):
    def __init__(self, name, required = False, default_value = None, enum_values = None):
        ArgValidator.__init__(self, name, required, default_value)
        self.enum_values = enum_values
    def _validate(self, value, name):
        if not isinstance(value, Util.STRING_TYPE):
            raise ValidationError(name, 'must be a string but is "%s"' % (value))
        v = str(value)
        if self.enum_values is not None and v not in self.enum_values:
            raise ValidationError(name, 'is "%s" but must be one of "%s"' % (value, '" "'.join(sorted(self.enum_values))))
        return v

class ArgValidatorInt(ArgValidator):
    def __init__(self, name, required = False, val_min = None, val_max = None, default_value = 0):
        ArgValidator.__init__(self, name, required, default_value)
        self.val_min = val_min
        self.val_max = val_max
    def _validate(self, value, name):
        v = None
        try:
            if isinstance(value, int):
                v = value
            if isinstance(value, Util.STRING_TYPE):
                v = int(value)
        except:
            pass
        if v is None:
            raise ValidationError(name, 'must be an integer number but is "%s"' % (value))
        if self.val_min is not None and v < self.val_min:
            raise ValidationError(name, 'value is %s but cannot be less then %s' % (value, self.val_min))
        if self.val_max is not None and v > self.val_max:
            raise ValidationError(name, 'value is %s but cannot be greater then %s' % (value, self.val_max))
        return v

class ArgValidatorBool(ArgValidator):
    def __init__(self, name, required = False, default_value = False):
        ArgValidator.__init__(self, name, required, default_value)
    def _validate(self, value, name):
        try:
            if isinstance(value, bool):
                return value
            if isinstance(value, Util.STRING_TYPE) or isinstance(value, int):
                return Util.boolean(value)
        except:
            pass
        raise ValidationError(name, 'must be an boolean but is "%s"' % (value))

class ArgValidatorIP(ArgValidatorStr):
    def __init__(self, name, family = None, required = False, default_value = None, plain_address = True):
        ArgValidatorStr.__init__(self, name, required, default_value, None)
        self.family = family
        self.plain_address = plain_address
    def _validate(self, value, name):
        v = ArgValidatorStr._validate(self, value, name)
        try:
            addr, family = Util.parse_ip(v, self.family)
        except:
            raise ValidationError(name, 'value "%s" is not a valid IP%s address' % (value, Util.addr_family_to_v(self.family)))
        if self.plain_address:
            return addr
        return { "family": family, "address": addr }

class ArgValidatorMac(ArgValidatorStr):
    def __init__(self, name, force_len = None, required = False, default_value = None):
        ArgValidatorStr.__init__(self, name, required, default_value, None)
        self.force_len = force_len
    def _validate(self, value, name):
        v = ArgValidatorStr._validate(self, value, name)
        try:
            addr = Util.mac_aton(v, self.force_len)
        except MyError as e:
            raise ValidationError(name, 'value "%s" is not a valid MAC address' % (value))
        if not addr:
            raise ValidationError(name, 'value "%s" is not a valid MAC address' % (value))
        return Util.mac_ntoa(addr)

class ArgValidatorIPAddr(ArgValidatorStr):
    def __init__(self, name, family = None, required = False, default_value = None):
        ArgValidatorStr.__init__(self, name, required, default_value, None)
        self.family = family
    def _validate(self, value, name):
        v = ArgValidatorStr._validate(self, value, name)
        try:
            return Util.parse_address(v, self.family)
        except:
            raise ValidationError(name, 'value "%s" is not a valid IP%s address with prefix length' % (value, Util.addr_family_to_v(self.family)))

class ArgValidatorDict(ArgValidator):
    def __init__(self, name = None, required = False, nested = None, default_value = None, all_missing_during_validate = False):
        ArgValidator.__init__(self, name, required, default_value)
        if nested is not None:
            self.nested = dict([(v.name, v) for v in nested])
        else:
            self.nested = {}
        self.all_missing_during_validate = all_missing_during_validate
    def _validate(self, value, name):
        result = {}
        seen_keys = set()
        try:
            l = list(value.items())
        except:
            raise ValidationError(name, 'invalid content is not a dictionary')
        for (k,v) in l:
            if k in seen_keys:
                raise ValidationError(name, 'duplicate key "%s"' % (k))
            seen_keys.add(k)
            validator = self.nested.get(k, None)
            if validator is None:
                raise ValidationError(name, 'invalid key "%s"' % (k))
            try:
                vv = validator.validate(v, name + '.' + k)
            except ValidationError as e:
                raise ValidationError(e.name, e.error_message)
            result[k] = vv
        for (k,v) in self.nested.items():
            if k in seen_keys:
                continue
            if v.required:
                raise ValidationError(name, 'missing required key "%s"' % (k))
            vv = v.get_default_value()
            if not self.all_missing_during_validate and vv is not ArgValidator.MISSING:
                result[k] = vv
        return result

class ArgValidatorList(ArgValidator):
    def __init__(self, name, nested, default_value = None):
        ArgValidator.__init__(self, name, required = False, default_value = default_value)
        self.nested = nested
    def construct_name(self, name):
        return ('' if n is None else n) + name
    def _validate(self, value, name):
        result = []
        for (idx, v) in enumerate(value):
            try:
                vv = self.nested.validate(v, name + '[' + str(idx) + ']')
            except ValidationError as e:
                raise ValidationError(e.name, e.error_message)
            result.append(vv)
        return result

class ArgValidator_DictIP(ArgValidatorDict):
    def __init__(self):
        ArgValidatorDict.__init__(self,
            name = 'ip',
            required = False,
            nested = [
                ArgValidatorBool('dhcp4', default_value = None),
                ArgValidatorBool('dhcp4_send_hostname', default_value = None),
                ArgValidatorIP  ('gateway4', family = socket.AF_INET),
                ArgValidatorInt ('route_metric4', val_min = -1, val_max = 0xFFFFFFFF, default_value = None),
                ArgValidatorBool('auto6'),
                ArgValidatorIP  ('gateway6', family = socket.AF_INET6),
                ArgValidatorInt ('route_metric6', val_min = -1, val_max = 0xFFFFFFFF, default_value = None),
                ArgValidatorList('address',
                    nested = ArgValidatorIPAddr('address[?]'),
                    default_value = list,
                ),
            ],
            default_value = lambda: {
                'ip_is_present': False,
                'dhcp4': True,
                'dhcp4_send_hostname': None,
                'gateway4': None,
                'route_metric4': None,
                'auto6': True,
                'gateway6': None,
                'route_metric6': None,
                'address': [],
            },
            all_missing_during_validate = False,
        )

    def _validate_post(self, value, name, result):
        if 'ip_is_present' not in result:
            result['ip_is_present'] = True
        if result['dhcp4'] is None:
            result['dhcp4'] = result['dhcp4_send_hostname'] is not None or not any([a for a in result['address'] if a['is_v4']])
        if result['auto6'] is None:
            result['auto6'] = not any([a for a in result['address'] if not a['is_v4']])
        if result['dhcp4_send_hostname'] is None:
            result['dhcp4_send_hostname'] = False
        else:
            if not result['dhcp4']:
                raise ValidationError(name, '"dhcp4_send_hostname" is only valid if "dhcp4" is enabled')
        return result

class ArgValidator_DictConnection(ArgValidatorDict):

    VALID_STATES = ['up', 'down', 'present', 'absent', 'wait']
    VALID_TYPES = [ 'ethernet', 'bridge', 'team', 'bond', 'vlan' ]
    VALID_SLAVE_TYPES = [ 'bridge', 'bond', 'team' ]

    def __init__(self):
        ArgValidatorDict.__init__(self,
            name = 'connections[?]',
            required = False,
            nested = [
                ArgValidatorStr ('name'),
                ArgValidatorStr ('state', enum_values = ArgValidator_DictConnection.VALID_STATES),
                ArgValidatorInt ('wait', val_min = -1, val_max = 1200),
                ArgValidatorStr ('type', enum_values = ArgValidator_DictConnection.VALID_TYPES),
                ArgValidatorBool('autoconnect', default_value = True),
                ArgValidatorStr ('slave_type', enum_values = ArgValidator_DictConnection.VALID_SLAVE_TYPES),
                ArgValidatorStr ('master'),
                ArgValidatorStr ('interface_name'),
                ArgValidatorMac ('mac'),
                ArgValidatorBool('check_iface_exists', default_value = True),
                ArgValidatorStr ('parent'),
                ArgValidatorInt ('vlan_id', val_min = 0, val_max = 4095, default_value = None),
                ArgValidatorBool('ignore_errors', default_value = None),
                ArgValidator_DictIP(),
            ],
            default_value = dict,
            all_missing_during_validate = True,
        )

    def _validate_post(self, value, name, result):
        if 'state' not in result:
            if 'type' in result:
                result['state'] = 'present'
            elif list(result.keys()) == [ 'wait' ]:
                result['state'] = 'wait'
            else:
                result['state'] = 'up'

        if result['state'] == 'present' or (result['state'] == 'up' and 'type' in result):
            VALID_FIELDS = list(self.nested.keys())
            if result['state'] == 'present':
                VALID_FIELDS.remove('wait')
        elif result['state'] in ['up', 'down']:
            VALID_FIELDS = ['name', 'state', 'wait', 'ignore_errors']
        elif result['state'] == 'absent':
            VALID_FIELDS = ['name', 'state', 'ignore_errors']
        elif result['state'] == 'wait':
            VALID_FIELDS = ['state', 'wait']
        else:
            assert False

        VALID_FIELDS = set(VALID_FIELDS)
        for k in result:
            if k not in VALID_FIELDS:
               raise ValidationError(name + '.' + k, 'property is not allowed for state "%s"' % (result['state']))

        if result['state'] != 'wait':
            if 'name' not in result:
                raise ValidationError(name, 'missing "name"')
            if not result['name']:
                raise ValidationError(name + '.name', 'empty "name" is invalid')

        if result['state'] == 'wait':
            if result.get('wait', -1) == -1:
                result['wait'] = 10
            elif result['wait'] == 0:
                raise ValidationError(name + '.wait', 'the "wait" value for state "wait" must be positive')
        elif result['state'] in ['up', 'down']:
            if result.get('wait', -1) == -1:
                result['wait'] = 90
        else:
            if 'wait' in result:
                raise ValidationError(name + '.wait', '"wait" is not allowed for state "%s"' % (result['state']))

        if result['state'] == 'present' and 'type' not in result:
            raise ValidationError(name + '.state', '"present" state requires a "type" argument')

        if 'type' in result:

            if 'slave_type' in result:
                if 'master' not in result:
                    raise ValidationError(name + '.slave_type', '"slave_type" requires a "master" property')
                if result['master'] == result['name']:
                    raise ValidationError(name + '.master', '"master" cannot refer to itself')
            else:
                if 'master' in result:
                    raise ValidationError(name + '.master', '"master" requires a "slave_type" property')

            if 'ip' in result:
                if 'slave_type' in result:
                    raise ValidationError(name + '.ip', 'a "slave_type" cannot have an "ip" property')
            else:
                if 'slave_type' not in result:
                    result['ip'] = self.nested['ip'].get_default_value()

            if 'mac' in result:
                if result['type'] != 'ethernet':
                    raise ValidationError(name + '.mac', 'a "mac" address is only allowed for type "ethernet"')

            if 'interface_name' in result:
                if not Util.ifname_valid(result['interface_name']):
                    raise ValidationError(name + '.interface_name', 'invalid "interface_name" "%s"' % (result['interface_name']))
            else:
                if result['type'] in [ 'bridge', 'bond', 'team', 'vlan' ]:
                    if not Util.ifname_valid(result['name']):
                        raise ValidationError(name + '.interface_name', 'requires "interface_name" as "name" "%s" is not valid' % (result['name']))
                    result['interface_name'] = result['name']

            if result['type'] == 'vlan':
                if 'vlan_id' not in result:
                    raise ValidationError(name + '.vlan_id', 'missing "vlan_id" for "type" "vlan"')
                if 'parent' not in result:
                    raise ValidationError(name + '.parent', 'missing "parent" for "type" "vlan"')
                if result['parent'] == result['name']:
                    raise ValidationError(name + '.parent', '"parent" cannot refer to itself')
            else:
                if 'vlan_id' in result:
                    raise ValidationError(name + '.vlan_id', '"vlan_id" is only allowed for "type" "vlan"')
                if 'parent' in result:
                    raise ValidationError(name + '.parent', '"parent" is only allowed for "type" "vlan"')

        for k in VALID_FIELDS:
            if k in result:
                continue
            v = self.nested[k]
            vv = v.get_default_value()
            if vv is not ArgValidator.MISSING:
                result[k] = vv

        return result

class ArgValidator_ListConnections(ArgValidatorList):
    def __init__(self):
        ArgValidatorList.__init__(self,
            name = 'connections',
            nested = ArgValidator_DictConnection(),
            default_value = list
        )

    def _validate_post(self, value, name, result):
        for idx, connection in enumerate(result):
            if connection['state'] in ['down', 'up']:
                if connection['state'] == 'up' and 'type' in connection:
                    pass
                elif not ArgUtil.connection_find_by_name(connection['name'], result, idx):
                    raise ValidationError(name + '[' + str(idx) + '].name', 'references non-existing connection "%s"' % (connection['name']))
            if 'type' in connection:
                if connection['master']:
                    if not ArgUtil.connection_find_by_name(connection['master'], result, idx):
                        raise ValidationError(name + '[' + str(idx) + '].master', 'references non-existing "master" connection "%s"' % (connection['master']))
                if connection['parent']:
                    if not ArgUtil.connection_find_by_name(connection['parent'], result, idx):
                        raise ValidationError(name + '[' + str(idx) + '].parent', 'references non-existing "parent" connection "%s"' % (connection['parent']))
        return result

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
            raise MyError('invalid ifcfg-name %s' % (name))
        if file_type is None:
            file_type = 'ifcfg'
        if file_type not in cls.FILE_TYPES:
            raise MyError('invalid file-type %s' % (file_type))
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
    def _connection_find_master(cls, name, connections, n_connections = None):
        c = ArgUtil.connection_find_by_name(name, connections, n_connections)
        if not c:
            raise MyError('invalid master/parent "%s"' % (name))
        if not Util.ifname_valid(c['interface_name']):
            raise MyError('invalid master/parent "%s" which has not a valid interface name ("%s")' % (name, c['interface_name']))
        return c['interface_name']

    @classmethod
    def ifcfg_create(cls, connections, idx, warn_fcn):
        connection = connections[idx]
        ip = connection['ip']

        ifcfg_all = {}
        for file_type in cls.FILE_TYPES:
            ifcfg_all[file_type] = {}
        ifcfg = ifcfg_all['ifcfg']

        if ip['dhcp4_send_hostname'] is not None:
            warn_fcn('ip.dhcp4_send_hostname is not supported by initscripts provider')
        if ip['route_metric4'] is not None and ip['route_metric4'] >= 0:
            warn_fcn('ip.route_metric4 is not supported by initscripts provider')
        if ip['route_metric6'] is not None and ip['route_metric6'] >= 0:
            warn_fcn('ip.route_metric6 is not supported by initscripts provider')

        ifcfg['NM_CONTROLLED'] = 'no'

        if connection['autoconnect']:
            ifcfg['ONBOOT'] = 'yes'

        ifcfg['DEVICE'] = connection['interface_name']

        if connection['type'] == 'ethernet':
            ifcfg['TYPE'] = 'Ethernet'
            ifcfg['HWADDR'] = connection['mac']
        elif connection['type'] == 'bridge':
            ifcfg['TYPE'] = 'Bridge'
        elif connection['type'] == 'bond':
            ifcfg['TYPE'] = 'Bond'
            ifcfg['BONDING_MASTER'] = 'yes'
        elif connection['type'] == 'team':
            ifcfg['DEVICETYPE'] = 'Team'
        elif connection['type'] == 'vlan':
            ifcfg['VLAN'] = 'yes'
            ifcfg['TYPE'] = 'Vlan'
            ifcfg['PHYSDEV'] = cls._connection_find_master(connection['parent'], connections, idx)
            ifcfg['VID'] = connection['vlan_id']
        else:
            raise MyError('unsupported type %s' % (connection['type']))

        if connection['slave_type'] is not None:
            m = cls._connection_find_master(connection['master'], connections, idx)
            if connection['slave_type'] == 'bridge':
                ifcfg['BRIDGE'] = m
            elif connection['slave_type'] == 'bond':
                ifcfg['MASTER'] = m
                ifcfg['SLAVE'] = 'yes'
            elif connection['slave_type'] == 'team':
                ifcfg['TEAM_MASTER'] = m
                if 'TYPE' in ifcfg:
                    del ifcfg['TYPE']
                if connection['type'] != 'team':
                    ifcfg['DEVICETYPE'] = 'TeamPort'
            else:
                raise MyError('invalid slave_type "%s"' % (connection['slave_type']))
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
            if ip['gateway4'] is not None:
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
            if ip['gateway6'] is not None:
                ifcfg['IPV6_DEFAULTGW'] = ip['gateway6']

        for file_type in cls.FILE_TYPES:
            h = ifcfg_all[file_type]
            for key in h.keys():
                if h[key] is None:
                    del h[key]
                    continue
                if type(h[key]) == type(True):
                    h[key] = 'yes' if h[key] else 'no'

        return ifcfg_all

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

    ANSIBLE_MANAGED = '# this file was created by ansible'

    @classmethod
    def content_from_dict(cls, ifcfg_all, file_type = None):
        content = {}
        for file_type in cls._file_types(file_type):
            h = ifcfg_all[file_type]
            if not h:
                if file_type != 'ifcfg':
                    content[file_type] = None
                continue
            s = cls.ANSIBLE_MANAGED + '\n'
            for key in sorted(h.keys()):
                value = h[key]
                if not cls.KeyValid(key):
                    raise MyError('invalid ifcfg key %s' % (key))
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
        import os
        for file_type in cls._file_types(file_type):
            path = cls.ifcfg_path(name, file_type)
            h = content[file_type]
            if h is None:
                try:
                    os.unlink(path)
                except OSError as e:
                    import errno
                    if e.errno != errno.ENOENT:
                        raise
            else:
                with open(path, 'w') as text_file:
                    text_file.write(h)

###############################################################################

class NMUtil:

    def __init__(self, nmclient = None):
        if nmclient is None:
            nmclient = Util.NM().Client.new(None)
        self.nmclient = nmclient

    def active_connection_list(self, connections = None, black_list = None, mainloop_iterate = True):
        if mainloop_iterate:
            Util.GMainLoop_iterate_all()
        active_cons = self.nmclient.get_active_connections()
        if connections:
            connections = set(connections)
            active_cons = [ac for ac in active_cons if ac.get_connection() in connections]
        if black_list:
            active_cons = [ac for ac in active_cons if ac not in black_list]
        active_cons = list(active_cons)
        return active_cons;

    def connection_list(self, name = None, uuid = None, black_list = None, black_list_uuid = None, mainloop_iterate = True):
        if mainloop_iterate:
            Util.GMainLoop_iterate_all()
        cons = self.nmclient.get_connections()
        if name is not None:
            cons = [c for c in cons if c.get_id() == name]
        if uuid is not None:
            cons = [c for c in cons if c.get_uuid() == uuid]

        if black_list:
            cons = [c for c in cons if c not in black_list]
        if black_list_uuid:
            cons = [c for c in cons if c.get_uuid() not in black_list_uuid]

        cons = list(cons)
        def _cmp(a, b):
            s_a = a.get_setting_connection()
            s_b = b.get_setting_connection()
            if not s_a and not s_b:
                return 0
            if not s_a:
                return 1
            if not s_b:
                return -1
            t_a = s_a.get_timestamp()
            t_b = s_b.get_timestamp()
            if t_a == t_b:
                return 0
            if t_a <= 0:
                return 1
            if t_b <= 0:
                return -1
            return cmp(t_a, t_b)
        cons.sort(cmp = _cmp)
        return cons

    def connection_compare(self, con_a, con_b, normalize_a = False, normalize_b = False, compare_flags = None):
        NM = Util.NM()

        if normalize_a:
            con_a = NM.SimpleConnection.new_clone(con_a)
            try:
                con_a.normalize()
            except:
                pass
        if normalize_b:
            con_b = NM.SimpleConnection.new_clone(con_b)
            try:
                con_b.normalize()
            except:
                pass
        if compare_flags == None:
            compare_flags = NM.SettingCompareFlags.IGNORE_TIMESTAMP

        return not(not(con_a.compare (con_b, compare_flags)))

    @staticmethod
    def _connection_find_master_uuid(name, connections, n_connections = None):
        c = ArgUtil.connection_find_by_name(name, connections, n_connections)
        if not c:
            raise MyError('invalid master/parent "%s"' % (name))
        assert c.get('nm.uuid', None)
        return c['nm.uuid']

    def connection_create(self, connections, idx):
        NM = Util.NM()

        connection = connections[idx]

        con = NM.SimpleConnection.new()
        s_con = NM.SettingConnection.new()
        con.add_setting(s_con)

        s_con.set_property(NM.SETTING_CONNECTION_ID, connection['name'])
        s_con.set_property(NM.SETTING_CONNECTION_UUID, connection['nm.uuid'])
        s_con.set_property(NM.SETTING_CONNECTION_AUTOCONNECT, connection['autoconnect'])
        s_con.set_property(NM.SETTING_CONNECTION_INTERFACE_NAME, connection['interface_name'])

        if connection['type'] == 'ethernet':
            s_con.set_property(NM.SETTING_CONNECTION_TYPE, '802-3-ethernet')
            s_wired = NM.SettingWired.new()
            con.add_setting(s_wired)
            s_wired.set_property(NM.SETTING_WIRED_MAC_ADDRESS, connection['mac'])
        elif connection['type'] == 'bridge':
            s_con.set_property(NM.SETTING_CONNECTION_TYPE, 'bridge')
            s_bridge = NM.SettingBridge.new()
            con.add_setting(s_bridge)
            s_bridge.set_property(NM.SETTING_BRIDGE_STP, False)
        elif connection['type'] == 'bond':
            s_con.set_property(NM.SETTING_CONNECTION_TYPE, 'bond')
        elif connection['type'] == 'team':
            s_con.set_property(NM.SETTING_CONNECTION_TYPE, 'team')
        elif connection['type'] == 'vlan':
            s_vlan = NM.SettingVlan.new()
            con.add_setting(s_vlan)
            s_vlan.set_property(NM.SETTING_VLAN_ID, int(connection['vlan_id']))
            s_vlan.set_property(NM.SETTING_VLAN_PARENT, self._connection_find_master_uuid(connection['parent'], connections, idx))
        else:
            raise MyError('unsupported type %s' % (connection['type']))

        if connection['slave_type'] is not None:
            s_con.set_property(NM.SETTING_CONNECTION_SLAVE_TYPE, connection['slave_type'])
            s_con.set_property(NM.SETTING_CONNECTION_MASTER, self._connection_find_master_uuid(connection['master'], connections, idx))
        else:
            ip = connection['ip']

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
            if ip['gateway4'] is not None:
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
            if ip['gateway6'] is not None:
                s_ip6.set_property(NM.SETTING_IP_CONFIG_GATEWAY, ip['gateway6'])
            if ip['route_metric6'] is not None and ip['route_metric6'] >= 0:
                s_ip6.set_property(NM.SETTING_IP_CONFIG_ROUTE_METRIC, ip['route_metric6'])

            con.add_setting(s_ip4)
            con.add_setting(s_ip6)

        try:
            con.normalize()
        except Exception as e:
            raise MyError('created connection failed to normalize: %s' % (e))
        return con

    def connection_add(self, con, timeout = 5):

        def add_cb(client, result, cb_args):
            con = None
            try:
                con = client.add_connection_finish(result)
            except Exception as e:
                if Util.error_is_cancelled(e):
                    return
                cb_args['error'] = str(e)
            cb_args['con'] = con
            Util.GMainLoop().quit()

        cancellable = Util.create_cancellable()
        cb_args = {}
        self.nmclient.add_connection_async(con, True, cancellable, add_cb, cb_args)
        if not Util.GMainLoop_run(timeout):
            cancellable.cancel()
            raise MyError('failure to add connection: %s' % ('timeout'))
        if not cb_args.get('con', None):
            raise MyError('failure to add connection: %s' % (cb_args.get('error', 'unknown error')))
        return cb_args['con']

    def connection_update(self, con, con_new, timeout = 5):
        NM = Util.NM()

        con.replace_settings_from_connection(con_new)

        def update_cb(connection, result, cb_args):
            success = False
            try:
                success = connection.commit_changes_finish(result)
            except Exception as e:
                if Util.error_is_cancelled(e):
                    return
                cb_args['error'] = str(e)
            cb_args['success'] = success
            Util.GMainLoop().quit()

        cancellable = Util.create_cancellable()
        cb_args = {}
        con.commit_changes_async(True, cancellable, update_cb, cb_args)
        if not Util.GMainLoop_run(timeout):
            cancellable.cancel()
            raise MyError('failure to update connection: %s' % ('timeout'))
        if not cb_args.get('success', False):
            raise MyError('failure to update connection: %s' % (cb_args.get('error', 'unknown error')))
        return True

    def connection_delete(self, connection, timeout = 5):

        def delete_cb(connection, result, cb_args):
            success = False
            try:
                success = connection.delete_finish(result)
            except Exception as e:
                if Util.error_is_cancelled(e):
                    return
                cb_args['error'] = str(e)
            cb_args['success'] = success
            Util.GMainLoop().quit()

        cancellable = Util.create_cancellable()
        cb_args = {}
        connection.delete_async(cancellable, delete_cb, cb_args)
        if not Util.GMainLoop_run(timeout):
            cancellable.cancel()
            raise MyError('failure to delete connection: %s' % ('timeout'))
        if not cb_args.get('success', False):
            raise MyError('failure to delete connection: %s' % (cb_args.get('error', 'unknown error')))

    def connection_activate(self, connection, timeout = 5):

        def activate_cb(client, result, cb_args):
            active_connection = None
            try:
                active_connection = client.activate_connection_finish(result)
            except Exception as e:
                if Util.error_is_cancelled(e):
                    return
                cb_args['error'] = str(e)
            cb_args['active_connection'] = active_connection
            Util.GMainLoop().quit()

        cancellable = Util.create_cancellable()
        cb_args = {}
        self.nmclient.activate_connection_async(connection, None, None, cancellable, activate_cb, cb_args)
        if not Util.GMainLoop_run(timeout):
            cancellable.cancel()
            raise MyError('failure to activate connection: %s' % ('timeout'))
        if not cb_args.get('active_connection', None):
            raise MyError('failure to activate connection: %s' % (cb_args.get('error', 'unknown error')))
        return cb_args['active_connection']

    def active_connection_deactivate(self, ac, timeout = 5):

        def deactivate_cb(client, result, cb_args):
            success = False
            try:
                success = client.deactivate_connection_finish(result)
            except Exception as e:
                if Util.error_is_cancelled(e):
                    return
                cb_args['error'] = str(ex)
            cb_args['success'] = success
            Util.GMainLoop().quit()

        cancellable = Util.create_cancellable()
        cb_args = {}
        self.nmclient.deactivate_connection_async(ac, cancellable, deactivate_cb, cb_args)
        if not Util.GMainLoop_run(timeout):
            cancellable.cancel()
            raise MyError('failure to deactivate connection: %s' % (timeout))
        if not cb_args.get('success', False):
            raise MyError('failure to deactivate connection: %s' % (cb_args.get('error', 'unknown error')))
        return True

###############################################################################

class _AnsibleUtil:

    ARGS = {
        'ignore_errors':  { 'required': False, 'default': False, 'type': 'str' },
        'provider':       { 'required': True,  'default': None,  'type': 'str' },
        'connections':    { 'required': False, 'default': None,  'type': 'list' },
    }

    ARGS_CONNECTIONS = ArgValidator_ListConnections()

    def __init__(self):
        from ansible.module_utils.basic import AnsibleModule

        self.AnsibleModule = AnsibleModule
        self._module = None
        self._connections = None
        self._run_results = None
        self._check_mode = None

    @property
    def check_mode(self):
        if self._check_mode == None:
            raise MyError('check_mode is not initialized')
        return self._check_mode

    def check_mode_next(self):
        if self._check_mode == None:
            if self.module.check_mode:
                self._check_mode = CheckMode.DRY_RUN
            else:
                self._check_mode = CheckMode.PRE_RUN
            return self._check_mode
        if self.check_mode == CheckMode.PRE_RUN:
            self._run_results = None
            self._check_mode = CheckMode.REAL_RUN
            return CheckMode.REAL_RUN
        if self._check_mode != CheckMode.DONE:
            self._check_mode = CheckMode.DONE
            return CheckMode.DONE
        assert False

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
    def connections(self):
        c = self._connections
        if c is None:
            try:
                c = self.ARGS_CONNECTIONS.validate(self.params['connections'])
            except ValidationError as e:
                self.fail_json('configuration error: %s' % (e),
                               warn_traceback = True)
            self._connections = c
        return c

    @property
    def run_results(self):
        c = self._run_results
        if c is None:
            c = []
            for cc in self.connections:
                c.append({
                    'changed': False,
                    'log': [],
                    'rc': [],
                })
            self._run_results = c
        return c

    def run_results_changed(self, idx, changed = None):
        if changed is None:
            changed = True
        self.run_results[idx]['changed'] = bool(changed)

    def run_results_rc(self, idx, rc, msg):
        self.run_results[idx]['rc'].append((rc, msg))
        self.log(idx, LogLevel.INFO, 'command: %s (rc=%s)' % (msg, rc))

    def log_debug(self, idx, msg):
        self.log(idx, LogLevel.DEBUG, msg)

    def log_info(self, idx, msg):
        self.log(idx, LogLevel.INFO, msg)

    def log_warn(self, idx, msg):
        self.log(idx, LogLevel.WARN, msg)

    def log_error(self, idx, msg, warn_traceback = False):
        self.log(idx, LogLevel.ERROR, msg, warn_traceback = warn_traceback)

    def log(self, idx, severity, msg, warn_traceback = False):
        self.run_results[idx]['log'].append((severity, msg))
        if severity == LogLevel.ERROR:
            # ignore_errors can be specified per profile. In absense of a
            # per-profile setting, a global parameter is consulted.
            ignore_errors = self.connections[idx]['ignore_errors']
            if ignore_errors is None:
                try:
                    ignore_errors = Util.boolean(self.params['ignore_errors'])
                except:
                    ignore_errors = None
            if not ignore_errors:
                self.fail_json('error: %s' % (msg), warn_traceback = warn_traceback)

    def _complete_kwargs(self, kwargs, traceback_msg = None):
        if 'warnings' in kwargs:
            logs = list(kwargs['warnings'])
        else:
            logs = []
        if self._run_results is not None:
            for idx, rr in enumerate(self.run_results):
                c = self.connections[idx]
                prefix = 'state:%s' % (c['state'])
                if c['state'] != 'wait':
                    prefix = prefix + (', "%s"' % (c['name']))
                for r in rr['log']:
                    logs.append('%s #%s, %s: %s' % (LogLevel.fmt(r[0]), idx, prefix, r[1]))
        if traceback_msg is not None:
            logs.append(traceback_msg)
        kwargs['warnings'] = logs
        return kwargs

    def exit_json(self, **kwargs):
        changed = False
        if self._run_results is not None:
            for rr in self.run_results:
                if rr['changed']:
                    changed = True
        kwargs['changed'] = changed
        self.module.exit_json(**self._complete_kwargs(kwargs))

    def fail_json(self, msg, warn_traceback = False, **kwargs):
        traceback_msg = None
        if warn_traceback:
            traceback_msg = 'exception: %s' % (traceback.format_exc())
        kwargs['msg'] = msg
        self.module.fail_json(**self._complete_kwargs(kwargs, traceback_msg))

AnsibleUtil = _AnsibleUtil()

###############################################################################

class Cmd:

    @staticmethod
    def create():
        provider = AnsibleUtil.params['provider']
        if provider == 'nm':
            return Cmd_nm()
        elif provider == 'initscripts':
            return Cmd_initscripts()
        AnsibleUtil.fail_json('unsupported provider %s' % (provider))

    def run(self):
        self.run_prepare()
        while AnsibleUtil.check_mode_next() != CheckMode.DONE:
            for idx, connection in enumerate(AnsibleUtil.connections):
                try:
                    state = connection['state']
                    if state == 'wait':
                        AnsibleUtil.log_info(idx, "wait for %s seconds" % (connection['wait']))
                        if AnsibleUtil.check_mode == CheckMode.REAL_RUN:
                            import time
                            time.sleep(connection['wait'])
                    elif state == 'absent':
                        self.run_state_absent(idx)
                    elif state == 'present':
                        self.run_state_present(idx)
                    elif state == 'up':
                        if 'type' in connection:
                            self.run_state_present(idx)
                        self.run_state_up(idx)
                    elif state == 'down':
                        self.run_state_down(idx)
                    else:
                        assert False
                except Exception as e:
                    AnsibleUtil.log_warn(idx, "failure: %s [[%s]]" % (e, traceback.format_exc()))
                    raise

    def run_prepare(self):
        for idx, connection in enumerate(AnsibleUtil.connections):
            if 'type' in connection and connection['check_iface_exists']:
                # when the profile is tied to a certain interface via 'interface_name' or 'mac',
                # check that such an interface exists.
                #
                # This check has many flaws, as we don't check whether the existing
                # interface has the right device type. Also, there is some ambiguity
                # between the current MAC address and the permanent MAC address.
                li_mac = None
                li_ifname = None
                if connection['mac']:
                    li_mac = SysUtil.link_info_find(mac = connection['mac'])
                    if not li_mac:
                        AnsibleUtil.log_error(idx, 'profile specifies mac "%s" but not such interface exists' % (connection['mac']))
                if connection['interface_name'] and connection['type'] == 'ethernet':
                    li_ifname = SysUtil.link_info_find(ifname = connection['interface_name'])
                    if not li_ifname:
                        AnsibleUtil.log_error(idx, 'profile specifies interface_name "%s" but not such interface exists' % (connection['interface_name']))
                if li_mac and li_ifname and li_mac != li_ifname:
                    AnsibleUtil.log_error(idx, 'profile specifies interface_name "%s" and mac "%s" but not such interface exists' % (connection['interface_name'], connection['mac']))

###############################################################################

class Cmd_nm(Cmd):

    def __init__(self):
        self._nmutil = None

    @property
    def nmutil(self):
        if self._nmutil is None:
            try:
                nmclient = Util.NM().Client.new(None)
            except Exception as e:
                AnsibleUtil.fail_json('failure loading libnm library: %s' % (e))
            self._nmutil = NMUtil(nmclient)
        return self._nmutil

    def run_prepare(self):
        Cmd.run_prepare(self)
        names = {}
        for connection in AnsibleUtil.connections:
            if connection['state'] in ['up', 'down', 'present', 'absent']:
                name = connection['name']
                if name in names:
                    exists = names[name]['nm.exists']
                    uuid = names[name]['nm.uuid']
                else:
                    c = Util.first(self.nmutil.connection_list(name = name))

                    exists = (c is not None)
                    if c is not None:
                        uuid = c.get_uuid()
                    else:
                        uuid = Util.create_uuid()
                    names[name] = {
                        'nm.exists': exists,
                        'nm.uuid': uuid,
                    }
                connection['nm.exists'] = exists
                connection['nm.uuid'] = uuid

    def run_state_absent(self, idx):
        changed = False
        seen = set()
        name = AnsibleUtil.connections[idx]['name']
        while True:
            connections = self.nmutil.connection_list(name = name, black_list = seen)
            if not connections:
                break
            c = connections[-1]
            seen.add(c)
            AnsibleUtil.run_results_changed(idx)
            AnsibleUtil.log_info(idx, 'delete connection %s, %s' % (c.get_id(), c.get_uuid()))
            if AnsibleUtil.check_mode == CheckMode.REAL_RUN:
                try:
                    self.nmutil.connection_delete(c)
                except MyError as e:
                    AnsibleUtil.log_error(idx, 'delete connection failed: %s' % (e))
        if not seen:
            AnsibleUtil.log_info(idx, 'no connection "%s"' % (name))

    def run_state_present(self, idx):
        connection = AnsibleUtil.connections[idx]
        con_cur = Util.first(self.nmutil.connection_list(name = connection['name'], uuid = connection['nm.uuid']))
        con_new = self.nmutil.connection_create(AnsibleUtil.connections, idx)
        changed = False
        if con_cur is None:
            AnsibleUtil.log_info(idx, 'add connection %s, %s' % (connection['name'], connection['nm.uuid']))
            changed = True
            try:
                if AnsibleUtil.check_mode == CheckMode.REAL_RUN:
                    con_cur = self.nmutil.connection_add(con_new)
            except MyError as e:
                AnsibleUtil.log_error(idx, 'adding connection failed: %s' % (e))
        elif not self.nmutil.connection_compare(con_cur, con_new, normalize_a = True):
            changed = True
            AnsibleUtil.log_info(idx, 'update connection %s, %s' % (con_cur.get_id(), con_cur.get_uuid()))
            if AnsibleUtil.check_mode == CheckMode.REAL_RUN:
                try:
                    self.nmutil.connection_update(con_cur, con_new)
                except MyError as e:
                    AnsibleUtil.log_error(idx, 'updating connection failed: %s' % (e))
        else:
            AnsibleUtil.log_info(idx, 'connection %s, %s already up to date' % (con_cur.get_id(), con_cur.get_uuid()))

        seen = set()
        if con_cur is not None:
            seen.add(con_cur)

        while True:
            connections = self.nmutil.connection_list(name = connection['name'], black_list = seen, black_list_uuid = [connection['nm.uuid']])
            if not connections:
                break
            c = connections[-1]
            AnsibleUtil.log_info(idx, 'delete duplicate connection %s, %s' % (c.get_id(), c.get_uuid()))
            changed = True
            if AnsibleUtil.check_mode == CheckMode.REAL_RUN:
                try:
                   self.nmutil.connection_delete(c)
                except MyError as e:
                    AnsibleUtil.log_error(idx, 'delete duplicate connection failed: %s' % (e))
            seen.add(c)

        AnsibleUtil.run_results_changed(idx, changed)

    def run_state_up(self, idx):
        connection = AnsibleUtil.connections[idx]

        if connection['wait'] != 0:
            AnsibleUtil.log_warn(idx, 'wait for activation is not yet implemented')

        con = Util.first(self.nmutil.connection_list(name = connection['name'], uuid = connection['nm.uuid']))
        if not con:
            if AnsibleUtil.check_mode == CheckMode.REAL_RUN:
                AnsibleUtil.log_error(idx, 'up connection %s, %s failed: no connection' % (connection['name'], connection['nm.uuid']))
            else:
                AnsibleUtil.log_info(idx, 'up connection %s, %s' % (connection['name'], connection['nm.uuid']))
            return
        AnsibleUtil.log_info(idx, 'up connection %s, %s' % (con.get_id(), con.get_uuid()))
        if AnsibleUtil.check_mode == CheckMode.REAL_RUN:
            try:
                self.nmutil.connection_activate (con)
            except MyError as e:
                AnsibleUtil.log_error(idx, 'up connection failed: %s' % (e))

        AnsibleUtil.run_results_changed(idx)

    def run_state_down(self, idx):
        connection = AnsibleUtil.connections[idx]

        if connection['wait'] != 0:
            AnsibleUtil.log_warn(idx, 'wait for activation is not yet implemented')

        cons = self.nmutil.connection_list(name = connection['name'])
        changed = False
        if cons:
            seen = set()
            while True:
                ac = Util.first(self.nmutil.active_connection_list(connections = cons, black_list = seen))
                if ac is None:
                    break
                changed = True
                seen.add(ac)
                AnsibleUtil.log_info(idx, 'down connection %s: %s' % (connection['name'], ac.get_path()))
                if AnsibleUtil.check_mode == CheckMode.REAL_RUN:
                    try:
                        self.nmutil.active_connection_deactivate(ac)
                    except MyError as e:
                        AnsibleUtil.log_error(idx, 'down connection failed: %s' % (e))
                cons = self.nmutil.connection_list(name = connection['name'])

        if not changed:
            AnsibleUtil.log_info(idx, 'down connection %s failed: no connection' % (connection['name']))
        AnsibleUtil.run_results_changed(idx, changed)


###############################################################################

class Cmd_initscripts(Cmd):

    def check_name(self, idx, name = None):
        if name is None:
            name = AnsibleUtil.connections[idx]['name']
        try:
            f = IfcfgUtil.ifcfg_path(name)
        except MyError as e:
            AnsibleUtil.log_error(idx, 'invalid name %s for connection' % (name))
            return None
        return f

    def run_state_absent(self, idx):
        if not self.check_name(idx):
            return
        import os
        name = AnsibleUtil.connections[idx]['name']
        changed = False
        for path in IfcfgUtil.ifcfg_paths(name):
            if not os.path.isfile(path):
                continue
            changed = True
            AnsibleUtil.log_info(idx, 'delete ifcfg-rh file "%s"' % (path))
            if AnsibleUtil.check_mode == CheckMode.REAL_RUN:
                try:
                    os.unlink(path)
                except Exception as e:
                    AnsibleUtil.log_error(idx, 'delete ifcfg-rh file "%s" failed: %s' % (path, e))

        if not changed:
            AnsibleUtil.log_info(idx, 'delete ifcfg-rh files for "%s" (no files present)' % (name))
        AnsibleUtil.run_results_changed(idx, changed)

    def run_state_present(self, idx):
        if not self.check_name(idx):
            return

        connection = AnsibleUtil.connections[idx]
        name = connection['name']

        ifcfg_all = IfcfgUtil.ifcfg_create(AnsibleUtil.connections, idx,
                                           lambda msg: AnsibleUtil.log_warn(idx, msg))

        old_content = IfcfgUtil.content_from_file(name)
        new_content = IfcfgUtil.content_from_dict(ifcfg_all)

        if old_content == new_content:
            AnsibleUtil.log_info(idx, 'ifcfg-rh profile "%s" already up to date' % (name))
            return

        op = 'add' if (old_content['ifcfg'] is None) else 'update'

        AnsibleUtil.log_info(idx, '%s ifcfg-rh profile "%s"' % (op, name))

        if AnsibleUtil.check_mode == CheckMode.REAL_RUN:
            try:
                IfcfgUtil.content_to_file(name, new_content)
            except MyError as e:
                AnsibleUtil.log_error(idx, '%s ifcfg-rh profile "%s" failed: %s' % (op, name, e))

        AnsibleUtil.run_results_changed(idx)

    def _run_state_updown(self, idx, cmd):
        if not self.check_name(idx):
            return

        connection = AnsibleUtil.connections[idx]
        name = connection['name']

        if connection['wait'] != 0:
            # initscripts don't support wait, they always block until the ifup/ifdown
            # command completes. Silently ignore the argument.
            pass

        import os

        AnsibleUtil.log_info(idx, 'call `%s %s`' % (cmd, name))

        path = IfcfgUtil.ifcfg_path(name)
        if not os.path.isfile(path):
            if AnsibleUtil.check_mode == CheckMode.REAL_RUN:
                AnsibleUtil.log_error(idx, 'ifcfg file "%s" does not exist' % (path))
            else:
                AnsibleUtil.log_info(idx, 'ifcfg file "%s" does not exist in check mode' % (path))
        else:
            if AnsibleUtil.check_mode == CheckMode.REAL_RUN:
                rc, out, err = AnsibleUtil.module.run_command([cmd, name], encoding=None)
                AnsibleUtil.log_info(idx, 'call `%s %s`: rc=%d, out="%s", err="%s"' % (cmd, name, rc, out, err))
                if rc != 0:
                    AnsibleUtil.log_error(idx, 'call `%s %s` failed with exit status %d' % (cmd, name, rc))

        AnsibleUtil.run_results_changed(idx)


    def run_state_up(self, idx):
        self._run_state_updown(idx, 'ifup')

    def run_state_down(self, idx):
        self._run_state_updown(idx, 'ifdown')

###############################################################################

if __name__ == '__main__':
    try:
        Cmd.create().run()
    except Exception as e:
        AnsibleUtil.fail_json('fatal error: %s' % (e),
                              warn_traceback = True)
    AnsibleUtil.exit_json()
