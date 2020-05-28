#!/usr/bin/python
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: BSD-3-Clause

import errno
import functools
import os
import re
import shlex
import socket
import time
import traceback

# pylint: disable=import-error, no-name-in-module
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network_lsr import ethtool
from ansible.module_utils.network_lsr import MyError

from ansible.module_utils.network_lsr.argument_validator import (
    ArgUtil,
    ArgValidator_ListConnections,
    ValidationError,
)

from ansible.module_utils.network_lsr.utils import Util
from ansible.module_utils.network_lsr import nm_provider

# pylint: enable=import-error, no-name-in-module


DOCUMENTATION = """
---
module: network_connections
author: "Thomas Haller (thaller@redhat.com)"
short_description: module for network role to manage connection profiles
requirements: for 'nm' provider requires pygobject, dbus and NetworkManager.
version_added: "2.0"
description: Manage networking profiles (connections) for NetworkManager and
  initscripts networking providers.
options: Documentation needs to be written. Note that the network_connections
  module tightly integrates with the network role and currently it is not
  expected to use this module outside the role. Thus, consult README.md for
  examples for the role.
"""


###############################################################################

DEFAULT_ACTIVATION_TIMEOUT = 90


class CheckMode:
    PREPARE = "prepare"
    DRY_RUN = "dry-run"
    PRE_RUN = "pre-run"
    REAL_RUN = "real-run"
    DONE = "done"


class LogLevel:
    ERROR = "error"
    WARN = "warn"
    INFO = "info"
    DEBUG = "debug"

    @staticmethod
    def fmt(level):
        return "<%-6s" % (str(level) + ">")


# cmp() is not available in python 3 anymore
if "cmp" not in dir(__builtins__):

    def cmp(x, y):
        """
        Replacement for built-in function cmp that was removed in Python 3

        Compare the two objects x and y and return an integer according to
        the outcome. The return value is negative if x < y, zero if x == y
        and strictly positive if x > y.
        """

        return (x > y) - (x < y)


class SysUtil:
    @staticmethod
    def _sysctl_read(filename):
        try_count = 0
        while True:
            try_count += 1
            try:
                with open(filename, "r") as f:
                    return f.read()
            except Exception:
                if try_count < 5:
                    continue
                raise

    @staticmethod
    def _link_read_ifindex(ifname):
        c = SysUtil._sysctl_read("/sys/class/net/" + ifname + "/ifindex")
        return int(c.strip())

    @staticmethod
    def _link_read_address(ifname):
        c = SysUtil._sysctl_read("/sys/class/net/" + ifname + "/address")
        return Util.mac_norm(c.strip())

    @staticmethod
    def _link_read_permaddress(ifname):
        return ethtool.get_perm_addr(ifname)

    @staticmethod
    def _link_infos_fetch():
        links = {}
        for ifname in os.listdir("/sys/class/net/"):
            if not os.path.islink("/sys/class/net/" + ifname):
                # /sys/class/net may contain certain entries that are not
                # interface names, like 'bonding_master'. Skip over files
                # that are not links.
                continue
            links[ifname] = {
                "ifindex": SysUtil._link_read_ifindex(ifname),
                "ifname": ifname,
                "address": SysUtil._link_read_address(ifname),
                "perm-address": SysUtil._link_read_permaddress(ifname),
            }
        return links

    @classmethod
    def link_infos(cls, refresh=False):
        if refresh:
            linkinfos = None
        else:
            linkinfos = getattr(cls, "_link_infos", None)
        if linkinfos is None:
            try_count = 0
            b = None
            while True:
                try_count += 1
                try:
                    # there is a race in that we lookup properties by ifname
                    # and interfaces can be renamed. Try to avoid that by
                    # fetching the info twice and repeat until we get the same
                    # result.
                    if b is None:
                        b = SysUtil._link_infos_fetch()
                    linkinfos = SysUtil._link_infos_fetch()
                    if linkinfos != b:
                        b = linkinfos
                        raise Exception(
                            "cannot read stable link-infos. They keep changing"
                        )
                except Exception:
                    if try_count < 50:
                        raise
                    continue
                break
            cls._link_infos = linkinfos
        return linkinfos

    @classmethod
    def link_info_find(cls, refresh=False, mac=None, ifname=None):
        if mac is not None:
            mac = Util.mac_norm(mac)
        for li in cls.link_infos(refresh).values():
            if mac is not None and mac not in [
                li.get("perm-address", None),
                li.get("address", None),
            ]:
                continue
            if ifname is not None and ifname != li.get("ifname", None):
                continue
            return li
        return None


###############################################################################


###############################################################################


class IfcfgUtil:

    FILE_TYPES = ["ifcfg", "keys", "route", "route6", "rule", "rule6"]

    @classmethod
    def _file_types(cls, file_type):
        if file_type is None:
            return cls.FILE_TYPES
        else:
            return [file_type]

    @classmethod
    def ifcfg_paths(cls, name, file_types=None):
        paths = []
        if file_types is None:
            file_types = cls.FILE_TYPES
        for f in file_types:
            paths.append(cls.ifcfg_path(name, f))
        return paths

    @classmethod
    def ifcfg_path(cls, name, file_type=None):
        n = str(name)
        if not name or n == "." or n == ".." or n.find("/") != -1:
            raise MyError("invalid ifcfg-name %s" % (name))
        if file_type is None:
            file_type = "ifcfg"
        if file_type not in cls.FILE_TYPES:
            raise MyError("invalid file-type %s" % (file_type))
        return "/etc/sysconfig/network-scripts/" + file_type + "-" + n

    @classmethod
    def KeyValid(cls, name):
        r = getattr(cls, "_CHECKSTR_VALID_KEY", None)
        if r is None:
            r = re.compile("^[a-zA-Z][a-zA-Z0-9_]*$")
            cls._CHECKSTR_VALID_KEY = r
        return bool(r.match(name))

    @classmethod
    def ValueEscape(cls, value):

        r = getattr(cls, "_re_ValueEscape", None)
        if r is None:
            r = re.compile("^[a-zA-Z_0-9-.]*$")
            cls._re_ValueEscape = r

        if r.match(value):
            return value

        if any([ord(c) < ord(" ") for c in value]):
            # needs ansic escaping due to ANSI control caracters (newline)
            s = "$'"
            for c in value:
                if ord(c) < ord(c):
                    s += "\\" + str(ord(c))
                elif c == "\\" or c == "'":
                    s += "\\" + c
                else:
                    # non-unicode chars are fine too to take literally
                    # as utf8
                    s += c
            s += "'"
        else:
            # double quoting
            s = '"'
            for c in value:
                if c == '"' or c == "\\" or c == "$" or c == "`":
                    s += "\\" + c
                else:
                    # non-unicode chars are fine too to take literally
                    # as utf8
                    s += c
            s += '"'
        return s

    @classmethod
    def _ifcfg_route_merge(cls, route, append_only, current):
        if not append_only or current is None:
            if not route:
                return None
            return "\n".join(route) + "\n"

        if route:
            # the 'route' file is processed line by line by initscripts'
            # ifup-route. Hence, the order of the route matters.
            # _ifcfg_route_merge() is not sophisticated enough to understand
            # pre-existing lines. It will only append lines that don't exist
            # yet, which hopefully is correct. It's better to always rewrite
            # the entire file with route_append_only=False.
            changed = False
            c_lines = list(current.split("\n"))
            for r in route:
                if r not in c_lines:
                    changed = True
                    c_lines.append(r)
            if changed:
                return "\n".join(c_lines) + "\n"

        return current

    @classmethod
    def ifcfg_create(
        cls, connections, idx, warn_fcn=lambda msg: None, content_current=None
    ):
        connection = connections[idx]
        ip = connection["ip"]

        ifcfg = {}
        keys_file = None
        route4_file = None
        route6_file = None
        rule4_file = None
        rule6_file = None

        if ip["dhcp4_send_hostname"] is not None:
            warn_fcn("ip.dhcp4_send_hostname is not supported by initscripts provider")
        if ip["route_metric4"] is not None and ip["route_metric4"] >= 0:
            warn_fcn("ip.route_metric4 is not supported by initscripts provider")
        if ip["route_metric6"] is not None and ip["route_metric6"] >= 0:
            warn_fcn("ip.route_metric6 is not supported by initscripts provider")

        ifcfg["NM_CONTROLLED"] = "no"

        if connection["autoconnect"]:
            ifcfg["ONBOOT"] = "yes"
        else:
            ifcfg["ONBOOT"] = "no"

        ifcfg["DEVICE"] = connection["interface_name"]

        if connection["type"] == "ethernet":
            ifcfg["TYPE"] = "Ethernet"
            ifcfg["HWADDR"] = connection["mac"]
        elif connection["type"] == "infiniband":
            ifcfg["TYPE"] = "InfiniBand"
            ifcfg["HWADDR"] = connection["mac"]
            ifcfg["CONNECTED_MODE"] = (
                "yes"
                if (connection["infiniband"]["transport_mode"] == "connected")
                else "no"
            )
            if connection["infiniband"]["p_key"] != -1:
                ifcfg["PKEY"] = "yes"
                ifcfg["PKEY_ID"] = str(connection["infiniband"]["p_key"])
                if connection["parent"]:
                    ifcfg["PHYSDEV"] = ArgUtil.connection_find_master(
                        connection["parent"], connections, idx
                    )
        elif connection["type"] == "bridge":
            ifcfg["TYPE"] = "Bridge"
        elif connection["type"] == "bond":
            ifcfg["TYPE"] = "Bond"
            ifcfg["BONDING_MASTER"] = "yes"
            opts = ["mode=%s" % (connection["bond"]["mode"])]
            if connection["bond"]["miimon"] is not None:
                opts.append(" miimon=%s" % (connection["bond"]["miimon"]))
            ifcfg["BONDING_OPTS"] = " ".join(opts)
        elif connection["type"] == "team":
            ifcfg["DEVICETYPE"] = "Team"
        elif connection["type"] == "vlan":
            ifcfg["VLAN"] = "yes"
            ifcfg["TYPE"] = "Vlan"
            ifcfg["PHYSDEV"] = ArgUtil.connection_find_master(
                connection["parent"], connections, idx
            )
            ifcfg["VID"] = str(connection["vlan"]["id"])
        else:
            raise MyError("unsupported type %s" % (connection["type"]))

        if connection["mtu"]:
            ifcfg["MTU"] = str(connection["mtu"])

        ethtool_options = ""
        if "ethernet" in connection:
            if connection["ethernet"]["autoneg"] is not None:
                if connection["ethernet"]["autoneg"]:
                    ethtool_options = "autoneg on"
                else:
                    ethtool_options = "autoneg off speed %s duplex %s" % (
                        connection["ethernet"]["speed"],
                        connection["ethernet"]["duplex"],
                    )

        ethtool_features = connection["ethtool"]["features"]
        configured_features = []
        for feature, setting in ethtool_features.items():
            value = ""
            if setting:
                value = "on"
            elif setting is not None:
                value = "off"

            if value:
                configured_features.append("%s %s" % (feature, value))

        if configured_features:
            if ethtool_options:
                ethtool_options += " ; "
            ethtool_options += "-K %s %s" % (
                connection["interface_name"],
                " ".join(configured_features),
            )

        if ethtool_options:
            ifcfg["ETHTOOL_OPTS"] = ethtool_options

        if connection["master"] is not None:
            m = ArgUtil.connection_find_master(connection["master"], connections, idx)
            if connection["slave_type"] == "bridge":
                ifcfg["BRIDGE"] = m
            elif connection["slave_type"] == "bond":
                ifcfg["MASTER"] = m
                ifcfg["SLAVE"] = "yes"
            elif connection["slave_type"] == "team":
                ifcfg["TEAM_MASTER"] = m
                if "TYPE" in ifcfg:
                    del ifcfg["TYPE"]
                if connection["type"] != "team":
                    ifcfg["DEVICETYPE"] = "TeamPort"
            else:
                raise MyError("invalid slave_type '%s'" % (connection["slave_type"]))

            if ip["route_append_only"] and content_current:
                route4_file = content_current["route"]
                route6_file = content_current["route6"]
        else:
            if connection["zone"]:
                ifcfg["ZONE"] = connection["zone"]

            addrs4 = list([a for a in ip["address"] if a["family"] == socket.AF_INET])
            addrs6 = list([a for a in ip["address"] if a["family"] == socket.AF_INET6])

            if ip["dhcp4"]:
                ifcfg["BOOTPROTO"] = "dhcp"
            elif addrs4:
                ifcfg["BOOTPROTO"] = "static"
            else:
                ifcfg["BOOTPROTO"] = "none"
            for i in range(0, len(addrs4)):
                addr = addrs4[i]
                ifcfg["IPADDR" + ("" if i == 0 else str(i))] = addr["address"]
                ifcfg["PREFIX" + ("" if i == 0 else str(i))] = str(addr["prefix"])
            if ip["gateway4"] is not None:
                ifcfg["GATEWAY"] = ip["gateway4"]

            for idx, dns in enumerate(ip["dns"]):
                ifcfg["DNS" + str(idx + 1)] = dns["address"]
            if ip["dns_search"]:
                ifcfg["DOMAIN"] = " ".join(ip["dns_search"])

            if ip["auto6"]:
                ifcfg["IPV6INIT"] = "yes"
                ifcfg["IPV6_AUTOCONF"] = "yes"
            elif addrs6:
                ifcfg["IPV6INIT"] = "yes"
                ifcfg["IPV6_AUTOCONF"] = "no"
            else:
                ifcfg["IPV6INIT"] = "no"
            if addrs6:
                ifcfg["IPVADDR"] = addrs6[0]["address"] + "/" + str(addrs6[0]["prefix"])
                if len(addrs6) > 1:
                    ifcfg["IPVADDR_SECONDARIES"] = " ".join(
                        [a["address"] + "/" + str(a["prefix"]) for a in addrs6[1:]]
                    )
            if ip["gateway6"] is not None:
                ifcfg["IPV6_DEFAULTGW"] = ip["gateway6"]

            route4 = []
            route6 = []
            for r in ip["route"]:
                line = r["network"] + "/" + str(r["prefix"])
                if r["gateway"]:
                    line += " via " + r["gateway"]
                if r["metric"] != -1:
                    line += " metric " + str(r["metric"])

                if r["family"] == socket.AF_INET:
                    route4.append(line)
                else:
                    route6.append(line)

            route4_file = cls._ifcfg_route_merge(
                route4,
                ip["route_append_only"] and content_current,
                content_current["route"] if content_current else None,
            )
            route6_file = cls._ifcfg_route_merge(
                route6,
                ip["route_append_only"] and content_current,
                content_current["route6"] if content_current else None,
            )

        if ip["rule_append_only"] and content_current:
            rule4_file = content_current["rule"]
            rule6_file = content_current["rule6"]

        for key in list(ifcfg.keys()):
            v = ifcfg[key]
            if v is None:
                del ifcfg[key]
                continue
            if isinstance(v, bool):
                ifcfg[key] = "yes" if v else "no"

        return {
            "ifcfg": ifcfg,
            "keys": keys_file,
            "route": route4_file,
            "route6": route6_file,
            "rule": rule4_file,
            "rule6": rule6_file,
        }

    @classmethod
    def ifcfg_parse_line(cls, line):
        r1 = getattr(cls, "_re_parse_line1", None)
        if r1 is None:
            r1 = re.compile("^[ \t]*([a-zA-Z_][a-zA-Z_0-9]*)=(.*)$")
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
        except Exception:
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
    def content_from_dict(cls, ifcfg_all, file_type=None, header=None):
        content = {}
        for file_type in cls._file_types(file_type):
            h = ifcfg_all[file_type]
            if file_type == "ifcfg":
                if header is not None:
                    s = header + "\n"
                else:
                    s = ""
                for key in sorted(h.keys()):
                    value = h[key]
                    if not cls.KeyValid(key):
                        raise MyError("invalid ifcfg key %s" % (key))
                    if value is not None:
                        s += key + "=" + cls.ValueEscape(value) + "\n"
                content[file_type] = s
            else:
                content[file_type] = h

        return content

    @classmethod
    def content_to_dict(cls, content, file_type=None):
        ifcfg_all = {}
        for file_type in cls._file_types(file_type):
            ifcfg_all[file_type] = cls.ifcfg_parse(content[file_type])
        return ifcfg_all

    @classmethod
    def content_from_file(cls, name, file_type=None):
        """
        Return dictionary with all file contents for an initscripts profile
        """
        content = {}
        for file_type in cls._file_types(file_type):
            path = cls.ifcfg_path(name, file_type)
            try:
                with open(path, "r") as content_file:
                    i_content = content_file.read()
            except Exception:
                i_content = None
            content[file_type] = i_content
        return content

    @classmethod
    def content_to_file(cls, name, content, file_type=None):
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
                with open(path, "w") as text_file:
                    text_file.write(h)

    @classmethod
    def connection_seems_active(cls, name):
        # we don't know whether a ifcfg file is currently active,
        # and we also don't know which.
        #
        # Do a very basic guess based on whether the interface
        # is in operstate "up".
        #
        # But first we need to find the interface name. Do
        # some naive parsing and check for DEVICE setting.
        content = cls.content_from_file(name, "ifcfg")
        if content["ifcfg"] is not None:
            content = cls.ifcfg_parse(content["ifcfg"])
        else:
            content = {}
        if "DEVICE" not in content:
            return None
        path = "/sys/class/net/" + content["DEVICE"] + "/operstate"
        try:
            with open(path, "r") as content_file:
                i_content = str(content_file.read())
        except Exception:
            return None

        if i_content.strip() != "up":
            return False

        return True


###############################################################################


class NMUtil:
    def __init__(self, nmclient=None):
        if nmclient is None:
            nmclient = Util.NM().Client.new(None)
        self.nmclient = nmclient

    def setting_ip_config_get_routes(self, s_ip):
        if s_ip is not None:
            for i in range(0, s_ip.get_num_routes()):
                yield s_ip.get_route(i)

    def connection_ensure_setting(self, connection, setting_type):
        setting = connection.get_setting(setting_type)
        if not setting:
            setting = setting_type.new()
            connection.add_setting(setting)
        return setting

    def device_is_master_type(self, dev):
        if dev:
            NM = Util.NM()
            GObject = Util.GObject()
            if (
                GObject.type_is_a(dev, NM.DeviceBond)
                or GObject.type_is_a(dev, NM.DeviceBridge)
                or GObject.type_is_a(dev, NM.DeviceTeam)
            ):
                return True
        return False

    def active_connection_list(self, connections=None, black_list=None):
        active_cons = self.nmclient.get_active_connections()
        if connections:
            connections = set(connections)
            active_cons = [
                ac for ac in active_cons if ac.get_connection() in connections
            ]
        if black_list:
            active_cons = [ac for ac in active_cons if ac not in black_list]
        return list(active_cons)

    def connection_list(
        self,
        name=None,
        uuid=None,
        black_list=None,
        black_list_names=None,
        black_list_uuids=None,
    ):
        cons = self.nmclient.get_connections()
        if name is not None:
            cons = [c for c in cons if c.get_id() == name]
        if uuid is not None:
            cons = [c for c in cons if c.get_uuid() == uuid]

        if black_list:
            cons = [c for c in cons if c not in black_list]
        if black_list_uuids:
            cons = [c for c in cons if c.get_uuid() not in black_list_uuids]
        if black_list_names:
            cons = [c for c in cons if c.get_id() not in black_list_names]

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

        if Util.PY3:
            # functools.cmp_to_key does not exist in Python 2.6
            cons.sort(key=functools.cmp_to_key(_cmp))
        else:
            cons.sort(cmp=_cmp)
        return cons

    def connection_compare(
        self, con_a, con_b, normalize_a=False, normalize_b=False, compare_flags=None
    ):
        NM = Util.NM()

        if normalize_a:
            con_a = NM.SimpleConnection.new_clone(con_a)
            try:
                con_a.normalize()
            except Exception:
                pass
        if normalize_b:
            con_b = NM.SimpleConnection.new_clone(con_b)
            try:
                con_b.normalize()
            except Exception:
                pass
        if compare_flags is None:
            compare_flags = NM.SettingCompareFlags.IGNORE_TIMESTAMP

        return not (not (con_a.compare(con_b, compare_flags)))

    def connection_is_active(self, con):
        NM = Util.NM()
        for ac in self.active_connection_list(connections=[con]):
            if (
                ac.get_state() >= NM.ActiveConnectionState.ACTIVATING
                and ac.get_state() <= NM.ActiveConnectionState.ACTIVATED
            ):
                return True
        return False

    def connection_create(self, connections, idx, connection_current=None):
        NM = Util.NM()

        connection = connections[idx]

        con = NM.SimpleConnection.new()
        s_con = self.connection_ensure_setting(con, NM.SettingConnection)

        s_con.set_property(NM.SETTING_CONNECTION_ID, connection["name"])
        s_con.set_property(NM.SETTING_CONNECTION_UUID, connection["nm.uuid"])
        s_con.set_property(NM.SETTING_CONNECTION_AUTOCONNECT, connection["autoconnect"])
        s_con.set_property(
            NM.SETTING_CONNECTION_INTERFACE_NAME, connection["interface_name"]
        )

        if connection["type"] == "ethernet":
            s_con.set_property(
                NM.SETTING_CONNECTION_TYPE, NM.SETTING_WIRED_SETTING_NAME
            )
            s_wired = self.connection_ensure_setting(con, NM.SettingWired)
            s_wired.set_property(NM.SETTING_WIRED_MAC_ADDRESS, connection["mac"])
        elif connection["type"] == "infiniband":
            s_con.set_property(
                NM.SETTING_CONNECTION_TYPE, NM.SETTING_INFINIBAND_SETTING_NAME
            )
            s_infiniband = self.connection_ensure_setting(con, NM.SettingInfiniband)
            s_infiniband.set_property(
                NM.SETTING_INFINIBAND_MAC_ADDRESS, connection["mac"]
            )
            s_infiniband.set_property(
                NM.SETTING_INFINIBAND_TRANSPORT_MODE,
                connection["infiniband"]["transport_mode"],
            )
            if connection["infiniband"]["p_key"] != -1:
                s_infiniband.set_property(
                    NM.SETTING_INFINIBAND_P_KEY, connection["infiniband"]["p_key"]
                )
                if connection["parent"]:
                    s_infiniband.set_property(
                        NM.SETTING_INFINIBAND_PARENT,
                        ArgUtil.connection_find_master(
                            connection["parent"], connections, idx
                        ),
                    )
        elif connection["type"] == "bridge":
            s_con.set_property(
                NM.SETTING_CONNECTION_TYPE, NM.SETTING_BRIDGE_SETTING_NAME
            )
            s_bridge = self.connection_ensure_setting(con, NM.SettingBridge)
            s_bridge.set_property(NM.SETTING_BRIDGE_STP, False)
        elif connection["type"] == "bond":
            s_con.set_property(NM.SETTING_CONNECTION_TYPE, NM.SETTING_BOND_SETTING_NAME)
            s_bond = self.connection_ensure_setting(con, NM.SettingBond)
            s_bond.add_option("mode", connection["bond"]["mode"])
            if connection["bond"]["miimon"] is not None:
                s_bond.add_option("miimon", str(connection["bond"]["miimon"]))
        elif connection["type"] == "team":
            s_con.set_property(NM.SETTING_CONNECTION_TYPE, NM.SETTING_TEAM_SETTING_NAME)
        elif connection["type"] == "vlan":
            s_con.set_property(NM.SETTING_CONNECTION_TYPE, NM.SETTING_VLAN_SETTING_NAME)
            s_vlan = self.connection_ensure_setting(con, NM.SettingVlan)
            s_vlan.set_property(NM.SETTING_VLAN_ID, connection["vlan"]["id"])
            s_vlan.set_property(
                NM.SETTING_VLAN_PARENT,
                ArgUtil.connection_find_master_uuid(
                    connection["parent"], connections, idx
                ),
            )
        elif connection["type"] == "macvlan":
            s_con.set_property(
                NM.SETTING_CONNECTION_TYPE, NM.SETTING_MACVLAN_SETTING_NAME
            )
            # convert mode name to a number (which is actually expected by nm)
            mode = connection["macvlan"]["mode"]
            try:
                mode_id = int(getattr(NM.SettingMacvlanMode, mode.upper()))
            except AttributeError:
                raise MyError("Macvlan mode '%s' is not recognized" % (mode))
            s_macvlan = self.connection_ensure_setting(con, NM.SettingMacvlan)
            s_macvlan.set_property(NM.SETTING_MACVLAN_MODE, mode_id)
            s_macvlan.set_property(
                NM.SETTING_MACVLAN_PROMISCUOUS, connection["macvlan"]["promiscuous"]
            )
            s_macvlan.set_property(NM.SETTING_MACVLAN_TAP, connection["macvlan"]["tap"])
            s_macvlan.set_property(
                NM.SETTING_MACVLAN_PARENT,
                ArgUtil.connection_find_master(connection["parent"], connections, idx),
            )
        else:
            raise MyError("unsupported type %s" % (connection["type"]))

        if "ethernet" in connection:
            if connection["ethernet"]["autoneg"] is not None:
                s_wired = self.connection_ensure_setting(con, NM.SettingWired)
                s_wired.set_property(
                    NM.SETTING_WIRED_AUTO_NEGOTIATE, connection["ethernet"]["autoneg"]
                )
                s_wired.set_property(
                    NM.SETTING_WIRED_DUPLEX, connection["ethernet"]["duplex"]
                )
                s_wired.set_property(
                    NM.SETTING_WIRED_SPEED, connection["ethernet"]["speed"]
                )

        if hasattr(NM, "SettingEthtool"):
            s_ethtool = self.connection_ensure_setting(con, NM.SettingEthtool)

            for feature, setting in connection["ethtool"]["features"].items():
                nm_feature = nm_provider.get_nm_ethtool_feature(feature)

                if setting is None:
                    if nm_feature:
                        s_ethtool.set_feature(nm_feature, NM.Ternary.DEFAULT)
                elif setting:
                    s_ethtool.set_feature(nm_feature, NM.Ternary.TRUE)
                else:
                    s_ethtool.set_feature(nm_feature, NM.Ternary.FALSE)

        if connection["mtu"]:
            if connection["type"] == "infiniband":
                s_infiniband = self.connection_ensure_setting(con, NM.SettingInfiniband)
                s_infiniband.set_property(NM.SETTING_INFINIBAND_MTU, connection["mtu"])
            else:
                s_wired = self.connection_ensure_setting(con, NM.SettingWired)
                s_wired.set_property(NM.SETTING_WIRED_MTU, connection["mtu"])

        if connection["master"] is not None:
            s_con.set_property(
                NM.SETTING_CONNECTION_SLAVE_TYPE, connection["slave_type"]
            )
            s_con.set_property(
                NM.SETTING_CONNECTION_MASTER,
                ArgUtil.connection_find_master_uuid(
                    connection["master"], connections, idx
                ),
            )
        else:
            if connection["zone"]:
                s_con.set_property(NM.SETTING_CONNECTION_ZONE, connection["zone"])

            ip = connection["ip"]

            s_ip4 = self.connection_ensure_setting(con, NM.SettingIP4Config)
            s_ip6 = self.connection_ensure_setting(con, NM.SettingIP6Config)

            s_ip4.set_property(NM.SETTING_IP_CONFIG_METHOD, "auto")
            s_ip6.set_property(NM.SETTING_IP_CONFIG_METHOD, "auto")

            addrs4 = list([a for a in ip["address"] if a["family"] == socket.AF_INET])
            addrs6 = list([a for a in ip["address"] if a["family"] == socket.AF_INET6])

            if ip["dhcp4"]:
                s_ip4.set_property(NM.SETTING_IP_CONFIG_METHOD, "auto")
                s_ip4.set_property(
                    NM.SETTING_IP_CONFIG_DHCP_SEND_HOSTNAME,
                    ip["dhcp4_send_hostname"] is not False,
                )
            elif addrs4:
                s_ip4.set_property(NM.SETTING_IP_CONFIG_METHOD, "manual")
            else:
                s_ip4.set_property(NM.SETTING_IP_CONFIG_METHOD, "disabled")
            for a in addrs4:
                s_ip4.add_address(
                    NM.IPAddress.new(a["family"], a["address"], a["prefix"])
                )
            if ip["gateway4"] is not None:
                s_ip4.set_property(NM.SETTING_IP_CONFIG_GATEWAY, ip["gateway4"])
            if ip["route_metric4"] is not None and ip["route_metric4"] >= 0:
                s_ip4.set_property(
                    NM.SETTING_IP_CONFIG_ROUTE_METRIC, ip["route_metric4"]
                )
            for d in ip["dns"]:
                if d["family"] == socket.AF_INET:
                    s_ip4.add_dns(d["address"])
            for s in ip["dns_search"]:
                s_ip4.add_dns_search(s)

            if ip["auto6"]:
                s_ip6.set_property(NM.SETTING_IP_CONFIG_METHOD, "auto")
            elif addrs6:
                s_ip6.set_property(NM.SETTING_IP_CONFIG_METHOD, "manual")
            else:
                s_ip6.set_property(NM.SETTING_IP_CONFIG_METHOD, "ignore")
            for a in addrs6:
                s_ip6.add_address(
                    NM.IPAddress.new(a["family"], a["address"], a["prefix"])
                )
            if ip["gateway6"] is not None:
                s_ip6.set_property(NM.SETTING_IP_CONFIG_GATEWAY, ip["gateway6"])
            if ip["route_metric6"] is not None and ip["route_metric6"] >= 0:
                s_ip6.set_property(
                    NM.SETTING_IP_CONFIG_ROUTE_METRIC, ip["route_metric6"]
                )
            for d in ip["dns"]:
                if d["family"] == socket.AF_INET6:
                    s_ip6.add_dns(d["address"])

            if ip["route_append_only"] and connection_current:
                for r in self.setting_ip_config_get_routes(
                    connection_current.get_setting(NM.SettingIP4Config)
                ):
                    s_ip4.add_route(r)
                for r in self.setting_ip_config_get_routes(
                    connection_current.get_setting(NM.SettingIP6Config)
                ):
                    s_ip6.add_route(r)
            for r in ip["route"]:
                rr = NM.IPRoute.new(
                    r["family"], r["network"], r["prefix"], r["gateway"], r["metric"]
                )
                if r["family"] == socket.AF_INET:
                    s_ip4.add_route(rr)
                else:
                    s_ip6.add_route(rr)

        if connection["ieee802_1x"]:
            s_8021x = self.connection_ensure_setting(con, NM.Setting8021x)

            s_8021x.set_property(
                NM.SETTING_802_1X_EAP, [connection["ieee802_1x"]["eap"]]
            )
            s_8021x.set_property(
                NM.SETTING_802_1X_IDENTITY, connection["ieee802_1x"]["identity"]
            )

            s_8021x.set_property(
                NM.SETTING_802_1X_PRIVATE_KEY,
                Util.path_to_glib_bytes(connection["ieee802_1x"]["private_key"]),
            )

            if connection["ieee802_1x"]["private_key_password"]:
                s_8021x.set_property(
                    NM.SETTING_802_1X_PRIVATE_KEY_PASSWORD,
                    connection["ieee802_1x"]["private_key_password"],
                )

            if connection["ieee802_1x"]["private_key_password_flags"]:
                s_8021x.set_secret_flags(
                    NM.SETTING_802_1X_PRIVATE_KEY_PASSWORD,
                    Util.NM().SettingSecretFlags(
                        Util.convert_passwd_flags_nm(
                            connection["ieee802_1x"]["private_key_password_flags"]
                        ),
                    ),
                )

            s_8021x.set_property(
                NM.SETTING_802_1X_CLIENT_CERT,
                Util.path_to_glib_bytes(connection["ieee802_1x"]["client_cert"]),
            )

            if connection["ieee802_1x"]["ca_cert"]:
                s_8021x.set_property(
                    NM.SETTING_802_1X_CA_CERT,
                    Util.path_to_glib_bytes(connection["ieee802_1x"]["ca_cert"]),
                )

            s_8021x.set_property(
                NM.SETTING_802_1X_SYSTEM_CA_CERTS,
                connection["ieee802_1x"]["system_ca_certs"],
            )

            if connection["ieee802_1x"]["domain_suffix_match"]:
                s_8021x.set_property(
                    NM.SETTING_802_1X_DOMAIN_SUFFIX_MATCH,
                    connection["ieee802_1x"]["domain_suffix_match"],
                )

        try:
            con.normalize()
        except Exception as e:
            raise MyError("created connection failed to normalize: %s" % (e))
        return con

    def connection_add(self, con, timeout=10):
        def add_cb(client, result, cb_args):
            con = None
            try:
                con = client.add_connection_finish(result)
            except Exception as e:
                if Util.error_is_cancelled(e):
                    return
                cb_args["error"] = str(e)
            cb_args["con"] = con
            Util.GMainLoop().quit()

        cancellable = Util.create_cancellable()
        cb_args = {}
        self.nmclient.add_connection_async(con, True, cancellable, add_cb, cb_args)
        if not Util.GMainLoop_run(timeout):
            cancellable.cancel()
            raise MyError("failure to add connection: %s" % ("timeout"))
        if not cb_args.get("con", None):
            raise MyError(
                "failure to add connection: %s"
                % (cb_args.get("error", "unknown error"))
            )
        return cb_args["con"]

    def connection_update(self, con, con_new, timeout=10):
        con.replace_settings_from_connection(con_new)

        def update_cb(connection, result, cb_args):
            success = False
            try:
                success = connection.commit_changes_finish(result)
            except Exception as e:
                if Util.error_is_cancelled(e):
                    return
                cb_args["error"] = str(e)
            cb_args["success"] = success
            Util.GMainLoop().quit()

        cancellable = Util.create_cancellable()
        cb_args = {}
        con.commit_changes_async(True, cancellable, update_cb, cb_args)
        if not Util.GMainLoop_run(timeout):
            cancellable.cancel()
            raise MyError("failure to update connection: %s" % ("timeout"))
        if not cb_args.get("success", False):
            raise MyError(
                "failure to update connection: %s"
                % (cb_args.get("error", "unknown error"))
            )
        return True

    def connection_delete(self, connection, timeout=10):

        # Do nothing, if the connection is already gone
        if connection not in self.connection_list():
            return

        if "update2" in dir(connection):
            return self.volatilize_connection(connection, timeout)

        delete_cb = Util.create_callback("delete_finish")

        cancellable = Util.create_cancellable()
        cb_args = {}
        connection.delete_async(cancellable, delete_cb, cb_args)
        if not Util.GMainLoop_run(timeout):
            cancellable.cancel()
            raise MyError("failure to delete connection: %s" % ("timeout"))
        if not cb_args.get("success", False):
            raise MyError(
                "failure to delete connection: %s"
                % (cb_args.get("error", "unknown error"))
            )

        # workaround libnm oddity. The connection may not yet be gone if the
        # connection was active and is deactivating. Wait.
        c_uuid = connection.get_uuid()
        gone = self.wait_till_connection_is_gone(c_uuid)
        if not gone:
            raise MyError(
                "connection %s was supposedly deleted successfully, but it's still here"
                % (c_uuid)
            )

    def volatilize_connection(self, connection, timeout=10):
        update2_cb = Util.create_callback("update2_finish")

        cancellable = Util.create_cancellable()
        cb_args = {}

        connection.update2(
            None,  # settings
            Util.NM().SettingsUpdate2Flags.IN_MEMORY_ONLY
            | Util.NM().SettingsUpdate2Flags.VOLATILE,  # flags
            None,  # args
            cancellable,
            update2_cb,
            cb_args,
        )

        if not Util.GMainLoop_run(timeout):
            cancellable.cancel()
            raise MyError("failure to volatilize connection: %s" % ("timeout"))

        Util.GMainLoop_iterate_all()

        # Do not check of success if the connection does not exist anymore This
        # can happen if the connection was already volatile and set to down
        # during the module call
        if connection not in self.connection_list():
            return

        # update2_finish returns None on failure and a GLib.Variant of type
        # a{sv} with the result otherwise (which can be empty)
        if cb_args.get("success", None) is None:
            raise MyError(
                "failure to volatilize connection: %s: %r"
                % (cb_args.get("error", "unknown error"), cb_args)
            )

    def create_checkpoint(self, timeout):
        """ Create a new checkpoint """
        checkpoint = Util.call_async_method(
            self.nmclient,
            "checkpoint_create",
            [
                [],  # devices, empty list is all devices
                timeout,
                Util.NM().CheckpointCreateFlags.DELETE_NEW_CONNECTIONS
                | Util.NM().CheckpointCreateFlags.DISCONNECT_NEW_DEVICES,
            ],
        )

        if checkpoint:
            return checkpoint.get_path()
        return None

    def destroy_checkpoint(self, path):
        """ Destroy the specified checkpoint """
        Util.call_async_method(self.nmclient, "checkpoint_destroy", [path])

    def rollback_checkpoint(self, path):
        """ Rollback the specified checkpoint """
        Util.call_async_method(
            self.nmclient,
            "checkpoint_rollback",
            [path],
            mainloop_timeout=DEFAULT_ACTIVATION_TIMEOUT,
        )

    def wait_till_connection_is_gone(self, uuid, timeout=10):
        """
        Wait until a connection is gone or until the timeout elapsed

        :param uuid: UUID of the connection that to wait for to be gone
        :param timeout: Timeout in seconds to wait for
        :returns: True when connection is gone, False when timeout elapsed
        :rtype: bool
        """

        def _poll_timeout_cb(unused):
            if not self.connection_list(uuid=uuid):
                Util.GMainLoop().quit()

        poll_timeout_id = Util.GLib().timeout_add(100, _poll_timeout_cb, None)
        gone = Util.GMainLoop_run(timeout)
        Util.GLib().source_remove(poll_timeout_id)
        return gone

    def connection_activate(self, connection, timeout=15, wait_time=None):

        already_retried = False

        while True:

            def activate_cb(client, result, cb_args):
                active_connection = None
                try:
                    active_connection = client.activate_connection_finish(result)
                except Exception as e:
                    if Util.error_is_cancelled(e):
                        return
                    cb_args["error"] = str(e)
                cb_args["active_connection"] = active_connection
                Util.GMainLoop().quit()

            cancellable = Util.create_cancellable()
            cb_args = {}
            self.nmclient.activate_connection_async(
                connection, None, None, cancellable, activate_cb, cb_args
            )
            if not Util.GMainLoop_run(timeout):
                cancellable.cancel()
                raise MyError("failure to activate connection: %s" % ("timeout"))

            if cb_args.get("active_connection", None):
                ac = cb_args["active_connection"]
                self.connection_activate_wait(ac, wait_time)
                return ac

            # there is a bug in NetworkManager, that the connection
            # might already be in the process of activating. In that
            # case, NM would reject the activation request with
            # "Connection '$PROFILE' is not available on the device $DEV
            # at this time."
            #
            # Try to work around it by waiting a bit and retrying.
            if already_retried:
                raise MyError(
                    "failure to activate connection: %s"
                    % (cb_args.get("error", "unknown error"))
                )

            already_retried = True

            time.sleep(1)

    def connection_activate_wait(self, ac, wait_time):

        if not wait_time:
            return

        NM = Util.NM()

        state = ac.get_state()
        if state == NM.ActiveConnectionState.ACTIVATED:
            return
        if state != NM.ActiveConnectionState.ACTIVATING:
            raise MyError("activation is in unexpected state '%s'" % (state))

        def check_activated(ac, dev):
            ac_state = ac.get_state()

            # the state reason was for active-connection was introduced
            # in NM 1.8 API. Work around for older library version.
            try:
                ac_reason = ac.get_state_reason()
            except AttributeError:
                ac_reason = None

            if dev:
                dev_state = dev.get_state()

            if ac_state == NM.ActiveConnectionState.ACTIVATING:
                if (
                    self.device_is_master_type(dev)
                    and dev_state >= NM.DeviceState.IP_CONFIG
                    and dev_state <= NM.DeviceState.ACTIVATED
                ):
                    # master connections qualify as activated once they
                    # reach IP-Config state. That is because they may
                    # wait for slave devices to attach
                    return True, None
                # fall through
            elif ac_state == NM.ActiveConnectionState.ACTIVATED:
                return True, None
            elif ac_state == NM.ActiveConnectionState.DEACTIVATED:
                if (
                    not dev
                    or (
                        ac_reason is not None
                        and ac_reason
                        != NM.ActiveConnectionStateReason.DEVICE_DISCONNECTED
                    )
                    or dev.get_active_connection() is not ac
                ):
                    return (
                        True,
                        (
                            (ac_reason.value_nick if ac_reason else None)
                            or "unknown reason"
                        ),
                    )
                # the state of the active connection is not very helpful.
                # see if the device-state is better.
                if (
                    dev_state <= NM.DeviceState.DISCONNECTED
                    or dev_state > NM.DeviceState.DEACTIVATING
                ):
                    return (
                        True,
                        (
                            dev.get_state_reason().value_nick
                            or (ac_reason.value_nick if ac_reason else None)
                            or "unknown reason"
                        ),
                    )
                # fall through, wait longer for a better state reason.

            # wait longer.
            return False, None

        dev = Util.first(ac.get_devices())

        complete, failure_reason = check_activated(ac, dev)

        if not complete:

            cb_out = []

            def check_activated_cb():
                complete, failure_reason = check_activated(ac, dev)
                if complete:
                    cb_out.append(failure_reason)
                    Util.GMainLoop().quit()

            try:
                # 'state-changed' signal is 1.8 API. Workaround for
                # older libnm API version
                ac_id = ac.connect(
                    "state-changed", lambda source, state, reason: check_activated_cb()
                )
            except Exception:
                ac_id = None
            if dev:
                dev_id = dev.connect(
                    "notify::state", lambda source, pspec: check_activated_cb()
                )

            try:
                if not Util.GMainLoop_run(wait_time):
                    raise MyError("connection not fully activated after timeout")
            finally:
                if dev:
                    dev.handler_disconnect(dev_id)
                if ac_id is not None:
                    ac.handler_disconnect(ac_id)

            failure_reason = cb_out[0]

        if failure_reason:
            raise MyError("connection not activated: %s" % (failure_reason))

    def active_connection_deactivate(self, ac, timeout=10, wait_time=None):
        def deactivate_cb(client, result, cb_args):
            success = False
            try:
                success = client.deactivate_connection_finish(result)
            except Exception as e:
                if Util.error_is_cancelled(e):
                    return
                cb_args["error"] = str(e)
            cb_args["success"] = success
            Util.GMainLoop().quit()

        cancellable = Util.create_cancellable()
        cb_args = {}
        self.nmclient.deactivate_connection_async(
            ac, cancellable, deactivate_cb, cb_args
        )
        if not Util.GMainLoop_run(timeout):
            cancellable.cancel()
            raise MyError("failure to deactivate connection: %s" % (timeout))
        if not cb_args.get("success", False):
            raise MyError(
                "failure to deactivate connection: %s"
                % (cb_args.get("error", "unknown error"))
            )

        self.active_connection_deactivate_wait(ac, wait_time)
        return True

    def active_connection_deactivate_wait(self, ac, wait_time):

        if not wait_time:
            return

        NM = Util.NM()

        def check_deactivated(ac):
            return ac.get_state() >= NM.ActiveConnectionState.DEACTIVATED

        if not check_deactivated(ac):

            def check_deactivated_cb():
                if check_deactivated(ac):
                    Util.GMainLoop().quit()

            ac_id = ac.connect(
                "notify::state", lambda source, pspec: check_deactivated_cb()
            )

            try:
                if not Util.GMainLoop_run(wait_time):
                    raise MyError("connection not fully deactivated after timeout")
            finally:
                ac.handler_disconnect(ac_id)

    def reapply(self, device, connection=None):
        version_id = 0
        flags = 0
        return Util.call_async_method(
            device, "reapply", [connection, version_id, flags]
        )


###############################################################################


class RunEnvironment(object):
    def __init__(self):
        self._check_mode = None

    @property
    def ifcfg_header(self):
        return None

    def log(
        self,
        connections,
        idx,
        severity,
        msg,
        is_changed=False,
        ignore_errors=False,
        warn_traceback=False,
        force_fail=False,
    ):
        raise NotImplementedError()

    def run_command(self, argv, encoding=None):
        raise NotImplementedError()

    def _check_mode_changed(self, old_check_mode, new_check_mode, connections):
        raise NotImplementedError()

    def check_mode_set(self, check_mode, connections=None):
        c = self._check_mode
        self._check_mode = check_mode
        assert (
            (c is None and check_mode in [CheckMode.PREPARE])
            or (
                c == CheckMode.PREPARE
                and check_mode in [CheckMode.PRE_RUN, CheckMode.DRY_RUN]
            )
            or (c == CheckMode.PRE_RUN and check_mode in [CheckMode.REAL_RUN])
            or (c == CheckMode.REAL_RUN and check_mode in [CheckMode.DONE])
            or (c == CheckMode.DRY_RUN and check_mode in [CheckMode.DONE])
        )
        self._check_mode_changed(c, check_mode, connections)


class RunEnvironmentAnsible(RunEnvironment):

    ARGS = {
        "ignore_errors": {"required": False, "default": False, "type": "bool"},
        "force_state_change": {"required": False, "default": False, "type": "bool"},
        "provider": {"required": True, "default": None, "type": "str"},
        "connections": {"required": False, "default": None, "type": "list"},
        "__debug_flags": {"required": False, "default": "", "type": "str"},
    }

    def __init__(self):
        RunEnvironment.__init__(self)
        self._run_results = []
        self._log_idx = 0
        self.on_failure = None
        module = AnsibleModule(argument_spec=self.ARGS, supports_check_mode=True)
        self.module = module

    @property
    def ifcfg_header(self):
        return "# this file was created by ansible"

    def run_command(self, argv, encoding=None):
        return self.module.run_command(argv, encoding=encoding)

    def _run_results_push(self, n_connections):
        c = []
        for cc in range(0, n_connections + 1):
            c.append({"log": []})
        self._run_results.append(c)

    @property
    def run_results(self):
        return self._run_results[-1]

    def _check_mode_changed(self, old_check_mode, new_check_mode, connections):
        if old_check_mode is None:
            self._run_results_push(len(connections))
        elif old_check_mode == CheckMode.PREPARE:
            self._run_results_push(len(self.run_results) - 1)
        elif old_check_mode == CheckMode.PRE_RUN:
            # when switching from RRE_RUN to REAL_RUN, we drop the run-results
            # we just collected and reset to empty. The PRE_RUN succeeded.
            n_connections = len(self.run_results) - 1
            del self._run_results[-1]
            self._run_results_push(n_connections)

    def log(
        self,
        connections,
        idx,
        severity,
        msg,
        is_changed=False,
        ignore_errors=False,
        warn_traceback=False,
        force_fail=False,
    ):
        assert idx >= -1
        self._log_idx += 1
        self.run_results[idx]["log"].append((severity, msg, self._log_idx))
        if severity == LogLevel.ERROR:
            if force_fail or not ignore_errors:
                self.fail_json(
                    connections,
                    "error: %s" % (msg),
                    changed=is_changed,
                    warn_traceback=warn_traceback,
                )

    def _complete_kwargs_loglines(self, rr, connections, idx):
        if idx == len(connections):
            prefix = "#"
        else:
            c = connections[idx]
            prefix = "#%s, state:%s persistent_state:%s" % (
                idx,
                c["state"],
                c["persistent_state"],
            )
            prefix = prefix + (", '%s'" % (c["name"]))
        for severity, msg, idx in rr["log"]:
            yield (
                idx,
                "[%03d] %s %s: %s" % (idx, LogLevel.fmt(severity), prefix, msg),
                severity,
            )

    def _complete_kwargs(self, connections, kwargs, traceback_msg=None, fail=False):
        warning_logs = kwargs.get("warnings", [])
        debug_logs = []
        loglines = []
        for res in self._run_results:
            for idx, rr in enumerate(res):
                loglines.extend(self._complete_kwargs_loglines(rr, connections, idx))
        loglines.sort(key=lambda log_line: log_line[0])
        for idx, log_line, severity in loglines:
            debug_logs.append(log_line)
            if fail:
                warning_logs.append(log_line)
            elif severity >= LogLevel.WARN:
                warning_logs.append(log_line)
        if traceback_msg is not None:
            warning_logs.append(traceback_msg)
        kwargs["warnings"] = warning_logs
        stderr = "\n".join(debug_logs) + "\n"
        kwargs["stderr"] = stderr
        return kwargs

    def exit_json(self, connections, changed=False, **kwargs):
        kwargs["changed"] = changed
        self.module.exit_json(**self._complete_kwargs(connections, kwargs))

    def fail_json(
        self, connections, msg, changed=False, warn_traceback=False, **kwargs
    ):
        if self.on_failure:
            self.on_failure()

        traceback_msg = None
        if warn_traceback:
            traceback_msg = "exception: %s" % (traceback.format_exc())
        kwargs["msg"] = msg
        kwargs["changed"] = changed
        self.module.fail_json(
            **self._complete_kwargs(connections, kwargs, traceback_msg, fail=True)
        )


###############################################################################


class Cmd(object):
    def __init__(
        self,
        run_env,
        connections_unvalidated,
        connection_validator,
        is_check_mode=False,
        ignore_errors=False,
        force_state_change=False,
        debug_flags="",
    ):
        self.run_env = run_env
        self.validate_one_type = None
        self._connections_unvalidated = connections_unvalidated
        self._connection_validator = connection_validator
        self._is_check_mode = is_check_mode
        self._ignore_errors = Util.boolean(ignore_errors)
        self._force_state_change = Util.boolean(force_state_change)

        self._connections = None
        self._connections_data = None
        self._check_mode = CheckMode.PREPARE
        self._is_changed_modified_system = False
        self._debug_flags = debug_flags

    def run_command(self, argv, encoding=None):
        return self.run_env.run_command(argv, encoding=encoding)

    @property
    def is_changed_modified_system(self):
        return self._is_changed_modified_system

    @property
    def connections(self):
        c = self._connections
        if c is None:
            try:
                c = self._connection_validator.validate(self._connections_unvalidated)
            except ValidationError as e:
                raise MyError("configuration error: %s" % (e))
            self._connections = c
        return c

    @property
    def connections_data(self):
        c = self._connections_data
        if c is None:
            assert self.check_mode in [
                CheckMode.DRY_RUN,
                CheckMode.PRE_RUN,
                CheckMode.REAL_RUN,
            ]
            c = []
            for _ in range(0, len(self.connections)):
                c.append({"changed": False})
            self._connections_data = c
        return c

    def connections_data_reset(self):
        for c in self.connections_data:
            c["changed"] = False

    def connections_data_set_changed(self, idx, changed=True):
        assert self._check_mode in [
            CheckMode.PRE_RUN,
            CheckMode.DRY_RUN,
            CheckMode.REAL_RUN,
        ]
        if not changed:
            return
        self.connections_data[idx]["changed"] = changed
        if changed and self._check_mode in [CheckMode.DRY_RUN, CheckMode.REAL_RUN]:
            # we only do actual modifications during the REAL_RUN step.
            # And as a special exception, during the DRY_RUN step, which
            # is like REAL_RUN, except not not actually changing anything.
            self._is_changed_modified_system = True

    def log_debug(self, idx, msg):
        self.log(idx, LogLevel.DEBUG, msg)

    def log_info(self, idx, msg):
        self.log(idx, LogLevel.INFO, msg)

    def log_warn(self, idx, msg):
        self.log(idx, LogLevel.WARN, msg)

    def log_error(self, idx, msg, warn_traceback=False, force_fail=False):
        self.log(
            idx,
            LogLevel.ERROR,
            msg,
            warn_traceback=warn_traceback,
            force_fail=force_fail,
        )

    def log_fatal(self, idx, msg, warn_traceback=False):
        self.log(
            idx, LogLevel.ERROR, msg, warn_traceback=warn_traceback, force_fail=True
        )

    def log(self, idx, severity, msg, warn_traceback=False, force_fail=False):
        self.run_env.log(
            self.connections,
            idx,
            severity,
            msg,
            is_changed=self.is_changed_modified_system,
            ignore_errors=self.connection_ignore_errors(self.connections[idx]),
            warn_traceback=warn_traceback,
            force_fail=force_fail,
        )

    @staticmethod
    def create(provider, **kwargs):
        if provider == "nm":
            return Cmd_nm(**kwargs)
        elif provider == "initscripts":
            return Cmd_initscripts(**kwargs)
        raise MyError("unsupported provider %s" % (provider))

    def connection_force_state_change(self, connection):
        v = connection["force_state_change"]
        if v is not None:
            return v
        return self._force_state_change

    def connection_ignore_errors(self, connection):
        v = connection["ignore_errors"]
        if v is not None:
            return v
        return self._ignore_errors

    def connection_modified_earlier(self, idx):
        # for index @idx, check if any of the previous profiles [0..idx[
        # modify the connection.

        con = self.connections[idx]
        assert con["state"] in ["up", "down"]

        # also check, if the current profile is 'up' with a 'type' (which
        # possibly modifies the connection as well)
        if (
            con["state"] == "up"
            and "type" in con
            and self.connections_data[idx]["changed"]
        ):
            return True

        for i in reversed(range(idx)):
            c = self.connections[i]
            if "name" not in c:
                continue
            if c["name"] != con["name"]:
                continue

            c_state = c["state"]
            c_pstate = c["persistent_state"]
            if c_state == "up" and "type" not in c:
                pass
            elif c_state == "down":
                return True
            elif c_pstate == "absent":
                return True
            elif c_state == "up" or c_pstate == "present":
                if self.connections_data[idx]["changed"]:
                    return True

        return False

    @property
    def check_mode(self):
        return self._check_mode

    def check_mode_next(self):
        if self._check_mode == CheckMode.PREPARE:
            if self._is_check_mode:
                c = CheckMode.DRY_RUN
            else:
                c = CheckMode.PRE_RUN
        elif self.check_mode == CheckMode.PRE_RUN:
            self.connections_data_reset()
            c = CheckMode.REAL_RUN
        elif self._check_mode != CheckMode.DONE:
            c = CheckMode.DONE
        else:
            assert False
        self._check_mode = c
        self.run_env.check_mode_set(c)
        return c

    def run(self):
        self.run_env.check_mode_set(CheckMode.PREPARE, self.connections)
        for idx, connection in enumerate(self.connections):
            try:
                self._connection_validator.validate_connection_one(
                    self.validate_one_type, self.connections, idx
                )
            except ValidationError as e:
                self.log_fatal(idx, str(e))
        self.run_prepare()
        while self.check_mode_next() != CheckMode.DONE:
            if self.check_mode == CheckMode.REAL_RUN:
                self.start_transaction()

            for idx, connection in enumerate(self.connections):
                try:
                    for action in connection["actions"]:
                        if action == "absent":
                            self.run_action_absent(idx)
                        elif action == "present":
                            self.run_action_present(idx)
                        elif action == "up":
                            self.run_action_up(idx)
                        elif action == "down":
                            self.run_action_down(idx)
                        else:
                            assert False
                except Exception as error:
                    if self.check_mode == CheckMode.REAL_RUN:
                        self.rollback_transaction(idx, action, error)
                    raise

            if self.check_mode == CheckMode.REAL_RUN:
                self.finish_transaction()

    def run_prepare(self):
        for idx, connection in enumerate(self.connections):
            if "type" in connection and connection["check_iface_exists"]:
                # when the profile is tied to a certain interface via
                # 'interface_name' or 'mac', check that such an interface
                # exists.
                #
                # This check has many flaws, as we don't check whether the
                # existing interface has the right device type. Also, there is
                # some ambiguity between the current MAC address and the
                # permanent MAC address.
                li_mac = None
                li_ifname = None
                if connection["mac"]:
                    li_mac = SysUtil.link_info_find(mac=connection["mac"])
                    if not li_mac:
                        self.log_fatal(
                            idx,
                            "profile specifies mac '%s' but no such interface exists"
                            % (connection["mac"]),
                        )
                if connection["interface_name"]:
                    li_ifname = SysUtil.link_info_find(
                        ifname=connection["interface_name"]
                    )
                    if not li_ifname:
                        if connection["type"] == "ethernet":
                            self.log_fatal(
                                idx,
                                "profile specifies interface_name '%s' but no such "
                                "interface exists" % (connection["interface_name"]),
                            )
                        elif connection["type"] == "infiniband":
                            if connection["infiniband"]["p_key"] != -1:
                                self.log_fatal(
                                    idx,
                                    "profile specifies interface_name '%s' but no such "
                                    "infiniband interface exists"
                                    % (connection["interface_name"]),
                                )
                if li_mac and li_ifname and li_mac != li_ifname:
                    self.log_fatal(
                        idx,
                        "profile specifies interface_name '%s' and mac '%s' but no "
                        "such interface exists"
                        % (connection["interface_name"], connection["mac"]),
                    )

    def start_transaction(self):
        """ Hook before making changes """

    def finish_transaction(self):
        """ Hook for after all changes where made successfuly """

    def rollback_transaction(self, idx, action, error):
        """ Hook if configuring a profile results in an error

        :param idx: Index of the connection that triggered the error
        :param action: Action that triggered the error
        :param error: The error

        :type idx: int
        :type action: str
        :type error: Exception

        """
        self.log_warn(
            idx, "failure: %s (%s) [[%s]]" % (error, action, traceback.format_exc())
        )

    def on_failure(self):
        """ Hook to do any cleanup on failure before exiting """
        pass

    def run_action_absent(self, idx):
        raise NotImplementedError()

    def run_action_present(self, idx):
        raise NotImplementedError()

    def run_action_down(self, idx):
        raise NotImplementedError()

    def run_action_up(self, idx):
        raise NotImplementedError()


###############################################################################


class Cmd_nm(Cmd):
    def __init__(self, **kwargs):
        Cmd.__init__(self, **kwargs)
        self._nmutil = None
        self.validate_one_type = ArgValidator_ListConnections.VALIDATE_ONE_MODE_NM
        self._checkpoint = None

    @property
    def nmutil(self):
        if self._nmutil is None:
            try:
                nmclient = Util.NM().Client.new(None)
            except Exception as e:
                raise MyError("failure loading libnm library: %s" % (e))
            self._nmutil = NMUtil(nmclient)
        return self._nmutil

    def run_prepare(self):
        Cmd.run_prepare(self)

        names = {}
        for idx, connection in enumerate(self.connections):
            self._check_ethtool_setting_support(idx, connection)

            name = connection["name"]
            if not name:
                assert connection["persistent_state"] == "absent"
                continue
            if name in names:
                exists = names[name]["nm.exists"]
                uuid = names[name]["nm.uuid"]
            else:
                c = Util.first(self.nmutil.connection_list(name=name))

                exists = c is not None
                if c is not None:
                    uuid = c.get_uuid()
                else:
                    uuid = Util.create_uuid()
                names[name] = {"nm.exists": exists, "nm.uuid": uuid}
            connection["nm.exists"] = exists
            connection["nm.uuid"] = uuid

    def start_transaction(self):
        Cmd.start_transaction(self)
        if "disable-checkpoints" in self._debug_flags:
            pass
        else:
            self._checkpoint = self.nmutil.create_checkpoint(
                len(self.connections) * DEFAULT_ACTIVATION_TIMEOUT
            )

    def rollback_transaction(self, idx, action, error):
        Cmd.rollback_transaction(self, idx, action, error)
        self.on_failure()

    def finish_transaction(self):
        Cmd.finish_transaction(self)
        if self._checkpoint:
            try:
                self.nmutil.destroy_checkpoint(self._checkpoint)
            finally:
                self._checkpoint = None

    def on_failure(self):
        if self._checkpoint:
            try:
                self.nmutil.rollback_checkpoint(self._checkpoint)
            finally:
                self._checkpoint = None

    def _check_ethtool_setting_support(self, idx, connection):
        """ Check if SettingEthtool support is needed and available

        If any feature is specified, the SettingEthtool setting needs to be
        available. Also NM needs to know about each specified setting. Do not
        check if NM knows about any defaults.

        """
        NM = Util.NM()

        # If the profile is not completely specified, for example if only the
        # runtime change is specified, the ethtool subtree might be missing.
        # Then no checks are required.
        if "ethtool" not in connection:
            return

        ethtool_features = connection["ethtool"]["features"]
        specified_features = dict(
            [(k, v) for k, v in ethtool_features.items() if v is not None]
        )

        if specified_features and not hasattr(NM, "SettingEthtool"):
            self.log_fatal(idx, "ethtool.features specified but not supported by NM")

        for feature, setting in specified_features.items():
            nm_feature = nm_provider.get_nm_ethtool_feature(feature)
            if not nm_feature:
                self.log_fatal(
                    idx, "ethtool feature %s specified but not support by NM" % feature
                )

    def run_action_absent(self, idx):
        seen = set()
        name = self.connections[idx]["name"]
        black_list_names = None
        if not name:
            name = None
            black_list_names = ArgUtil.connection_get_non_absent_names(self.connections)
        while True:
            connections = self.nmutil.connection_list(
                name=name, black_list_names=black_list_names, black_list=seen
            )
            if not connections:
                break
            c = connections[-1]
            seen.add(c)
            self.log_info(idx, "delete connection %s, %s" % (c.get_id(), c.get_uuid()))
            self.connections_data_set_changed(idx)
            if self.check_mode == CheckMode.REAL_RUN:
                try:
                    self.nmutil.connection_delete(c)
                except MyError as e:
                    self.log_error(idx, "delete connection failed: %s" % (e))
        if not seen:
            self.log_info(idx, "no connection '%s'" % (name))

    def run_action_present(self, idx):
        connection = self.connections[idx]
        con_cur = Util.first(
            self.nmutil.connection_list(
                name=connection["name"], uuid=connection["nm.uuid"]
            )
        )

        if not connection.get("type"):
            # if the type is not specified, just check that the connection was
            # found
            if not con_cur:
                self.log_error(
                    idx, "Connection not found on system and 'type' not specified"
                )
            return

        con_new = self.nmutil.connection_create(self.connections, idx, con_cur)
        if con_cur is None:
            self.log_info(
                idx,
                "add connection %s, %s" % (connection["name"], connection["nm.uuid"]),
            )
            self.connections_data_set_changed(idx)
            if self.check_mode == CheckMode.REAL_RUN:
                try:
                    con_cur = self.nmutil.connection_add(con_new)
                except MyError as e:
                    self.log_error(idx, "adding connection failed: %s" % (e))
        elif not self.nmutil.connection_compare(con_cur, con_new, normalize_a=True):
            self.log_info(
                idx, "update connection %s, %s" % (con_cur.get_id(), con_cur.get_uuid())
            )
            self.connections_data_set_changed(idx)
            if self.check_mode == CheckMode.REAL_RUN:
                try:
                    self.nmutil.connection_update(con_cur, con_new)
                except MyError as e:
                    self.log_error(idx, "updating connection failed: %s" % (e))
        else:
            self.log_info(
                idx,
                "connection %s, %s already up to date"
                % (con_cur.get_id(), con_cur.get_uuid()),
            )

        seen = set()
        if con_cur is not None:
            seen.add(con_cur)

        while True:
            connections = self.nmutil.connection_list(
                name=connection["name"],
                black_list=seen,
                black_list_uuids=[connection["nm.uuid"]],
            )
            if not connections:
                break
            c = connections[-1]
            self.log_info(
                idx, "delete duplicate connection %s, %s" % (c.get_id(), c.get_uuid())
            )
            self.connections_data_set_changed(idx)
            if self.check_mode == CheckMode.REAL_RUN:
                try:
                    self.nmutil.connection_delete(c)
                except MyError as e:
                    self.log_error(idx, "delete duplicate connection failed: %s" % (e))
            seen.add(c)

    def run_action_up(self, idx):
        connection = self.connections[idx]

        con = Util.first(
            self.nmutil.connection_list(
                name=connection["name"], uuid=connection["nm.uuid"]
            )
        )
        if not con:
            if self.check_mode == CheckMode.REAL_RUN:
                self.log_error(
                    idx,
                    "up connection %s, %s failed: no connection"
                    % (connection["name"], connection["nm.uuid"]),
                )
            else:
                self.log_info(
                    idx,
                    "up connection %s, %s"
                    % (connection["name"], connection["nm.uuid"]),
                )
            return

        is_active = self.nmutil.connection_is_active(con)
        is_modified = self.connection_modified_earlier(idx)
        force_state_change = self.connection_force_state_change(connection)

        if is_active and not force_state_change and not is_modified:
            self.log_info(
                idx,
                "up connection %s, %s skipped because already active"
                % (con.get_id(), con.get_uuid()),
            )
            return

        self.log_info(
            idx,
            "up connection %s, %s (%s)"
            % (
                con.get_id(),
                con.get_uuid(),
                "not-active"
                if not is_active
                else "is-modified"
                if is_modified
                else "force-state-change",
            ),
        )
        self.connections_data_set_changed(idx)
        if self.check_mode == CheckMode.REAL_RUN:
            if self._try_reapply(idx, con):
                return

            try:
                ac = self.nmutil.connection_activate(con)
            except MyError as e:
                self.log_error(idx, "up connection failed: %s" % (e))

            wait_time = connection["wait"]
            if wait_time is None:
                wait_time = DEFAULT_ACTIVATION_TIMEOUT

            try:
                self.nmutil.connection_activate_wait(ac, wait_time)
            except MyError as e:
                self.log_error(idx, "up connection failed while waiting: %s" % (e))

    def _try_reapply(self, idx, con):
        """ Try to reapply a connection

        If there is exactly one active connection with the same UUID activated
        on exactly one device, ask the device to reapply the connection.

        :returns: `True`, when the connection was reapplied, `False` otherwise
        :rtype: bool
        """
        NM = Util.NM()

        acons = list(self.nmutil.active_connection_list(connections=[con]))
        if len(acons) != 1:
            return False

        active_connection = acons[0]
        if active_connection.get_state() == NM.ActiveConnectionState.ACTIVATED:
            devices = active_connection.get_devices()
            if len(devices) == 1:
                try:
                    self.nmutil.reapply(devices[0])
                    self.log_info(idx, "connection reapplied")
                    return True
                except MyError as error:
                    self.log_info(idx, "connection reapply failed: %s" % (error))
        return False

    def run_action_down(self, idx):
        connection = self.connections[idx]

        cons = self.nmutil.connection_list(name=connection["name"])
        changed = False
        if cons:
            seen = set()
            while True:
                ac = Util.first(
                    self.nmutil.active_connection_list(
                        connections=cons, black_list=seen
                    )
                )
                if ac is None:
                    break
                seen.add(ac)
                self.log_info(
                    idx, "down connection %s: %s" % (connection["name"], ac.get_path())
                )
                changed = True
                self.connections_data_set_changed(idx)
                if self.check_mode == CheckMode.REAL_RUN:
                    try:
                        self.nmutil.active_connection_deactivate(ac)
                    except MyError as e:
                        self.log_error(idx, "down connection failed: %s" % (e))

                    wait_time = connection["wait"]
                    if wait_time is None:
                        wait_time = 10

                    try:
                        self.nmutil.active_connection_deactivate_wait(ac, wait_time)
                    except MyError as e:
                        self.log_error(
                            idx, "down connection failed while waiting: %s" % (e)
                        )

                cons = self.nmutil.connection_list(name=connection["name"])
        if not changed:
            self.log_error(
                idx,
                "down connection %s failed: connection not found"
                % (connection["name"]),
            )


###############################################################################


class Cmd_initscripts(Cmd):
    def __init__(self, **kwargs):
        Cmd.__init__(self, **kwargs)
        self.validate_one_type = (
            ArgValidator_ListConnections.VALIDATE_ONE_MODE_INITSCRIPTS
        )

    def run_prepare(self):
        Cmd.run_prepare(self)
        for idx, connection in enumerate(self.connections):
            if connection.get("type") in ["macvlan"]:
                self.log_fatal(
                    idx,
                    "unsupported type %s for initscripts provider"
                    % (connection["type"]),
                )

    def check_name(self, idx, name=None):
        if name is None:
            name = self.connections[idx]["name"]
        try:
            f = IfcfgUtil.ifcfg_path(name)
        except MyError:
            self.log_error(idx, "invalid name %s for connection" % (name))
            return None
        return f

    def run_action_absent(self, idx):
        n = self.connections[idx]["name"]
        name = n
        if not name:
            names = []
            black_list_names = ArgUtil.connection_get_non_absent_names(self.connections)
            for f in os.listdir("/etc/sysconfig/network-scripts"):
                if not f.startswith("ifcfg-"):
                    continue
                name = f[6:]
                if name in black_list_names:
                    continue
                if name == "lo":
                    continue
                names.append(name)
        else:
            if not self.check_name(idx):
                return
            names = [name]

        changed = False
        for name in names:
            for path in IfcfgUtil.ifcfg_paths(name):
                if not os.path.isfile(path):
                    continue
                changed = True
                self.log_info(idx, "delete ifcfg-rh file '%s'" % (path))
                self.connections_data_set_changed(idx)
                if self.check_mode == CheckMode.REAL_RUN:
                    try:
                        os.unlink(path)
                    except Exception as e:
                        self.log_error(
                            idx, "delete ifcfg-rh file '%s' failed: %s" % (path, e)
                        )

        if not changed:
            self.log_info(
                idx,
                "delete ifcfg-rh files for %s (no files present)"
                % ("'" + n + "'" if n else "*"),
            )

    def run_action_present(self, idx):
        if not self.check_name(idx):
            return

        connection = self.connections[idx]
        name = connection["name"]

        old_content = IfcfgUtil.content_from_file(name)

        if not connection.get("type"):
            # if the type is not specified, just check that the connection was
            # found
            if not old_content.get("ifcfg"):
                self.log_error(
                    idx, "Connection not found on system and 'type' not present"
                )
            return

        ifcfg_all = IfcfgUtil.ifcfg_create(
            self.connections, idx, lambda msg: self.log_warn(idx, msg), old_content
        )

        new_content = IfcfgUtil.content_from_dict(
            ifcfg_all, header=self.run_env.ifcfg_header
        )

        if old_content == new_content:
            self.log_info(idx, "ifcfg-rh profile '%s' already up to date" % (name))
            return

        op = "add" if (old_content["ifcfg"] is None) else "update"

        self.log_info(idx, "%s ifcfg-rh profile '%s'" % (op, name))

        self.connections_data_set_changed(idx)
        if self.check_mode == CheckMode.REAL_RUN:
            try:
                IfcfgUtil.content_to_file(name, new_content)
            except MyError as e:
                self.log_error(
                    idx, "%s ifcfg-rh profile '%s' failed: %s" % (op, name, e)
                )

    def _run_action_updown(self, idx, do_up):
        if not self.check_name(idx):
            return

        connection = self.connections[idx]
        name = connection["name"]

        if connection["wait"] is not None:
            # initscripts don't support wait, they always block until the ifup/ifdown
            # command completes. Silently ignore the argument.
            pass

        path = IfcfgUtil.ifcfg_path(name)
        if not os.path.isfile(path):
            if self.check_mode == CheckMode.REAL_RUN:
                self.log_error(idx, "ifcfg file '%s' does not exist" % (path))
            else:
                self.log_info(
                    idx, "ifcfg file '%s' does not exist in check mode" % (path)
                )
            return

        is_active = IfcfgUtil.connection_seems_active(name)
        is_modified = self.connection_modified_earlier(idx)
        force_state_change = self.connection_force_state_change(connection)

        if do_up:
            if is_active is True and not force_state_change and not is_modified:
                self.log_info(
                    idx, "up connection %s skipped because already active" % (name)
                )
                return

            self.log_info(
                idx,
                "up connection %s (%s)"
                % (
                    name,
                    "not-active"
                    if is_active is not True
                    else "is-modified"
                    if is_modified
                    else "force-state-change",
                ),
            )
            cmd = "ifup"
        else:
            if is_active is False and not force_state_change:
                self.log_info(
                    idx, "down connection %s skipped because not active" % (name)
                )
                return

            self.log_info(
                idx,
                "up connection %s (%s)"
                % (name, "active" if is_active is not False else "force-state-change"),
            )
            cmd = "ifdown"

        self.connections_data_set_changed(idx)
        if self.check_mode == CheckMode.REAL_RUN:
            rc, out, err = self.run_env.run_command([cmd, name])
            self.log_info(
                idx,
                "call '%s %s': rc=%d, out='%s', err='%s'" % (cmd, name, rc, out, err),
            )
            if rc != 0:
                self.log_error(
                    idx, "call '%s %s' failed with exit status %d" % (cmd, name, rc)
                )

    def run_action_up(self, idx):
        self._run_action_updown(idx, True)

    def run_action_down(self, idx):
        self._run_action_updown(idx, False)


###############################################################################


def main():
    connections = None
    cmd = None
    run_env_ansible = RunEnvironmentAnsible()
    try:
        params = run_env_ansible.module.params
        cmd = Cmd.create(
            params["provider"],
            run_env=run_env_ansible,
            connections_unvalidated=params["connections"],
            connection_validator=ArgValidator_ListConnections(),
            is_check_mode=run_env_ansible.module.check_mode,
            ignore_errors=params["ignore_errors"],
            force_state_change=params["force_state_change"],
            debug_flags=params["__debug_flags"],
        )
        connections = cmd.connections
        run_env_ansible.on_failure = cmd.on_failure
        cmd.run()
    except Exception as e:
        run_env_ansible.fail_json(
            connections,
            "fatal error: %s" % (e),
            changed=(cmd is not None and cmd.is_changed_modified_system),
            warn_traceback=not isinstance(e, MyError),
        )
    run_env_ansible.exit_json(
        connections, changed=(cmd is not None and cmd.is_changed_modified_system)
    )


if __name__ == "__main__":
    main()
