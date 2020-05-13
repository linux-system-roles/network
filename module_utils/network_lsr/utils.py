#!/usr/bin/python3 -tt
# SPDX-License-Identifier: BSD-3-Clause
# vim: fileencoding=utf8

import socket
import sys
import uuid

# pylint: disable=import-error, no-name-in-module
from ansible.module_utils.network_lsr import MyError


class Util:

    PY3 = sys.version_info[0] == 3

    STRING_TYPE = str if PY3 else basestring  # noqa:F821

    @staticmethod
    def first(iterable, default=None, pred=None):
        for v in iterable:
            if pred is None or pred(v):
                return v
        return default

    @staticmethod
    def path_to_glib_bytes(path):
        """
        Converts a path to a GLib.Bytes object that can be accepted by NM
        """
        return Util.GLib().Bytes.new(("file://%s\x00" % path).encode("utf-8"))

    @staticmethod
    def convert_passwd_flags_nm(secret_flags):
        """
        Converts an array of "secret flags" strings
        to an integer represantion understood by NetworkManager
        """

        flag_int = 0

        if "none" in secret_flags:
            flag_int += 0
        if "agent-owned" in secret_flags:
            flag_int += 1
        if "not-saved" in secret_flags:
            flag_int += 2
        if "not-required" in secret_flags:
            flag_int += 4

        return flag_int

    @classmethod
    def create_uuid(cls):
        return str(uuid.uuid4())

    @classmethod
    def NM(cls):
        n = getattr(cls, "_NM", None)
        if n is None:
            # Installing pygobject in a tox virtualenv does not work out of the
            # box
            # pylint: disable=import-error
            import gi

            gi.require_version("NM", "1.0")
            from gi.repository import NM, GLib, Gio, GObject

            cls._NM = NM
            cls._GLib = GLib
            cls._Gio = Gio
            cls._GObject = GObject
            n = NM
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
    def GObject(cls):
        cls.NM()
        return cls._GObject

    @classmethod
    def Timestamp(cls):
        return cls.GLib().get_monotonic_time()

    @classmethod
    def GMainLoop(cls):
        gmainloop = getattr(cls, "_GMainLoop", None)
        if gmainloop is None:
            gmainloop = cls.GLib().MainLoop()
            cls._GMainLoop = gmainloop
        return gmainloop

    @classmethod
    def GMainLoop_run(cls, timeout=None):
        if timeout is None:
            cls.GMainLoop().run()
            return True

        GLib = cls.GLib()
        timeout_reached = []
        loop = cls.GMainLoop()

        def _timeout_cb(unused):
            timeout_reached.append(1)
            loop.quit()
            return False

        timeout_id = GLib.timeout_add(int(timeout * 1000), _timeout_cb, None)
        loop.run()
        if not timeout_reached:
            GLib.source_remove(timeout_id)
        return not timeout_reached

    @classmethod
    def GMainLoop_iterate(cls, may_block=False):
        return cls.GMainLoop().get_context().iteration(may_block)

    @classmethod
    def GMainLoop_iterate_all(cls):
        c = 0
        while cls.GMainLoop_iterate():
            c += 1
        return c

    @classmethod
    def call_async_method(cls, object_, action, args, mainloop_timeout=10):
        """ Asynchronously call a NetworkManager method """
        cancellable = cls.create_cancellable()
        async_action = action + "_async"
        # NM does not use a uniform naming for the async methods,
        # for checkpoints it is:
        # NMClient.checkpoint_create() and NMClient.checkpoint_create_finish(),
        # but for reapply it is:
        # NMDevice.reapply_async() and NMDevice.reapply_finish()
        # NMDevice.reapply() is a synchronous version
        # Therefore check if there is a method if an `async` suffix and use the
        # one without the suffix otherwise
        if not hasattr(object_, async_action):
            async_action = action
        finish = action + "_finish"
        user_data = {}

        fullargs = []
        fullargs += args
        fullargs += (cancellable, cls.create_callback(finish), user_data)

        getattr(object_, async_action)(*fullargs)

        if not cls.GMainLoop_run(mainloop_timeout):
            cancellable.cancel()
            raise MyError("failure to call %s.%s(): timeout" % object_, async_action)

        success = user_data.get("success", None)
        if success is not None:
            return success

        raise MyError(
            "failure to %s checkpoint: %s: %r"
            % (action, user_data.get("error", "unknown error"), user_data)
        )

    @classmethod
    def create_cancellable(cls):
        return cls.Gio().Cancellable.new()

    @classmethod
    def create_callback(cls, finish_method):
        """
        Create a callback that will return the result of the finish method and
        quit the GMainLoop

        :param finish_method str: Name of the finish method to call from the
        source object in the callback
        """

        def callback(source_object, res, user_data):
            success = None
            try:
                success = getattr(source_object, finish_method)(res)
            except Exception as e:
                if cls.error_is_cancelled(e):
                    return
                user_data["error"] = str(e)
            user_data["success"] = success
            cls.GMainLoop().quit()

        return callback

    @classmethod
    def error_is_cancelled(cls, e):
        GLib = cls.GLib()
        if isinstance(e, GLib.GError):
            if (
                e.domain == "g-io-error-quark"
                and e.code == cls.Gio().IOErrorEnum.CANCELLED
            ):
                return True
        return False

    @staticmethod
    def ifname_valid(ifname):
        # see dev_valid_name() in kernel's net/core/dev.c
        if not ifname:
            return False
        if ifname in [".", ".."]:
            return False
        if len(ifname) >= 16:
            return False
        if any([c == "/" or c == ":" or c.isspace() for c in ifname]):
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
                if c != ":":
                    raise MyError("not a valid MAC address: '%s'" % (mac_str))
                i = 0
                continue
            try:
                if i == 0:
                    n = int(c, 16) * 16
                    i = 1
                else:
                    assert i == 1
                    n = n + int(c, 16)
                    i = 2
                    b.append(n)
            except Exception:
                raise MyError("not a valid MAC address: '%s'" % (mac_str))
        if i == 1:
            raise MyError("not a valid MAC address: '%s'" % (mac_str))
        if force_len is not None:
            if force_len != len(b):
                raise MyError(
                    "not a valid MAC address of length %s: '%s'" % (force_len, mac_str)
                )
        return b

    @staticmethod
    def mac_ntoa(mac):
        if mac is None:
            return None
        # bytearray() is needed for python2 compatibility
        return ":".join(["%02x" % c for c in bytearray(mac)])

    @staticmethod
    def mac_norm(mac_str, force_len=None):
        return Util.mac_ntoa(Util.mac_aton(mac_str, force_len))

    @staticmethod
    def boolean(arg):
        if arg is None or isinstance(arg, bool):
            return arg
        arg0 = arg
        if isinstance(arg, Util.STRING_TYPE):
            arg = arg.lower()

        if arg in ["y", "yes", "on", "1", "true", 1, True]:
            return True
        if arg in ["n", "no", "off", "0", "false", 0, False]:
            return False

        raise MyError("value '%s' is not a boolean" % (arg0))

    @staticmethod
    def parse_ip(addr, family=None):
        if addr is None:
            return (None, None)
        if family is not None:
            Util.addr_family_check(family)
            a = socket.inet_pton(family, addr)
        else:
            a = None
            family = None
            try:
                a = socket.inet_pton(socket.AF_INET, addr)
                family = socket.AF_INET
            except Exception:
                a = socket.inet_pton(socket.AF_INET6, addr)
                family = socket.AF_INET6
        return (socket.inet_ntop(family, a), family)

    @staticmethod
    def addr_family_check(family):
        if family != socket.AF_INET and family != socket.AF_INET6:
            raise MyError("invalid address family %s" % (family))

    @staticmethod
    def addr_family_to_v(family):
        if family is None:
            return ""
        if family == socket.AF_INET:
            return "v4"
        if family == socket.AF_INET6:
            return "v6"
        raise MyError("invalid address family '%s'" % (family))

    @staticmethod
    def addr_family_default_prefix(family):
        Util.addr_family_check(family)
        if family == socket.AF_INET:
            return 24
        else:
            return 64

    @staticmethod
    def addr_family_valid_prefix(family, prefix):
        Util.addr_family_check(family)
        if family == socket.AF_INET:
            m = 32
        else:
            m = 128
        return prefix >= 0 and prefix <= m

    @staticmethod
    def parse_address(address, family=None):
        try:
            parts = address.split()
            addr_parts = parts[0].split("/")
            if len(addr_parts) != 2:
                raise MyError("expect two addr-parts: ADDR/PLEN")
            a, family = Util.parse_ip(addr_parts[0], family)
            prefix = int(addr_parts[1])
            if not Util.addr_family_valid_prefix(family, prefix):
                raise MyError("invalid prefix %s" % (prefix))
            if len(parts) > 1:
                raise MyError("too many parts")
            return {"address": a, "family": family, "prefix": prefix}
        except Exception:
            raise MyError("invalid address '%s'" % (address))
