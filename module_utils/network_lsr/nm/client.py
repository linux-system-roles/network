# SPDX-License-Identifier: BSD-3-Clause

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import logging

# Relative import is not support by ansible 2.8 yet
# pylint: disable=import-error, no-name-in-module
from ansible.module_utils.network_lsr.nm import error  # noqa:E501

import gi

try:
    gi.require_version("NM", "1.0")

    # It is required to state the NM version before importing it
    # But this break the flake8 rule: https://www.flake8rules.com/rules/E402.html
    # Use NOQA: E402 to suppress it.
    from gi.repository import NM  # NOQA: E402
    from gi.repository import GLib  # NOQA: E402
    from gi.repository import Gio  # NOQA: E402

    # pylint: enable=import-error, no-name-in-module

    NM
    GLib
    Gio
except ValueError:
    # This is to workaround a bug in ansible 2.9 which causes
    # this code to be executed on the control node, where NM
    # is not guaranteed to exist. On the other hand, it is
    # ensured on the managed nodes as NM package is installed
    # in the network role. Therefore, this exception handling
    # does not affect the network installation and configuration
    # on the managed nodes.
    pass


def get_client():
    return NM.Client.new()


class _NmMainLoop(object):
    def __init__(self, timeout):
        self._mainloop = GLib.MainLoop()
        self._cancellable = Gio.Cancellable.new()
        self._timeout = timeout
        self._timeout_id = None

    def run(self):
        logging.debug("NM mainloop running")
        user_data = None
        self._timeout_id = GLib.timeout_add(
            int(self._timeout * 1000),
            self._timeout_call_back,
            user_data,
        )
        logging.debug("Added timeout checker")
        self._mainloop.run()

    def _timeout_call_back(self, _user_data):
        logging.error("Timeout")
        self.fail(error.LsrNetworkNmError("Timeout"))

    @property
    def cancellable(self):
        return self._cancellable

    @property
    def is_cancelled(self):
        if self._cancellable:
            return self._cancellable.is_cancelled()
        return True

    def _clean_up(self):
        logging.debug("NM mainloop cleaning up")
        if self._timeout_id:
            logging.debug("Removing timeout checker")
            GLib.source_remove(self._timeout_id)
            self._timeout_id = None
        if self._cancellable:
            logging.debug("Canceling all pending tasks")
            self._cancellable.cancel()
            self._cancellable = None
        self._mainloop = None

    def quit(self):
        logging.debug("NM mainloop quiting")
        self._mainloop.quit()
        self._clean_up()

    def fail(self, exception):
        self.quit()
        raise exception


def get_mainloop(timeout):
    return _NmMainLoop(timeout)
