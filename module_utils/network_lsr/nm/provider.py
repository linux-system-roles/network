# SPDX-License-Identifier: BSD-3-Clause

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import logging

# pylint: disable=import-error
from .active_connection import deactivate_active_connection
from .client import get_client
from .connection import delete_remote_connection
from .connection import volatilize_remote_connection

# pylint: enable=import-error


class NetworkManagerProvider:
    def deactivate_connection(self, connection_name, timeout, check_mode):
        """
        Return True if changed.
        """
        nm_client = get_client()
        changed = False
        for nm_ac in nm_client.get_active_connections():
            nm_profile = nm_ac.get_connection()
            if nm_profile and nm_profile.get_id() == connection_name:
                changed |= deactivate_active_connection(nm_ac, timeout, check_mode)
        if not changed:
            logging.info("No active connection for %s", connection_name)

        return changed

    def volatilize_connection_by_uuid(self, uuid, timeout, check_mode):
        """
        Mark NM.RemoteConnection as volatile(delete on deactivation) via Update2,
        if not supported, delete the profile.

        Return True if changed.
        """
        nm_client = get_client()
        changed = False
        for nm_profile in nm_client.get_connections():
            if nm_profile and nm_profile.get_uuid() == uuid:
                if hasattr(nm_profile, "update2"):
                    changed |= volatilize_remote_connection(
                        nm_profile, timeout, check_mode
                    )
                else:
                    changed |= delete_remote_connection(nm_profile, timeout, check_mode)
        if not changed:
            logging.info("No connection with UUID %s to volatilize", uuid)

        return changed

    def get_connections(self):
        nm_client = get_client()
        return nm_client.get_connections()
