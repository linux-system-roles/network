# SPDX-License-Identifier: BSD-3-Clause

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import logging

# Relative import is not support by ansible 2.8 yet
# pylint: disable=import-error, no-name-in-module
from ansible.module_utils.network_lsr.nm import active_connection  # noqa:E501
from ansible.module_utils.network_lsr.nm import client  # noqa:E501
from ansible.module_utils.network_lsr.nm import connection  # noqa:E501

# pylint: enable=import-error, no-name-in-module


class NetworkManagerProvider:
    def deactivate_connection(self, connection_name, timeout, check_mode):
        """
        Return True if changed.
        """
        nm_client = client.get_client()
        changed = False
        for nm_ac in nm_client.get_active_connections():
            nm_profile = nm_ac.get_connection()
            if nm_profile and nm_profile.get_id() == connection_name:
                changed |= active_connection.deactivate_active_connection(
                    nm_ac, timeout, check_mode
                )
        if not changed:
            logging.info("No active connection for %s", connection_name)

        return changed

    def volatilize_connection_by_uuid(self, uuid, timeout, check_mode):
        """
        Mark NM.RemoteConnection as volatile(delete on deactivation) via Update2,
        if not supported, delete the profile.

        Return True if changed.
        """
        nm_client = client.get_client()
        changed = False
        for nm_profile in nm_client.get_connections():
            if nm_profile and nm_profile.get_uuid() == uuid:
                if hasattr(nm_profile, "update2"):
                    changed |= connection.volatilize_remote_connection(
                        nm_profile, timeout, check_mode
                    )
                else:
                    changed |= connection.delete_remote_connection(
                        nm_profile, timeout, check_mode
                    )
        if not changed:
            logging.info("No connection with UUID %s to volatilize", uuid)

        return changed

    def get_connections(self):
        nm_client = client.get_client()
        return nm_client.get_connections()

    def get_client_version(self):
        nm_client = client.get_client()
        return nm_client.get_version()

    def reload_configuration(self):
        timeout = 10
        nm_client = client.get_client()
        main_loop = client.get_mainloop(timeout)
        logging.debug("Reloading configuration with timeout %s", timeout)
        nm_client.reload_connections_async(
            main_loop.cancellable, _reload_config_callback, main_loop
        )
        main_loop.run()


def _reload_config_callback(nm_client, result, main_loop):
    try:
        success = nm_client.reload_connections_finish(result)
    except client.GLib.Error as e:
        logging.warn("Failed to reload configuration: %s", e)
        main_loop.quit()
        return
    if success:
        logging.debug("Reloading configuration finished")
    else:
        logging.warn("Failed to reload configuration, no error message")
    main_loop.quit()
