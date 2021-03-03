# SPDX-License-Identifier: BSD-3-Clause

# Handle NM.ActiveConnection

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import logging

# Relative import is not support by ansible 2.8 yet
# pylint: disable=import-error, no-name-in-module
from ansible.module_utils.network_lsr.nm import client  # noqa:E501
from ansible.module_utils.network_lsr.nm import error  # noqa:E501

# pylint: enable=import-error, no-name-in-module


NM_AC_STATE_CHANGED_SIGNAL = "state-changed"


def deactivate_active_connection(nm_ac, timeout, check_mode):
    if not nm_ac or nm_ac.props.state == client.NM.ActiveConnectionState.DEACTIVATED:
        logging.info("Connection is not active, no need to deactivate")
        return False
    if not check_mode:
        main_loop = client.get_mainloop(timeout)
        logging.debug("Deactivating %s with timeout %s", nm_ac.get_id(), timeout)
        user_data = main_loop
        handler_id = nm_ac.connect(
            NM_AC_STATE_CHANGED_SIGNAL, _nm_ac_state_change_callback, user_data
        )
        logging.debug(
            "Registered %s on client.NM.ActiveConnection %s",
            NM_AC_STATE_CHANGED_SIGNAL,
            nm_ac.get_id(),
        )
        if nm_ac.props.state != client.NM.ActiveConnectionState.DEACTIVATING:
            nm_client = client.get_client()
            user_data = (main_loop, nm_ac, nm_ac.get_id(), handler_id)
            nm_client.deactivate_connection_async(
                nm_ac,
                main_loop.cancellable,
                _nm_ac_deactivate_call_back,
                user_data,
            )
            logging.debug("Deactivating client.NM.ActiveConnection %s", nm_ac.get_id())
        main_loop.run()
    return True


def _nm_ac_state_change_callback(nm_ac, state, reason, user_data):
    main_loop = user_data
    if main_loop.is_cancelled:
        return
    logging.debug(
        "Got client.NM.ActiveConnection state change: %s: %s %s",
        nm_ac.get_id(),
        state,
        reason,
    )
    if nm_ac.props.state == client.NM.ActiveConnectionState.DEACTIVATED:
        logging.debug("client.NM.ActiveConnection %s is deactivated", nm_ac.get_id())
        main_loop.quit()


def _nm_ac_deactivate_call_back(nm_client, result, user_data):
    main_loop, nm_ac, nm_ac_id, handler_id = user_data
    logging.debug("client.NM.ActiveConnection deactivating callback")
    if main_loop.is_cancelled:
        if nm_ac:
            nm_ac.handler_disconnect(handler_id)
        return

    try:
        success = nm_client.deactivate_connection_finish(result)
    except client.GLib.Error as e:
        if e.matches(
            client.NM.ManagerError.quark(), client.NM.ManagerError.CONNECTIONNOTACTIVE
        ):
            logging.info(
                "Connection is not active on %s, no need to deactivate", nm_ac_id
            )
            if nm_ac:
                nm_ac.handler_disconnect(handler_id)
            main_loop.quit()
            return
        else:
            _deactivate_fail(
                main_loop,
                handler_id,
                nm_ac,
                "Failed to deactivate connection {id}, error={error}".format(
                    id=nm_ac_id, error=e
                ),
            )
            return
    except Exception as e:
        _deactivate_fail(
            main_loop,
            handler_id,
            nm_ac,
            "Failed to deactivate connection {id}, error={error}".format(
                id=nm_ac_id, error=e
            ),
        )
        return

    if not success:
        _deactivate_fail(
            main_loop,
            handler_id,
            nm_ac,
            "Failed to deactivate connection {0}, error='None "
            "returned from deactivate_connection_finish()'".format(nm_ac_id),
        )


def _deactivate_fail(main_loop, handler_id, nm_ac, msg):
    if nm_ac:
        nm_ac.handler_disconnect(handler_id)
    logging.error(msg)
    main_loop.fail(error.LsrNetworkNmError(msg))
