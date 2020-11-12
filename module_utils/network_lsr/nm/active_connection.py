# SPDX-License-Identifier: BSD-3-Clause

# Handle NM.ActiveConnection

import logging

# Relative import is not support by ansible 2.8 yet
# pylint: disable=import-error, no-name-in-module
from ansible.module_utils.network_lsr.nm.client import GLib  # noqa:E501
from ansible.module_utils.network_lsr.nm.client import NM  # noqa:E501
from ansible.module_utils.network_lsr.nm.client import get_mainloop  # noqa:E501
from ansible.module_utils.network_lsr.nm.client import get_client  # noqa:E501
from ansible.module_utils.network_lsr.nm.error import LsrNetworkNmError  # noqa:E501

# pylint: enable=import-error, no-name-in-module


NM_AC_STATE_CHANGED_SIGNAL = "state-changed"


def deactivate_active_connection(nm_ac, timeout, check_mode):
    if not nm_ac or nm_ac.props.state == NM.ActiveConnectionState.DEACTIVATED:
        logging.info("Connection is not active, no need to deactivate")
        return False
    if not check_mode:
        main_loop = get_mainloop(timeout)
        logging.debug(
            "Deactivating {id} with timeout {timeout}".format(
                id=nm_ac.get_id(), timeout=timeout
            )
        )
        user_data = main_loop
        handler_id = nm_ac.connect(
            NM_AC_STATE_CHANGED_SIGNAL, _nm_ac_state_change_callback, user_data
        )
        logging.debug(
            "Registered {signal} on NM.ActiveConnection {id}".format(
                signal=NM_AC_STATE_CHANGED_SIGNAL, id=nm_ac.get_id()
            )
        )
        if nm_ac.props.state != NM.ActiveConnectionState.DEACTIVATING:
            nm_client = get_client()
            user_data = (main_loop, nm_ac, nm_ac.get_id(), handler_id)
            nm_client.deactivate_connection_async(
                nm_ac,
                main_loop.cancellable,
                _nm_ac_deactivate_call_back,
                user_data,
            )
            logging.debug("Deactivating NM.ActiveConnection {0}".format(nm_ac.get_id()))
        main_loop.run()
    return True


def _nm_ac_state_change_callback(nm_ac, state, reason, user_data):
    main_loop = user_data
    if main_loop.is_cancelled:
        return
    logging.debug(
        "Got NM.ActiveConnection state change: {id}: {state} {reason}".format(
            id=nm_ac.get_id(), state=state, reason=reason
        )
    )
    if nm_ac.props.state == NM.ActiveConnectionState.DEACTIVATED:
        logging.debug("NM.ActiveConnection {0} is deactivated".format(nm_ac.get_id()))
        main_loop.quit()


def _nm_ac_deactivate_call_back(nm_client, result, user_data):
    main_loop, nm_ac, nm_ac_id, handler_id = user_data
    logging.debug("NM.ActiveConnection deactivating callback")
    if main_loop.is_cancelled:
        if nm_ac:
            nm_ac.handler_disconnect(handler_id)
        return

    try:
        success = nm_client.deactivate_connection_finish(result)
    except GLib.Error as e:
        if e.matches(NM.ManagerError.quark(), NM.ManagerError.CONNECTIONNOTACTIVE):
            logging.info(
                "Connection is not active on {0}, no need to deactivate".format(
                    nm_ac_id
                )
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
    main_loop.fail(LsrNetworkNmError(msg))
