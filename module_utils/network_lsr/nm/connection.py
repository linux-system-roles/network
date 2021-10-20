# SPDX-License-Identifier: BSD-3-Clause

# Handle NM.RemoteConnection

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import logging

from .client import NM
from .client import get_mainloop
from .error import LsrNetworkNmError


def delete_remote_connection(nm_profile, timeout, check_mode):
    if not nm_profile:
        logging.info("NULL NM.RemoteConnection, no need to delete")
        return False

    if not check_mode:
        main_loop = get_mainloop(timeout)
        user_data = main_loop
        nm_profile.delete_async(
            main_loop.cancellable,
            _nm_profile_delete_call_back,
            user_data,
        )
        logging.debug(
            "Deleting profile %s/%s with timeout %s",
            nm_profile.get_id(),
            nm_profile.get_uuid(),
            timeout,
        )
        main_loop.run()
    return True


def _nm_profile_delete_call_back(nm_profile, result, user_data):
    main_loop = user_data
    if main_loop.is_cancelled:
        return

    try:
        success = nm_profile.delete_finish(result)
    except Exception as e:
        main_loop.fail(
            LsrNetworkNmError(
                "Connection deletion aborted on {id}/{uuid}: error={error}".format(
                    id=nm_profile.get_id(), uuid=nm_profile.get_uuid(), error=e
                )
            )
        )
    if success:
        main_loop.quit()
    else:
        main_loop.fail(
            LsrNetworkNmError(
                "Connection deletion aborted on {id}/{uuid}: error=unknown".format(
                    id=nm_profile.get_id(), uuid=nm_profile.get_uuid()
                )
            )
        )


def volatilize_remote_connection(nm_profile, timeout, check_mode):
    if not nm_profile:
        logging.info("NULL NM.RemoteConnection, no need to volatilize")
        return False
    if not check_mode:
        main_loop = get_mainloop(timeout)
        user_data = main_loop
        nm_profile.update2(
            None,  # settings
            NM.SettingsUpdate2Flags.IN_MEMORY_ONLY | NM.SettingsUpdate2Flags.VOLATILE,
            None,  # args
            main_loop.cancellable,
            _nm_profile_volatile_update2_call_back,
            user_data,
        )
        logging.debug(
            "Volatilizing profile %s/%s with timeout %s",
            nm_profile.get_id(),
            nm_profile.get_uuid(),
            timeout,
        )
        main_loop.run()
    return True


def _nm_profile_volatile_update2_call_back(nm_profile, result, user_data):
    main_loop = user_data
    if main_loop.is_cancelled:
        return

    try:
        success = nm_profile.update2_finish(result)
    except Exception as e:
        main_loop.fail(
            LsrNetworkNmError(
                "Connection volatilize aborted on {id}/{uuid}: error={error}".format(
                    id=nm_profile.get_id(), uuid=nm_profile.get_uuid(), error=e
                )
            )
        )
    if success:
        main_loop.quit()
    else:
        main_loop.fail(
            LsrNetworkNmError(
                "Connection volatilize aborted on {id}/{uuid}: error=unknown".format(
                    id=nm_profile.get_id(), uuid=nm_profile.get_uuid()
                )
            )
        )
