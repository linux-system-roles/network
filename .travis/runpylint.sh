#!/bin/bash
# SPDX-License-Identifier: MIT

# A shell wrapper around custom_pylint.py. The purpose of this wrapper is to
# set environment variables defined in config.sh before custom_pylint.py
# invocation, so user can control what should be pylinted via config.sh.

# Note: Prior this change, RUN_PYLINT_* environment variables set in config.sh
#       take effect only when running inside Travis (because of runtox script
#       which set them by including config.sh). Now, they take effect also when
#       running tox locally.

# The given command line arguments are passed to custom_pylint.py.

# Environment variables:
#
#   RUN_PYLINT_SETUP_MODULE_UTILS
#     if set to an arbitrary non-empty value, the environment will be
#     configured so that linting of the module_utils/ code will be run
#     correctly

set -e

SCRIPTDIR=$(readlink -f "$(dirname "$0")")

. "${SCRIPTDIR}/config.sh"

if [[ "${RUN_PYLINT_SETUP_MODULE_UTILS}" ]]; then
  . "${SCRIPTDIR}/utils.sh"
  lsr_setup_module_utils
fi

export RUN_PYLINT_DISABLED
export RUN_PYLINT_EXCLUDE
export RUN_PYLINT_INCLUDE
set -x
python "${SCRIPTDIR}/custom_pylint.py" "$@"
