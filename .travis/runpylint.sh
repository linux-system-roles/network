#!/bin/bash
# SPDX-License-Identifier: MIT

# A shell wrapper around custom_pylint.py. The purpose of this wrapper is to
# set environment variables defined in config.sh before custom_pylint.py
# invocation, so user can control what should be pylinted via config.sh.

# Note: Prior this change, RUN_PYLINT_* environment variables set in config.sh
#       take effect only when running inside Travis (because of runtox script
#       which set them by including config.sh). Now, they take effect also when
#       running tox locally.

# First argument to the script is a path to environment python, the rest of
# arguments are passed to custom_pylint.py.

set -e

ME=$(basename $0)
SCRIPTDIR=$(readlink -f $(dirname $0))

. ${SCRIPTDIR}/config.sh

# Sanitize path in case if running within tox (see
# https://github.com/tox-dev/tox/issues/1463):
ENVPYTHON=$(readlink -f $1)
shift

set -x
${ENVPYTHON} ${SCRIPTDIR}/custom_pylint.py "$@"
