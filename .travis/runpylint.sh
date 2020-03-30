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

set -e

ME=$(basename $0)
SCRIPTDIR=$(readlink -f $(dirname $0))

. ${SCRIPTDIR}/utils.sh
. ${SCRIPTDIR}/config.sh

set -x
python ${SCRIPTDIR}/custom_pylint.py "$@"
