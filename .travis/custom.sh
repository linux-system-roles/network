#!/bin/bash
# SPDX-License-Identifier: MIT

# This script is executed with two arguments passed to it:
#
#   $1 - path to environment python (python used inside virtual environment
#        created by tox)
#   $2 - path to system python (python 3.x installed on the system)

set -e

ME=$(basename $0)
SCRIPTDIR=$(readlink -f $(dirname $0))
TOPDIR=$(readlink -f ${SCRIPTDIR}/..)

# Include library and config:
. ${SCRIPTDIR}/utils.sh
. ${SCRIPTDIR}/config.sh

# Sanitize arguments (see https://github.com/tox-dev/tox/issues/1463):
ENVPYTHON=$(readlink -f $1)
SYSPYTHON=$(readlink -f $2)
shift 2

# Write your custom commands here that should be run when `tox -e custom`:
if [[ -z "${TRAVIS}" ]] || lsr_check_python_version ${ENVPYTHON} -eq '3.6'; then
  (set -x; cd ${TOPDIR}/tests; ${ENVPYTHON} ./ensure_non_running_provider.py)
fi
