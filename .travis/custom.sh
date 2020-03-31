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

. ${SCRIPTDIR}/utils.sh
. ${SCRIPTDIR}/config.sh

# Write your custom commands here that should be run when `tox -e custom`:
if [[ -z "${TRAVIS}" ]] || lsr_check_python_version python -eq '3.6'; then
  (set -x; cd ${TOPDIR}/tests; ${ENVPYTHON} ./ensure_non_running_provider.py)
fi
