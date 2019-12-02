#!/bin/bash
# SPDX-License-Identifier: MIT

# Run flake8. The first script argument is a path to Python interpreter, the
# rest of arguments are passed to flake8.

# Environment variables:
#
#   RUN_FLAKE8_DISABLED
#     if set to an arbitrary non-empty value, flake8 will be not executed

set -e

ME=$(basename $0)
SCRIPTDIR=$(readlink -f $(dirname $0))

. ${SCRIPTDIR}/utils.sh
. ${SCRIPTDIR}/config.sh

if [[ "${RUN_FLAKE8_DISABLED}" ]]; then
  lsr_info "${ME}: flake8 is disabled. Skipping."
  exit 0
fi

# Sanitize path in case if running within tox (see
# https://github.com/tox-dev/tox/issues/1463):
ENVPYTHON=$(readlink -f $1)
shift

set -x
${ENVPYTHON} -m flake8 "$@"
