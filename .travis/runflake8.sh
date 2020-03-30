#!/bin/bash
# SPDX-License-Identifier: MIT

# A shell wrapper around flake8. The purpose of this wrapper is to get to user
# an opportunity to disable running flake8 via config.sh.

# The given command line arguments are passed to flake8.

# Environment variables:
#
#   RUN_FLAKE8_DISABLED
#     if set to an arbitrary non-empty value, flake8 will be not executed
#   RUN_FLAKE8_IGNORE
#     list of issues to ignore - see flake8 docs

set -e

ME=$(basename $0)
SCRIPTDIR=$(readlink -f $(dirname $0))

. ${SCRIPTDIR}/utils.sh
. ${SCRIPTDIR}/config.sh

if [[ "${RUN_FLAKE8_DISABLED}" ]]; then
  lsr_info "${ME}: flake8 is disabled. Skipping."
  exit 0
fi

set -x
python -m flake8 \
  ${RUN_FLAKE8_IGNORE:+--ignore} ${RUN_FLAKE8_IGNORE:-} \
  "$@"
