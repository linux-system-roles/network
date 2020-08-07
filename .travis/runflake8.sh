#!/bin/bash
# SPDX-License-Identifier: MIT

# A shell wrapper around flake8. The purpose of this wrapper is to get to user
# an opportunity to disable running flake8 via config.sh.

# The given command line arguments are passed to flake8.

# Environment variables:
#
#   RUN_FLAKE8_DISABLED
#     if set to an arbitrary non-empty value, flake8 will be not executed
#
#   RUN_FLAKE8_EXTRA_ARGS
#     any extra command line arguments to provide e.g. --ignore=some,errs

set -e

ME=$(basename "$0")
SCRIPTDIR=$(readlink -f "$(dirname "$0")")

. "${SCRIPTDIR}/utils.sh"
. "${SCRIPTDIR}/config.sh"

if [[ "${RUN_FLAKE8_DISABLED}" ]]; then
  lsr_info "${ME}: flake8 is disabled. Skipping."
  exit 0
fi

set -x
# https://github.com/koalaman/shellcheck/wiki/SC2086
# shellcheck disable=SC2086
python -m flake8 ${RUN_FLAKE8_EXTRA_ARGS:-} "$@"
