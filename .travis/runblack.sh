#!/bin/bash
# SPDX-License-Identifier: MIT

# Run black (the Python formatter). The first script argument is a path to
# Python interpreter, the rest of arguments are passed to black.

# Environment variables:
#
#   RUN_BLACK_INCLUDE
#     a regular expression specifying files to be included; can be overridden
#     from command line by --include;
#
#   RUN_BLACK_EXCLUDE
#     a regular expression specifying files to be excluded; can be overridden
#     from command line by --exclude;
#
#   RUN_BLACK_DISABLED
#     if set to an arbitrary non-empty value, black will be not executed

set -e

ME=$(basename $0)
SCRIPTDIR=$(readlink -f $(dirname $0))

# Include library and config.
. ${SCRIPTDIR}/utils.sh
. ${SCRIPTDIR}/config.sh

if [[ "${RUN_BLACK_DISABLED}" ]]; then
  lsr_info "${ME}: black is disabled. Skipping."
  exit 0
fi

# Sanitize path in case if running within tox (see
# https://github.com/tox-dev/tox/issues/1463):
ENVPYTHON=$(readlink -f $1)
shift

DEFAULT_INCLUDE='^[^.].*\.py$'
DEFAULT_EXCLUDE='/(\.[^.].*|tests/roles)/'

INCLUDE_ARG=""
EXCLUDE_ARG=""
OTHER_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --include)
      shift
      INCLUDE_ARG="$1"
      ;;
    --exclude)
      shift
      EXCLUDE_ARG="$1"
      ;;
    *)
      OTHER_ARGS+=( "$1" )
      ;;
  esac
  shift
done

set -x
${ENVPYTHON} -m black \
  --include "${INCLUDE_ARG:-${RUN_BLACK_INCLUDE:-${DEFAULT_INCLUDE}}}" \
  --exclude "${EXCLUDE_ARG:-${RUN_BLACK_EXCLUDE:-${DEFAULT_EXCLUDE}}}" \
  "${OTHER_ARGS[@]}"
