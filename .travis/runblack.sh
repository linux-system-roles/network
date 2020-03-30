#!/bin/bash
# SPDX-License-Identifier: MIT

# A shell wrapper around black (Python formatter). The purpose of this wrapper
# is to get a user the opportunity to control black from config.sh via setting
# environment variables.

# The given command line arguments are passed to black.

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
#
#   RUN_BLACK_EXTRA_ARGS
#     extra cmd line args to pass to black

set -e

ME=$(basename $0)
SCRIPTDIR=$(readlink -f $(dirname $0))

. ${SCRIPTDIR}/utils.sh
. ${SCRIPTDIR}/config.sh

if [[ "${RUN_BLACK_DISABLED}" ]]; then
  lsr_info "${ME}: black is disabled. Skipping."
  exit 0
fi

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
python -m black \
  --include "${INCLUDE_ARG:-${RUN_BLACK_INCLUDE:-${DEFAULT_INCLUDE}}}" \
  --exclude "${EXCLUDE_ARG:-${RUN_BLACK_EXCLUDE:-${DEFAULT_EXCLUDE}}}" \
  ${RUN_BLACK_EXTRA_ARGS:-} \
  "${OTHER_ARGS[@]}"
