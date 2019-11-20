#!/bin/bash
# SPDX-License-Identifier: MIT

# Wrapper around pytest. First argument is a path to environment python, the
# rest of arguments are passed to pytest.

set -e

ME=$(basename $0)
SCRIPTDIR=$(readlink -f $(dirname $0))
TOPDIR=$(readlink -f ${SCRIPTDIR}/..)

# Include library.
. ${SCRIPTDIR}/utils.sh

if [[ ! -d ${TOPDIR}/tests/unit ]]; then
  lsr_info "${ME}: No unit tests found. Skipping."
  exit 0
fi

# Sanitize path in case if running within tox (see
# https://github.com/tox-dev/tox/issues/1463):
ENVPYTHON=$(readlink -f $1)
shift

PYTEST_OPTS=()
PYTEST_OPTS_NOCOV=()
USE_COV=no

# Filter out coverage options if there is nothing to be analyzed with coverage.
while [[ $# -gt 0 ]]; do
  case "$1" in
    --cov=*)
      if [[ "${1:6}" && -d "${1:6}" ]]; then
        USE_COV=yes
        PYTEST_OPTS+=( "$1" )
      fi
      ;;
    --cov*|--no-cov*)
      PYTEST_OPTS+=( "$1" )
      ;;
    *)
      PYTEST_OPTS+=( "$1" )
      PYTEST_OPTS_NOCOV+=( "$1" )
      ;;
  esac
  shift
done

if [[ "${USE_COV}" == "no" ]]; then
  PYTEST_OPTS=( "${PYTEST_OPTS_NOCOV[@]}" )
fi

set -x
${ENVPYTHON} -m pytest "${PYTEST_OPTS[@]}"
