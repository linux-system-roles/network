#!/bin/bash
# SPDX-License-Identifier: MIT

# A shell wrapper around pytest. As pytest is sensitive on a content of project
# directory: if a project contains no unit tests, pytest fails. Similarly if
# there is nothing to be analyzed with coverage, running pytest with --cov*
# arguments may lead to problems. For this reasons, this shell wrapper skips
# running pytest if there are no unit tests and filters out --cov*/--no-cov*
# arguments if there is nothing to be analyzed with coverage.

# First argument to the script is a path to environment python, the rest of
# arguments are passed to pytest.

set -e

ME=$(basename $0)
SCRIPTDIR=$(readlink -f $(dirname $0))
TOPDIR=$(readlink -f ${SCRIPTDIR}/..)

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
