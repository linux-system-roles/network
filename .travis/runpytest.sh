#!/bin/bash
# SPDX-License-Identifier: MIT

# A shell wrapper around pytest. As pytest is sensitive on a content of project
# directory: if a project contains no unit tests, pytest fails. Similarly if
# there is nothing to be analyzed with coverage, running pytest with --cov*
# arguments may lead to problems. For this reasons, this shell wrapper skips
# running pytest if there are no unit tests and filters out --cov*/--no-cov*
# arguments if there is nothing to be analyzed with coverage.

# The given command line arguments are passed to pytest.

# Environment variables:
#
#   RUN_PYTEST_SETUP_MODULE_UTILS
#     if set to an arbitrary non-empty value, the environment will be
#     configured so that tests of the module_utils/ code will be run
#     correctly

set -e

ME=$(basename $0)
SCRIPTDIR=$(readlink -f $(dirname $0))

. ${SCRIPTDIR}/utils.sh
. ${SCRIPTDIR}/config.sh

if [[ ! -d ${TOPDIR}/tests/unit ]]; then
  lsr_info "${ME}: No unit tests found. Skipping."
  exit 0
fi

if [[ "${RUN_PYTEST_SETUP_MODULE_UTILS}" ]]; then
  lsr_setup_module_utils
fi

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
python -m pytest "${PYTEST_OPTS[@]}"
