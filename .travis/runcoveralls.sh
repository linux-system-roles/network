#!/bin/bash
# SPDX-License-Identifier: MIT

# Reports coverage results using coveralls. The aim of this script is to
# provide a unified way to reporting coverage results across all linux system
# roles projects.

# The given command line arguments are passed to coveralls.

# Environment variables:
#
#   LSR_PUBLISH_COVERAGE
#     If the variable is unset or empty (the default), no coverage is published.
#     Other valid values for the variable are:
#     strict - the reporting is performed in strict mode, so situations
#              like missing data to be reported are treated as errors
#     debug  - coveralls is run in debug mode (see coveralls debug --help)
#     normal - coverage results will be reported normally
#   LSR_TESTSDIR
#     a path to directory where tests and tests artifacts are located; if unset
#     or empty, this variable is set to ${TOPDIR}/tests; this path should
#     already exists and be populated with tests artifacts before the script
#     starts performing actions on it

set -e

ME=$(basename "$0")
SCRIPTDIR=$(readlink -f "$(dirname "$0")")

. "${SCRIPTDIR}/utils.sh"
. "${SCRIPTDIR}/config.sh"

# Publish the results only if it is desired.
if [[ -z "${LSR_PUBLISH_COVERAGE}" ]]; then
  lsr_info "${ME}: Publishing coverage report is not enabled. Skipping."
  exit 0
fi

case "${LSR_PUBLISH_COVERAGE}" in
    strict) : ;;
    debug) : ;;
    normal) : ;;
    *) lsr_error Error: \""${LSR_PUBLISH_COVERAGE}"\" is not a valid option ;;
esac

LSR_TESTSDIR=${LSR_TESTSDIR:-"${TOPDIR}/tests"}

# Ensure we are in $LSR_TESTSDIR. It is supposed that if a user wants to submit
# tests results, $LSR_TESTSDIR always exists.
cd "${LSR_TESTSDIR}"

# For simplicity, we suppose that coverage core data file has name .coverage
# and it is situated in $LSR_TESTSDIR. Similarly for .coveragerc.
COVERAGEFILE='.coverage'
COVERAGERCFILE='.coveragerc'

# In case there is no $COVERAGEFILE, there is nothing to report. If we are
# running in strict mode, treat this situation as error.
if [[ ! -s "${COVERAGEFILE}" ]]; then
  NO_COVERAGEFILE_MSG="${COVERAGEFILE} is missing or empty"
  if [[ "${LSR_PUBLISH_COVERAGE}" == "strict" ]]; then
    lsr_error "${ME} (strict mode): ${NO_COVERAGEFILE_MSG}!"
  fi
  lsr_info "${ME}: ${NO_COVERAGEFILE_MSG}, nothing to publish."
  exit 0
fi

# Create $COVERAGERCFILE file with a [paths] section. From the official docs:
#
#   The first value must be an actual file path on the machine where the
#   reporting will happen, so that source code can be found. The other values
#   can be file patterns to match against the paths of collected data, or they
#   can be absolute or relative file paths on the current machine.
#
# So in our $COVERAGERCFILE file we make both locations to point to the
# project's top directory.
cat > "${COVERAGERCFILE}" <<EOF
[paths]
source =
    ..
    $(readlink -f ..)
EOF

# Rename $COVERAGEFILE to ${COVERAGEFILE}.merge. With this trick, coverage
# combine applies configuration in $COVERAGERCFILE also to $COVERAGEFILE.
mv "${COVERAGEFILE}" "${COVERAGEFILE}.merge"
python -m coverage combine --append

MAYBE_DEBUG=""
if [[ "${LSR_PUBLISH_COVERAGE}" == "debug" ]]; then
  MAYBE_DEBUG=debug
fi

set -x
# https://github.com/koalaman/shellcheck/wiki/SC2086
# shellcheck disable=SC2086
coveralls ${MAYBE_DEBUG} "$@"
