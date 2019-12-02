#!/bin/bash
# SPDX-License-Identifier: MIT

# Report coverage results using coveralls. The script is executed with these
# parameters:
#
#   $1 - path to environment python
#   $2 - path to system python
#
# coveralls is executed only if $1 coincides with $2 and $1's environment is
# stable, i.e. TRAVIS_PYTHON_VERSION is of the form [:digit:] "." [:digit:]
# (this prevents running coveralls more then once in the case if both X.Y and
# X.Y-dev coincides with system python which version is also X.Y). The results
# are reported only if LSR_PUBLISH_COVERAGE is non-empty.

set -e

ME=$(basename $0)
SCRIPTDIR=$(readlink -f $(dirname $0))
TOPDIR=$(readlink -f ${SCRIPTDIR}/..)

. ${SCRIPTDIR}/utils.sh
. ${SCRIPTDIR}/config.sh

# Run user defined hook from .travis/config.sh.
lsr_runcoveralls_hook "$@"

# Publish the results only if it is desired.
if [[ -z "${LSR_PUBLISH_COVERAGE}" ]]; then
  lsr_info "${ME}: Publishing coverage report is not enabled. Skipping."
  exit 0
fi

# Sanitize arguments (see https://github.com/tox-dev/tox/issues/1463):
ENVPYTHON=$(readlink -f $1)
SYSPYTHON=$(readlink -f $2)
shift 2

if lsr_compare_pythons ${ENVPYTHON} -ne ${SYSPYTHON}; then
  lsr_info "${ME}:" \
    "Environment Python has no access to system Python libraries. Skipping."
  exit 0
fi

if [[ ! "${TRAVIS_PYTHON_VERSION}" =~ ^[[:digit:]]\.[[:digit:]]$ ]]; then
  lsr_info "${ME}: Not stable environment. Skipping."
  exit 0
fi

COVERALLSCMD=$(command -v coveralls)

# Fix coverage.
cat > ${TOPDIR}/.coveragerc <<EOF
[paths]
source =
    .
    ${TOPDIR}
EOF
mv ${TOPDIR}/.coverage ${TOPDIR}/.coverage.merge || :
${ENVPYTHON} -m coverage combine --append ${TOPDIR} || :

set -x
${ENVPYTHON} ${COVERALLSCMD}
