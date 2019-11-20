#!/bin/bash
# SPDX-License-Identifier: MIT

# Execute command in environment python only if environment python has access
# to system python libraries, especially C bindings. The script is run with
# these arguments:
#
#   $1     - path to environment python
#   $2     - path to system python
#   $3     - command runnable in Python (should be present in $PATH)
#   ${@:4} - arguments passed to $3

set -e

ME=$(basename $0)
SCRIPTDIR=$(readlink -f $(dirname $0))
TOPDIR=$(readlink -f ${SCRIPTDIR}/..)

# Include library and config.
. ${SCRIPTDIR}/utils.sh
. ${SCRIPTDIR}/config.sh

# Run user defined hook from .travis/config.sh.
lsr_runsyspycmd_hook "$@"

# Sanitize arguments (see https://github.com/tox-dev/tox/issues/1463):
ENVPYTHON=$(readlink -f $1)
SYSPYTHON=$(readlink -f $2)
shift 2

if lsr_compare_pythons ${ENVPYTHON} -ne ${SYSPYTHON}; then
  lsr_info "${ME}: ${1:-<missing command>}:" \
    "Environment Python has no access to system Python libraries. Skipping."
  exit 0
fi

COMMAND=$(command -v $1)
shift

set -x
${ENVPYTHON} ${COMMAND} "$@"
