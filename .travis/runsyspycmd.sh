#!/bin/bash
# SPDX-License-Identifier: MIT

# Execute command in environment python only if environment python has access
# to system python libraries, especially C bindings. The script is run with
# these arguments:
#
#   $1     - command runnable in Python (should be present in $PATH)
#   ${@:2} - arguments passed to $1

set -e

ME=$(basename "$0")
SCRIPTDIR=$(readlink -f "$(dirname "$0")")

. "${SCRIPTDIR}/utils.sh"
. "${SCRIPTDIR}/config.sh"

if ! lsr_venv_python_matches_system_python ; then
  lsr_info "${ME}: ${1:-<missing command>}:" \
    "Environment Python has no access to system Python libraries. Skipping."
  exit 0
fi

COMMAND=$(command -v "$1")
shift

set -x
python "${COMMAND}" "$@"
