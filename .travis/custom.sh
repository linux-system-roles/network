#!/bin/bash
# SPDX-License-Identifier: MIT

set -e

. "$LSR_SCRIPTDIR/utils.sh"

# Write your custom commands here that should be run when `tox -e custom`:
if lsr_check_python_version python -eq '3.6'; then
    (set -x; cd "${TOPDIR}/tests"; python ./ensure_provider_tests.py)
fi
