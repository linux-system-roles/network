#!/bin/bash
# SPDX-License-Identifier: MIT

# A shell wrapper around shellcheck. The purpose of this wrapper is to get to user
# an opportunity to disable running shellcheck via config.sh.
# The wrapper will also check for the existence of the shellcheck command and
# offer suggestions about how to install.

# The given command line arguments are passed to shellcheck.

# Environment variables:
#
#   RUN_SHELLCHECK_DISABLED
#     if set to an arbitrary non-empty value, shellcheck will be not executed
#
#   RUN_SHELLCHECK_EXTRA_ARGS
#     any extra command line arguments to provide e.g. --include=some,errs

set -e

ME=$(basename "$0")
SCRIPTDIR=$(readlink -f "$(dirname "$0")")

. "${SCRIPTDIR}/utils.sh"
. "${SCRIPTDIR}/config.sh"

if [[ "${RUN_SHELLCHECK_DISABLED}" ]]; then
  lsr_info "${ME}: shellcheck is disabled. Skipping."
  exit 0
fi

if ! type -p shellcheck > /dev/null 2>&1; then
  lsr_info "${ME}: on Fedora try 'dnf -y install ShellCheck'"
  lsr_info "${ME}: see https://github.com/koalaman/shellcheck#user-content-installing for more information"
  lsr_error "${ME}: shellcheck command not found"
fi

set -x
# the SC1090 is because we assume all sourced files are in this repo
# see https://github.com/koalaman/shellcheck/wiki/SC1090
# https://github.com/koalaman/shellcheck/wiki/SC2086
# shellcheck disable=SC2086
# https://github.com/koalaman/shellcheck/wiki/SC2038
# shellcheck disable=SC2038
find \( -name .tox -prune \) -o \( -name .venv -prune \) -o -name \*.sh -print | \
  xargs shellcheck ${RUN_SHELLCHECK_EXTRA_ARGS:-} -e SC1090
