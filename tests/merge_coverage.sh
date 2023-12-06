#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause

if [ -n "${DEBUG}" ]
then
    set -x
fi
set -e

if [ "$#" -lt 3 ]
then
    echo "USAGE: ${0} path_to_coverage_binary output_file input_files..."
    echo "Merges all input_files into output file without removing input_files"
    exit 1
fi

# path to coverage binary
coverage="${1}"
shift

# read by coverage binary
export COVERAGE_FILE="${1}"
shift

tempdir="$(mktemp -d /tmp/coverage_merge-XXXXXX)"
# we want to expand ${tempdir} here, so tell SC to be quiet
# https://github.com/koalaman/shellcheck/wiki/SC2064
# shellcheck disable=SC2064
trap "rm -rf '${tempdir}'" EXIT

cp --backup=numbered -- "${@}" "${tempdir}"
# FIXME: Would not work if coverage files are not hidden but they are by
# default
shopt -s dotglob
"${coverage}" combine "${tempdir}/"*

echo "Merged data into ${COVERAGE_FILE}"
./covstats "${COVERAGE_FILE}"
