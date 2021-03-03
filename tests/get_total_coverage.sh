#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause

set -e
coverage_data=total-coveragedata
testhost="${1}"

if [ "$#" -lt 1 ]
then
    echo "USAGE: ${0} host"
    echo "Get local and all remote coverage data for host"
    exit 1
fi

rm -f remote-coveragedata* "${coverage_data}"


# collect pytest coverage
tox -e py26,py27,py36,py37 -- --cov-append

for test_playbook in tests_*.yml
do
    ./get_coverage.sh "${testhost}" "${test_playbook}"
done

./merge_coverage.sh coverage "total-remote-coveragedata" remote-coveragedata-*
./covstats .coverage remote-coveragedata-* "total-remote-coveragedata"

./merge_coverage.sh coverage "${coverage_data}" .coverage remote-coveragedata-*
echo "Total coverage:"
COVERAGE_FILE="${coverage_data}" coverage report ||:
COVERAGE_FILE="${coverage_data}" coverage html --directory "htmlcov-${coverage_data}" ||:
echo "Open HTML report with:"
echo "xdg-open htmlcov-${coverage_data}/index.html"
