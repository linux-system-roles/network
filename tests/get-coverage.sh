#! /bin/bash
# SPDX-License-Identifier: BSD-3-Clause

if [ -n "${DEBUG}" ]
then
    set -x
fi
set -e

if [ "$#" -lt 2 ]
then
    echo "USAGE: ${0} host playbook"
    echo "Get coverage info from host for playbook"
    exit 1
fi

host="${1}"
shift
playbook="${1}"

coverage_data="remote-coveragedata-${host}-${playbook%.yml}"
coverage="/root/.local/bin/coverage"

echo "Getting coverage for ${playbook} on ${host}" >&2

call_ansible() {
    local module="${1}"
    shift
    local args="${1}"
    shift
    ansible -m "${module}" -i "${host}", -a "${args}" all "${@}"
}

remote_coverage_dir="$(mktemp -d /tmp/remote_coverage-XXXXXX)"
trap "rm -rf '${remote_coverage_dir}'" EXIT
ansible-playbook -i "${host}", get-coverage.yml -e "test_playbook=${playbook} destdir=${remote_coverage_dir}"

#COVERAGE_FILE=remote-coverage coverage combine remote-coverage/tests_*/*/root/.coverage
./merge-coverage.sh coverage "${coverage_data}"-tmp $(find "${remote_coverage_dir}" -type f | tr , _)

# When https://github.com/nedbat/coveragepy/pull/49 is merged, this can be simplified:
if false
then
cat > tmp_merge_coveragerc <<EOF
[paths]
source =
    .
    /tmp/ansible_*/
EOF
else
cat > tmp_merge_coveragerc <<EOF
[paths]
source =
    .
EOF
for file in $(COVERAGE_FILE="${coverage_data}"-tmp coverage report | grep -o "/tmp/ansible_[^/]*" | sort -u)
do
    echo "    ${file}" >> tmp_merge_coveragerc
done
fi

COVERAGE_FILE="${coverage_data}" coverage combine --rcfile tmp_merge_coveragerc "${coverage_data}"-tmp
rm tmp_merge_coveragerc

COVERAGE_FILE="${coverage_data}" coverage report ||:
COVERAGE_FILE="${coverage_data}" coverage html --directory "htmlcov-${coverage_data}" ||:

echo "Coverage collected in: ${coverage_data}"
