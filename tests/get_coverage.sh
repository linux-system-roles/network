#!/bin/bash
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

echo "Getting coverage for ${playbook} on ${host}" >&2

call_ansible() {
    local module="${1}"
    shift
    local args="${1}"
    shift
    ansible -m "${module}" -i "${host}", -a "${args}" all "${@}"
}

remote_coverage_dir="$(mktemp -d /tmp/remote_coverage-XXXXXX)"
# we want to expand ${remote_coverage_dir} here, so tell SC to be quiet
# https://github.com/koalaman/shellcheck/wiki/SC2064
# shellcheck disable=SC2064
trap "rm -rf '${remote_coverage_dir}'" EXIT
ansible-playbook -i "${host}", get_coverage.yml -e "test_playbook=${playbook} destdir=${remote_coverage_dir}"

#COVERAGE_FILE=remote-coverage coverage combine remote-coverage/tests_*/*/root/.coverage
# https://github.com/koalaman/shellcheck/wiki/SC2046
# shellcheck disable=SC2046
./merge_coverage.sh coverage "${coverage_data}"-tmp $(find "${remote_coverage_dir}" -type f | tr , _)

cat > tmp_merge_coveragerc <<EOF
[paths]
source =
    .
EOF
# example path with Ansible 2.9.6:
# /tmp/ansible_network_connections_payload_psugdf6r/ansible_network_connections_payload.zip/ansible/modules/network_connections.py
# /tmp/ansible_network_connections_payload_psugdf6r/ansible_network_connections_payload.zip/ansible/module_utils/network_lsr/__init__.py
# /tmp/ansible_network_connections_payload_psugdf6r/ansible_network_connections_payload.zip/ansible/module_utils/network_lsr/argument_validator.py
# /tmp/ansible_network_connections_payload_psugdf6r/ansible_network_connections_payload.zip/ansible/module_utils/network_lsr/utils.py
# /tmp/ansible_network_connections_payload_psugdf6r/ansible_network_connections_payload.zip/ansible/module_utils/network_lsr/nm_provider.py
for file in $(echo 'SELECT path FROM file;' | sqlite3 "${coverage_data}"-tmp | sed s,/module.*.py,, | sort -u)
do
    echo "    ${file}" >> tmp_merge_coveragerc
done

COVERAGE_FILE="${coverage_data}" coverage combine --rcfile tmp_merge_coveragerc "${coverage_data}"-tmp

test -n "${DEBUG}" && cat tmp_merge_coveragerc
rm tmp_merge_coveragerc

COVERAGE_FILE="${coverage_data}" coverage report ||:
COVERAGE_FILE="${coverage_data}" coverage html --directory "htmlcov-${coverage_data}" ||:

echo "Coverage collected in: ${coverage_data}"
