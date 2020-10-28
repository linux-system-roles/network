#!/bin/bash
# SPDX-License-Identifier: MIT

set -e

#uncomment if you use $ME - otherwise set in utils.sh
#ME=$(basename "$0")
SCRIPTDIR=$(readlink -f "$(dirname "$0")")

. "${SCRIPTDIR}/utils.sh"
. "${SCRIPTDIR}/config.sh"

# Collection commands that are run when `tox -e collection`:
role=$(basename "${TOPDIR}")
toxworkdir=${1:-"${TOPDIR}"/.tox}
STABLE_TAG=${2:-"master"}
cd "${toxworkdir}"
toxworkdir=$(pwd)
testlist="yamllint,py38"
extra="black flake8 shellcheck"

cd "${SCRIPTDIR}"
for item in ${extra}; do
    for f in *"${item}"*.sh; do
        if [ -f "${f}" ]; then
            testlist+=",${item}"
            break
        fi
    done
done

cd "${toxworkdir}"
automaintenancerepo=https://raw.githubusercontent.com/linux-system-roles/auto-maintenance/
curl -L -o lsr_role2collection.py "${automaintenancerepo}${STABLE_TAG}"/lsr_role2collection.py

python lsr_role2collection.py --src-path "${TOPDIR}/.." --dest-path "${toxworkdir}" --role "${role}" > "${toxworkdir}"/collection.out 2>&1

yamllint="${toxworkdir}"/ansible_collections/fedora/system_roles/.yamllint_defaults.yml
sed -i -e 's/\( *\)\(document-start: disable\)/\1\2\n\1line-length:\n\1\1level: warning/' "${yamllint}"

cd ansible_collections/fedora/system_roles
tox -e "${testlist}" 2>&1 | tee "${toxworkdir}"/collection.tox.out || :

rm -rf "${toxworkdir}"/auto-maintenance "${toxworkdir}"/ansible_collections
cd "${TOPDIR}"
res=$( grep "^ERROR: .*failed" "${toxworkdir}"/collection.tox.out || : )
if [ "$res" != "" ]; then
    lsr_error "${ME}: tox in the converted collection format failed."
    exit 1
fi
