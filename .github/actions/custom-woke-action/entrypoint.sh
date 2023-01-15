#!/bin/bash
# shellcheck disable=SC2086

set -e

cd "${GITHUB_WORKSPACE}/${INPUT_WORKDIR}" || exit 1

TEMP_PATH="$(mktemp -d)"
PATH="${TEMP_PATH}:$PATH"

echo '::group:: Installing woke ... https://github.com/nhosoi/woke'
curl https://raw.githubusercontent.com/nhosoi/woke/main/woke -o "${TEMP_PATH}/woke"
chmod 0755 "${TEMP_PATH}/woke"
echo '::endgroup::'

echo '::group:: Running woke ...'
woke \
  --output github-actions \
  --exit-1-on-failure="${INPUT_FAIL_ON_ERROR:-false}" \
  ${INPUT_WOKE_ARGS}
echo '::endgroup::'
