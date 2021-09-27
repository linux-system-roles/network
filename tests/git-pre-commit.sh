#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause

set -euo pipefail

# This script is intended to be used as git pre-commit hook.
# Make sure file is executable and copy it into <your repo>/.git/hooks/pre-commit
# This script has to be used together with post-commit to work properly.

GITPATH=$(git rev-parse --show-toplevel)

touch "$GITPATH/.commit"

