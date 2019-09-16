#!/bin/bash
# SPDX-License-Identifier: MIT

set -ex

cat > .coveragerc <<EOF
[paths]
source =
    .
    $PWD
EOF
mv .coverage .coverage.merge
coverage combine --append .
