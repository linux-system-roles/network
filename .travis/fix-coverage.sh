#!/bin/bash

set -ex

cat > .coveragerc <<EOF
[paths]
source =
    .
    $PWD
EOF
mv .coverage .coverage.merge
coverage combine --append .
