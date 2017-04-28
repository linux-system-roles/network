#!/bin/bash

# Run integration test for this repository. It fetches the test harness from
# docker.io, which is built from
#
#   http://github.com/linux-system-roles/test-harness

set -xeuf -o pipefail

CACHEDIR=${CACHEDIR:-$PWD/.image-cache}
mkdir -p $CACHEDIR

docker run --privileged \
           --rm \
           --volume $PWD:/role \
           --volume $CACHEDIR:/cache \
           cockpit/linux-system-roles-test
