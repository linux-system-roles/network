#!/bin/bash

if [ x${LSRENV} = x2.7 ]; then
  LSR_PYLINT_DIRS='library/network_connections.py module_utils/network_lsr tests/unit/test_network_connections.py'
fi

if [ x${LSRENV} = x3.5 ]; then
  LSR_MOLECULE_DEPS='-rmolecule_requirements.txt'

  sudo apt-get install -y python3-selinux
fi

if [ x${LSRENV} = x3.6 ]; then
  LSR_TEXTRA_DEPS='PyYAML'
  LSR_TEXTRA_DIR='tests'
  LSR_TEXTRA_CMD='./ensure_non_running_provider.py'
fi
