#!/usr/bin/env python
""" pytest environment setup """
# SPDX-License-Identifier: BSD-3-Clause

import sys
import os

try:
    from unittest import mock
except ImportError:  # py2
    import mock

project_path = os.path.abspath(os.path.dirname(os.path.realpath(__file__)) + "/../../")
sys.path.append(project_path + "/library")
sys.path.append(project_path + "/module_utils")

import network_lsr

__metaclass__ = type

sys.modules["ansible.module_utils.basic"] = mock.Mock()
sys.modules["ansible.module_utils.network_lsr"] = network_lsr
