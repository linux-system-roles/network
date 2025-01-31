#!/usr/bin/env python
"""Tests for network_connections Ansible module"""
# SPDX-License-Identifier: BSD-3-Clause

import os
import sys

TESTS_BASEDIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(1, os.path.join(TESTS_BASEDIR, "../..", "library"))
sys.path.insert(1, os.path.join(TESTS_BASEDIR, "../..", "module_utils"))

try:
    from unittest import mock
except ImportError:  # py2
    import mock

sys.modules["ansible"] = mock.Mock()
sys.modules["ansible.module_utils.basic"] = mock.Mock()
sys.modules["ansible.module_utils"] = mock.Mock()
sys.modules["ansible.module_utils.network_lsr"] = __import__("network_lsr")

with mock.patch.dict("sys.modules", {"gi": mock.Mock(), "gi.repository": mock.Mock()}):
    # pylint: disable=import-error, wrong-import-position
    from network_lsr import nm_provider


def test_get_nm_ethtool_feature():
    """Test get_nm_ethtool_feature()"""
    with mock.patch.object(nm_provider.Util, "NM") as nm_mock:
        nm_feature = nm_provider.get_nm_ethtool_feature("esp_hw_offload")
    assert nm_feature == nm_mock.return_value.ETHTOOL_OPTNAME_FEATURE_ESP_HW_OFFLOAD


def test_get_nm_ethtool_coalesce():
    """Test get_nm_ethtool_coalesce()"""
    with mock.patch.object(nm_provider.Util, "NM") as nm_mock:
        nm_feature = nm_provider.get_nm_ethtool_coalesce("rx_frames")
    assert nm_feature == nm_mock.return_value.ETHTOOL_OPTNAME_COALESCE_RX_FRAMES
