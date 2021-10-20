#!/usr/bin/env python
""" Tests for network_connections Ansible module """
# SPDX-License-Identifier: BSD-3-Clause

try:
    from unittest import mock
except ImportError:  # py2
    import mock

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
