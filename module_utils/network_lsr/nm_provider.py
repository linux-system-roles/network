# SPDX-License-Identifier: BSD-3-Clause
""" Support for NetworkManager aka the NM provider """

# pylint: disable=import-error, no-name-in-module
from ansible.module_utils.network_lsr.utils import Util  # noqa:E501

ETHTOOL_FEATURE_PREFIX = "ETHTOOL_OPTNAME_FEATURE_"
ETHTOOL_COALESCE_PREFIX = "ETHTOOL_OPTNAME_COALESCE_"


def get_nm_ethtool_feature(name):
    """
    Translate ethtool feature into Network Manager name

    :param name: Name of the feature
    :type name: str
    :returns: Name of the feature to be used by `NM.SettingEthtool.set_feature()`
    :rtype: str
    """

    name = ETHTOOL_FEATURE_PREFIX + name.upper()

    feature = getattr(Util.NM(), name, None)
    return feature


def get_nm_ethtool_coalesce(name):
    """
    Translate ethtool coalesce into Network Manager name

    :param name: Name of the coalesce
    :type name: str
    :returns: Name of the setting to be used by `NM.SettingEthtool.set_coalesce()`
    :rtype: str
    """

    name = ETHTOOL_COALESCE_PREFIX + name.upper()

    coalesce = getattr(Util.NM(), name, None)
    return coalesce
