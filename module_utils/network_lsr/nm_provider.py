# SPDX-License-Identifier: BSD-3-Clause
""" Support for NetworkManager aka the NM provider """

# pylint: disable=import-error, no-name-in-module
from ansible.module_utils.network_lsr.utils import Util

ETHTOOL_FEATURE_PREFIX = "ETHTOOL_OPTNAME_FEATURE_"


def get_nm_ethtool_feature(name):
    """
        Translate ethtool feature into Network Manager name

        :param name: Name of the feature
        :type name: str
        :returns: Name of the feature to be used by `NM.SettingEthtool.set_feature()`
        :rtype: str
    """

    name = ETHTOOL_FEATURE_PREFIX + name.upper().replace("-", "_")

    feature = getattr(Util.NM(), name, None)
    return feature
