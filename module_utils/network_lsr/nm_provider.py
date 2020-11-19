# SPDX-License-Identifier: BSD-3-Clause
""" Support for NetworkManager aka the NM provider """

# pylint: disable=import-error, no-name-in-module
from ansible.module_utils.network_lsr.utils import Util  # noqa:E501

ETHTOOL_FEATURE_PREFIX = "ETHTOOL_OPTNAME_FEATURE_"
ETHTOOL_SETRING_PREFIX = "ETHTOOL_OPTNAME_RING_"


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


def get_nm_ethtool_setring(name):
    """
    Translate ethtool set-ring into Network Manager name
    :param name: Name of the set-ring
    :type name: str
    :returns: Name of the setting to be used by `NM.SettingEthtool.set_ring()`
    :rtype: str
    """

    name = ETHTOOL_SETRING_PREFIX + name.upper()

    setring = getattr(Util.NM(), name, None)
    return setring
