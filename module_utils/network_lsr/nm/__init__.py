# Relative import is not support by ansible 2.8 yet
# pylint: disable=import-error, no-name-in-module
from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible.module_utils.network_lsr.nm import provider  # noqa:E501

# pylint: enable=import-error, no-name-in-module

provider.NetworkManagerProvider
