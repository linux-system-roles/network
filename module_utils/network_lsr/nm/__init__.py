# Relative import is not support by ansible 2.8 yet
# pylint: disable=import-error, no-name-in-module
from ansible.module_utils.network_lsr.nm import provider  # noqa:E501

# pylint: enable=import-error, no-name-in-module

provider.NetworkManagerProvider
