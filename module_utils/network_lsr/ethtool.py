# SPDX-License-Identifier: BSD-3-Clause

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import array
import struct
import fcntl
import socket

from .utils import Util

ETHTOOL_GPERMADDR = 0x00000020
SIOCETHTOOL = 0x8946
MAX_ADDR_LEN = 32
IFNAMESIZ = 16


def get_perm_addr(ifname):
    """
    Return the Permanent address value for the specified interface using the
    ETHTOOL_GPERMADDR ioctl command.

    Please for further documentation, see:
    wokeignore:rule=master
    https://github.com/torvalds/linux/blob/master/include/uapi/linux/ethtool.h#L734
    wokeignore:rule=master
    https://github.com/torvalds/linux/blob/master/include/uapi/linux/ethtool.h#L1388
    https://git.kernel.org/pub/scm/network/ethtool/ethtool.git/tree/ethtool.c#n4172
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sockfd = sock.fileno()
        ifname = ifname.encode("utf-8")
        if len(ifname) > IFNAMESIZ:
            return None

        ecmd = array.array(
            "B",
            struct.pack(
                "II%is" % MAX_ADDR_LEN,
                ETHTOOL_GPERMADDR,
                MAX_ADDR_LEN,
                b"\x00" * MAX_ADDR_LEN,
            ),
        )
        ifreq = struct.pack("%isP" % IFNAMESIZ, ifname, ecmd.buffer_info()[0])

        fcntl.ioctl(sockfd, SIOCETHTOOL, ifreq)
        try:
            res = ecmd.tobytes()
        except AttributeError:  # tobytes() is not available in python2
            res = ecmd.tostring()
        unused, size, perm_addr = struct.unpack("II%is" % MAX_ADDR_LEN, res)
        perm_addr = Util.mac_ntoa(perm_addr[:size])
    except IOError:
        perm_addr = None
    finally:
        sock.close()

    return perm_addr
