#!/usr/bin/python3 -tt
# vim: fileencoding=utf8
# SPDX-License-Identifier: BSD-3-Clause

import posixpath
import socket

# pylint: disable=import-error, no-name-in-module
from ansible.module_utils.network_lsr import MyError  # noqa:E501
from ansible.module_utils.network_lsr.utils import Util  # noqa:E501


class ArgUtil:
    @staticmethod
    def connection_find_by_name(name, connections, n_connections=None):
        if not name:
            raise ValueError("missing name argument")
        c = None
        for idx, connection in enumerate(connections):
            if n_connections is not None and idx >= n_connections:
                break
            if "name" not in connection or name != connection["name"]:
                continue

            if connection["persistent_state"] == "absent":
                c = None
            elif connection["persistent_state"] == "present":
                c = connection
        return c

    @staticmethod
    def connection_find_master(name, connections, n_connections=None):
        c = ArgUtil.connection_find_by_name(name, connections, n_connections)
        if not c:
            raise MyError("invalid master/parent '%s'" % (name))
        if c["interface_name"] is None:
            raise MyError(
                "invalid master/parent '%s' which needs an 'interface_name'" % (name)
            )
        if not Util.ifname_valid(c["interface_name"]):
            raise MyError(
                "invalid master/parent '%s' with invalid 'interface_name' ('%s')"
                % (name, c["interface_name"])
            )
        return c["interface_name"]

    @staticmethod
    def connection_find_master_uuid(name, connections, n_connections=None):
        c = ArgUtil.connection_find_by_name(name, connections, n_connections)
        if not c:
            raise MyError("invalid master/parent '%s'" % (name))
        return c["nm.uuid"]

    @staticmethod
    def connection_get_non_absent_names(connections):
        # @idx is the index with state['absent']. This will
        # return the names of all explicitly mentioned profiles.
        # That is, the names of profiles that should not be deleted.
        result = set()
        for connection in connections:
            if "name" not in connection:
                continue
            if not connection["name"]:
                continue
            result.add(connection["name"])
        return result


class ValidationError(MyError):
    def __init__(self, name, message):
        Exception.__init__(self, name + ": " + message)
        self.error_message = message
        self.name = name

    @staticmethod
    def from_connection(idx, message):
        return ValidationError("connection[" + str(idx) + "]", message)


class ArgValidator:
    MISSING = object()
    DEFAULT_SENTINEL = object()

    def __init__(self, name=None, required=False, default_value=None):
        self.name = name
        self.required = required
        self.default_value = default_value

    def get_default_value(self):
        try:
            return self.default_value()
        except Exception:  # pylint: disable=broad-except
            return self.default_value

    def validate(self, value):
        return self._validate(value, self.name)

    def _validate(self, value, name):
        validated = self._validate_impl(value, name)
        return self._validate_post(value, name, validated)

    def _validate_impl(self, value, name):
        raise NotImplementedError()

    # pylint: disable=unused-argument,no-self-use
    def _validate_post(self, value, name, result):
        return result


class ArgValidatorStr(ArgValidator):
    def __init__(  # pylint: disable=too-many-arguments
        self,
        name,
        required=False,
        default_value=None,
        enum_values=None,
        allow_empty=False,
        min_length=None,
        max_length=None,
    ):
        ArgValidator.__init__(self, name, required, default_value)
        self.enum_values = enum_values
        self.allow_empty = allow_empty

        if max_length is not None:
            if not isinstance(max_length, int):
                raise ValueError("max_length must be an integer")
            elif max_length < 0:
                raise ValueError("max_length must be a positive integer")
        self.max_length = max_length

        if min_length is not None:
            if not isinstance(min_length, int):
                raise ValueError("min_length must be an integer")
            elif min_length < 0:
                raise ValueError("min_length must be a positive integer")
        self.min_length = min_length

    def _validate_impl(self, value, name):
        if not isinstance(value, Util.STRING_TYPE):
            raise ValidationError(name, "must be a string but is '%s'" % (value))
        value = str(value)
        if self.enum_values is not None and value not in self.enum_values:
            raise ValidationError(
                name,
                "is '%s' but must be one of '%s'"
                % (value, "' '".join(sorted(self.enum_values))),
            )
        if not self.allow_empty and not value:
            raise ValidationError(name, "cannot be empty")
        if not self._validate_string_max_length(value):
            raise ValidationError(
                name, "maximum length is %s characters" % (self.max_length)
            )
        if not self._validate_string_min_length(value):
            raise ValidationError(
                name, "minimum length is %s characters" % (self.min_length)
            )
        return value

    def _validate_string_max_length(self, value):
        """
        Ensures that the length of string `value` is less than or equal to
        the maximum length
        """
        if self.max_length is not None:
            return len(str(value)) <= self.max_length
        else:
            return True

    def _validate_string_min_length(self, value):
        """
        Ensures that the length of string `value` is more than or equal to
         the minimum length
        """
        if self.min_length is not None:
            return len(str(value)) >= self.min_length
        else:
            return True


class ArgValidatorNum(ArgValidator):
    def __init__(  # pylint: disable=too-many-arguments
        self,
        name,
        required=False,
        val_min=None,
        val_max=None,
        default_value=ArgValidator.DEFAULT_SENTINEL,
        numeric_type=int,
    ):
        ArgValidator.__init__(
            self,
            name,
            required,
            numeric_type(0)
            if default_value is ArgValidator.DEFAULT_SENTINEL
            else default_value,
        )
        self.val_min = val_min
        self.val_max = val_max
        self.numeric_type = numeric_type

    def _validate_impl(self, value, name):
        v = None
        try:
            if isinstance(value, self.numeric_type):
                v = value
            else:
                v2 = self.numeric_type(value)
                if isinstance(value, Util.STRING_TYPE) or v2 == value:
                    v = v2
        except Exception:
            pass
        if v is None:
            raise ValidationError(
                name, "must be an integer number but is '%s'" % (value)
            )
        if self.val_min is not None and v < self.val_min:
            raise ValidationError(
                name, "value is %s but cannot be less then %s" % (value, self.val_min)
            )
        if self.val_max is not None and v > self.val_max:
            raise ValidationError(
                name,
                "value is %s but cannot be greater then %s" % (value, self.val_max),
            )
        return v


class ArgValidatorBool(ArgValidator):
    def __init__(self, name, required=False, default_value=False):
        ArgValidator.__init__(self, name, required, default_value)

    def _validate_impl(self, value, name):
        try:
            if isinstance(value, bool):
                return value
            if isinstance(value, Util.STRING_TYPE) or isinstance(value, int):
                return Util.boolean(value)
        except Exception:
            pass
        raise ValidationError(name, "must be an boolean but is '%s'" % (value))


class ArgValidatorDeprecated:
    def __init__(self, name, deprecated_by):
        self.name = name
        self.deprecated_by = deprecated_by


class ArgValidatorDict(ArgValidator):
    def __init__(
        self,
        name=None,
        required=False,
        nested=None,
        default_value=None,
        all_missing_during_validate=False,
    ):
        ArgValidator.__init__(self, name, required, default_value)
        if nested is not None:
            self.nested = dict([(v.name, v) for v in nested])
        else:
            self.nested = {}
        self.all_missing_during_validate = all_missing_during_validate

    def _validate_impl(self, value, name):
        result = {}
        seen_keys = set()
        try:
            items = list(value.items())
        except AttributeError:
            raise ValidationError(name, "invalid content is not a dictionary")
        for (setting, value) in items:
            try:
                validator = self.nested[setting]
            except KeyError:
                raise ValidationError(name, "invalid key '%s'" % (setting))
            if isinstance(validator, ArgValidatorDeprecated):
                setting = validator.deprecated_by
                validator = self.nested.get(setting, None)
            if setting in seen_keys:
                raise ValidationError(name, "duplicate key '%s'" % (setting))
            seen_keys.add(setting)
            try:
                validated_value = validator._validate(value, name + "." + setting)
            except ValidationError as e:
                raise ValidationError(e.name, e.error_message)
            result[setting] = validated_value
        for (setting, validator) in self.nested.items():
            if setting in seen_keys or isinstance(validator, ArgValidatorDeprecated):
                continue
            if validator.required:
                raise ValidationError(name, "missing required key '%s'" % (setting))
            default_value = validator.get_default_value()
            if (
                not self.all_missing_during_validate
                and default_value is not ArgValidator.MISSING
            ):
                result[setting] = default_value
        return result


class ArgValidatorList(ArgValidator):
    def __init__(self, name, nested, default_value=None):
        ArgValidator.__init__(self, name, required=False, default_value=default_value)
        self.nested = nested

    def _validate_impl(self, value, name):

        if isinstance(value, Util.STRING_TYPE):
            # we expect a list. However, for convenience allow to
            # specify a string, separated by space. Escaping is
            # not supported. If you need that, define a proper list.
            value = [s for s in value.split(" ") if s]

        result = []
        for (idx, v) in enumerate(value):
            try:
                vv = self.nested._validate(v, name + "[" + str(idx) + "]")
            except ValidationError as e:
                raise ValidationError(e.name, e.error_message)
            result.append(vv)
        return result


class ArgValidatorIP(ArgValidatorStr):
    def __init__(
        self, name, family=None, required=False, default_value=None, plain_address=True
    ):
        ArgValidatorStr.__init__(self, name, required, default_value, None)
        self.family = family
        self.plain_address = plain_address

    def _validate_impl(self, value, name):
        v = ArgValidatorStr._validate_impl(self, value, name)
        try:
            addr, family = Util.parse_ip(v, self.family)
        except Exception:
            raise ValidationError(
                name,
                "value '%s' is not a valid IP%s address"
                % (value, Util.addr_family_to_v(self.family)),
            )
        if self.plain_address:
            return addr
        return {"family": family, "address": addr}


class ArgValidatorMac(ArgValidatorStr):
    def __init__(self, name, force_len=None, required=False, default_value=None):
        ArgValidatorStr.__init__(self, name, required, default_value, None)
        self.force_len = force_len

    def _validate_impl(self, value, name):
        v = ArgValidatorStr._validate_impl(self, value, name)
        try:
            addr = Util.mac_aton(v, self.force_len)
        except MyError:
            raise ValidationError(
                name, "value '%s' is not a valid MAC address" % (value)
            )
        if not addr:
            raise ValidationError(
                name, "value '%s' is not a valid MAC address" % (value)
            )
        return Util.mac_ntoa(addr)


class ArgValidatorIPAddr(ArgValidatorDict):
    def __init__(self, name, family=None, required=False, default_value=None):
        ArgValidatorDict.__init__(
            self,
            name,
            required,
            nested=[
                ArgValidatorIP(
                    "address", family=family, required=True, plain_address=False
                ),
                ArgValidatorNum("prefix", default_value=None, val_min=0),
            ],
        )
        self.family = family

    def _validate_impl(self, value, name):
        if isinstance(value, Util.STRING_TYPE):
            v = str(value)
            if not v:
                raise ValidationError(name, "cannot be empty")
            try:
                return Util.parse_address(v, self.family)
            except Exception:
                raise ValidationError(
                    name,
                    "value '%s' is not a valid IP%s address with prefix length"
                    % (value, Util.addr_family_to_v(self.family)),
                )
        v = ArgValidatorDict._validate_impl(self, value, name)
        return {
            "address": v["address"]["address"],
            "family": v["address"]["family"],
            "prefix": v["prefix"],
        }

    def _validate_post(self, value, name, result):
        family = result["family"]
        prefix = result["prefix"]
        if prefix is None:
            prefix = Util.addr_family_default_prefix(family)
            result["prefix"] = prefix
        elif not Util.addr_family_valid_prefix(family, prefix):
            raise ValidationError(name, "invalid prefix %s in '%s'" % (prefix, value))
        return result


class ArgValidatorIPRoute(ArgValidatorDict):
    def __init__(self, name, family=None, required=False, default_value=None):
        ArgValidatorDict.__init__(
            self,
            name,
            required,
            nested=[
                ArgValidatorIP(
                    "network", family=family, required=True, plain_address=False
                ),
                ArgValidatorNum("prefix", default_value=None, val_min=0),
                ArgValidatorIP(
                    "gateway", family=family, default_value=None, plain_address=False
                ),
                ArgValidatorNum(
                    "metric", default_value=-1, val_min=-1, val_max=0xFFFFFFFF
                ),
            ],
        )
        self.family = family

    def _validate_post(self, value, name, result):
        network = result["network"]

        family = network["family"]
        result["network"] = network["address"]
        result["family"] = family

        gateway = result["gateway"]
        if gateway is not None:
            if family != gateway["family"]:
                raise ValidationError(
                    name,
                    "conflicting address family between network and gateway '%s'"
                    % (gateway["address"]),
                )
            result["gateway"] = gateway["address"]

        prefix = result["prefix"]
        if prefix is None:
            prefix = Util.addr_family_default_prefix(family)
            result["prefix"] = prefix
        elif not Util.addr_family_valid_prefix(family, prefix):
            raise ValidationError(name, "invalid prefix %s in '%s'" % (prefix, value))

        return result


class ArgValidator_DictIP(ArgValidatorDict):
    def __init__(self):
        ArgValidatorDict.__init__(
            self,
            name="ip",
            nested=[
                ArgValidatorBool("dhcp4", default_value=None),
                ArgValidatorBool("dhcp4_send_hostname", default_value=None),
                ArgValidatorIP("gateway4", family=socket.AF_INET),
                ArgValidatorNum(
                    "route_metric4", val_min=-1, val_max=0xFFFFFFFF, default_value=None
                ),
                ArgValidatorBool("auto6", default_value=None),
                ArgValidatorIP("gateway6", family=socket.AF_INET6),
                ArgValidatorNum(
                    "route_metric6", val_min=-1, val_max=0xFFFFFFFF, default_value=None
                ),
                ArgValidatorList(
                    "address",
                    nested=ArgValidatorIPAddr("address[?]"),
                    default_value=list,
                ),
                ArgValidatorList(
                    "route", nested=ArgValidatorIPRoute("route[?]"), default_value=list
                ),
                ArgValidatorBool("route_append_only"),
                ArgValidatorBool("rule_append_only"),
                ArgValidatorList(
                    "dns",
                    nested=ArgValidatorIP("dns[?]", plain_address=False),
                    default_value=list,
                ),
                ArgValidatorList(
                    "dns_search",
                    nested=ArgValidatorStr("dns_search[?]"),
                    default_value=list,
                ),
            ],
            default_value=lambda: {
                "dhcp4": True,
                "dhcp4_send_hostname": None,
                "gateway4": None,
                "route_metric4": None,
                "auto6": True,
                "gateway6": None,
                "route_metric6": None,
                "address": [],
                "route": [],
                "route_append_only": False,
                "rule_append_only": False,
                "dns": [],
                "dns_search": [],
            },
        )

    def _validate_post(self, value, name, result):
        if result["dhcp4"] is None:
            result["dhcp4"] = result["dhcp4_send_hostname"] is not None or not any(
                [a for a in result["address"] if a["family"] == socket.AF_INET]
            )
        if result["auto6"] is None:
            result["auto6"] = not any(
                [a for a in result["address"] if a["family"] == socket.AF_INET6]
            )
        if result["dhcp4_send_hostname"] is not None:
            if not result["dhcp4"]:
                raise ValidationError(
                    name, "'dhcp4_send_hostname' is only valid if 'dhcp4' is enabled"
                )
        return result


class ArgValidator_DictEthernet(ArgValidatorDict):
    def __init__(self):
        ArgValidatorDict.__init__(
            self,
            name="ethernet",
            nested=[
                ArgValidatorBool("autoneg", default_value=None),
                ArgValidatorNum(
                    "speed", val_min=0, val_max=0xFFFFFFFF, default_value=0
                ),
                ArgValidatorStr(
                    "duplex", enum_values=["half", "full"], default_value=None
                ),
            ],
            default_value=ArgValidator.MISSING,
        )

    def get_default_ethernet(self):
        return dict([(k, v.default_value) for k, v in self.nested.items()])

    def _validate_post(self, value, name, result):
        has_speed_or_duplex = result["speed"] != 0 or result["duplex"] is not None
        if result["autoneg"] is None:
            if has_speed_or_duplex:
                result["autoneg"] = False
        elif result["autoneg"]:
            if has_speed_or_duplex:
                raise ValidationError(
                    name,
                    "cannot specify '%s' with 'autoneg' enabled"
                    % ("duplex" if result["duplex"] is not None else "speed"),
                )
        else:
            if not has_speed_or_duplex:
                raise ValidationError(
                    name, "need to specify 'duplex' and 'speed' with 'autoneg' enabled"
                )
        if has_speed_or_duplex and (result["speed"] == 0 or result["duplex"] is None):
            raise ValidationError(
                name,
                "need to specify both 'speed' and 'duplex' with 'autoneg' disabled",
            )
        return result


class ArgValidator_DictEthtool(ArgValidatorDict):
    def __init__(self):
        ArgValidatorDict.__init__(
            self,
            name="ethtool",
            nested=[ArgValidator_DictEthtoolFeatures()],
            default_value=ArgValidator.MISSING,
        )

        self.default_value = dict(
            [(k, v.default_value) for k, v in self.nested.items()]
        )


class ArgValidator_DictEthtoolFeatures(ArgValidatorDict):
    # List of features created with:
    # nmcli connection modify "virbr0" ethtool.feature- on |& \
    #   sed -e 's_[,:]_\n_g'  | \ # split output in newlines
    #   grep ^\ f | \ # select only lines starting with " f"
    #   tr -d " ." | \ # remove spaces and fullstops
    #   sed -e 's,feature-,ArgValidatorBool(",' \ # add Python code
    #       -e 's/$/", default_value=None)],/'
    def __init__(self):
        ArgValidatorDict.__init__(
            self,
            name="features",
            nested=[
                ArgValidatorBool("esp_hw_offload", default_value=None),
                ArgValidatorDeprecated(
                    "esp-hw-offload", deprecated_by="esp_hw_offload"
                ),
                ArgValidatorBool("esp_tx_csum_hw_offload", default_value=None),
                ArgValidatorDeprecated(
                    "esp-tx-csum-hw-offload",
                    deprecated_by="esp_tx_csum_hw_offload",
                ),
                ArgValidatorBool("fcoe_mtu", default_value=None),
                ArgValidatorDeprecated("fcoe-mtu", deprecated_by="fcoe_mtu"),
                ArgValidatorBool("gro", default_value=None),
                ArgValidatorBool("gso", default_value=None),
                ArgValidatorBool("highdma", default_value=None),
                ArgValidatorBool("hw_tc_offload", default_value=None),
                ArgValidatorDeprecated("hw-tc-offload", deprecated_by="hw_tc_offload"),
                ArgValidatorBool("l2_fwd_offload", default_value=None),
                ArgValidatorDeprecated(
                    "l2-fwd-offload", deprecated_by="l2_fwd_offload"
                ),
                ArgValidatorBool("loopback", default_value=None),
                ArgValidatorBool("lro", default_value=None),
                ArgValidatorBool("ntuple", default_value=None),
                ArgValidatorBool("rx", default_value=None),
                ArgValidatorBool("rxhash", default_value=None),
                ArgValidatorBool("rxvlan", default_value=None),
                ArgValidatorBool("rx_all", default_value=None),
                ArgValidatorDeprecated("rx-all", deprecated_by="rx_all"),
                ArgValidatorBool("rx_fcs", default_value=None),
                ArgValidatorDeprecated("rx-fcs", deprecated_by="rx_fcs"),
                ArgValidatorBool("rx_gro_hw", default_value=None),
                ArgValidatorDeprecated("rx-gro-hw", deprecated_by="rx_gro_hw"),
                ArgValidatorBool("rx_udp_tunnel_port_offload", default_value=None),
                ArgValidatorDeprecated(
                    "rx-udp_tunnel-port-offload",
                    deprecated_by="rx_udp_tunnel_port_offload",
                ),
                ArgValidatorBool("rx_vlan_filter", default_value=None),
                ArgValidatorDeprecated(
                    "rx-vlan-filter", deprecated_by="rx_vlan_filter"
                ),
                ArgValidatorBool("rx_vlan_stag_filter", default_value=None),
                ArgValidatorDeprecated(
                    "rx-vlan-stag-filter",
                    deprecated_by="rx_vlan_stag_filter",
                ),
                ArgValidatorBool("rx_vlan_stag_hw_parse", default_value=None),
                ArgValidatorDeprecated(
                    "rx-vlan-stag-hw-parse",
                    deprecated_by="rx_vlan_stag_hw_parse",
                ),
                ArgValidatorBool("sg", default_value=None),
                ArgValidatorBool("tls_hw_record", default_value=None),
                ArgValidatorDeprecated("tls-hw-record", deprecated_by="tls_hw_record"),
                ArgValidatorBool("tls_hw_tx_offload", default_value=None),
                ArgValidatorDeprecated(
                    "tls-hw-tx-offload",
                    deprecated_by="tls_hw_tx_offload",
                ),
                ArgValidatorBool("tso", default_value=None),
                ArgValidatorBool("tx", default_value=None),
                ArgValidatorBool("txvlan", default_value=None),
                ArgValidatorBool("tx_checksum_fcoe_crc", default_value=None),
                ArgValidatorDeprecated(
                    "tx-checksum-fcoe-crc",
                    deprecated_by="tx_checksum_fcoe_crc",
                ),
                ArgValidatorBool("tx_checksum_ipv4", default_value=None),
                ArgValidatorDeprecated(
                    "tx-checksum-ipv4",
                    deprecated_by="tx_checksum_ipv4",
                ),
                ArgValidatorBool("tx_checksum_ipv6", default_value=None),
                ArgValidatorDeprecated(
                    "tx-checksum-ipv6",
                    deprecated_by="tx_checksum_ipv6",
                ),
                ArgValidatorBool("tx_checksum_ip_generic", default_value=None),
                ArgValidatorDeprecated(
                    "tx-checksum-ip-generic",
                    deprecated_by="tx_checksum_ip_generic",
                ),
                ArgValidatorBool("tx_checksum_sctp", default_value=None),
                ArgValidatorDeprecated(
                    "tx-checksum-sctp",
                    deprecated_by="tx_checksum_sctp",
                ),
                ArgValidatorBool("tx_esp_segmentation", default_value=None),
                ArgValidatorDeprecated(
                    "tx-esp-segmentation",
                    deprecated_by="tx_esp_segmentation",
                ),
                ArgValidatorBool("tx_fcoe_segmentation", default_value=None),
                ArgValidatorDeprecated(
                    "tx-fcoe-segmentation",
                    deprecated_by="tx_fcoe_segmentation",
                ),
                ArgValidatorBool("tx_gre_csum_segmentation", default_value=None),
                ArgValidatorDeprecated(
                    "tx-gre-csum-segmentation",
                    deprecated_by="tx_gre_csum_segmentation",
                ),
                ArgValidatorBool("tx_gre_segmentation", default_value=None),
                ArgValidatorDeprecated(
                    "tx-gre-segmentation",
                    deprecated_by="tx_gre_segmentation",
                ),
                ArgValidatorBool("tx_gso_partial", default_value=None),
                ArgValidatorDeprecated(
                    "tx-gso-partial", deprecated_by="tx_gso_partial"
                ),
                ArgValidatorBool("tx_gso_robust", default_value=None),
                ArgValidatorDeprecated("tx-gso-robust", deprecated_by="tx_gso_robust"),
                ArgValidatorBool("tx_ipxip4_segmentation", default_value=None),
                ArgValidatorDeprecated(
                    "tx-ipxip4-segmentation",
                    deprecated_by="tx_ipxip4_segmentation",
                ),
                ArgValidatorBool("tx_ipxip6_segmentation", default_value=None),
                ArgValidatorDeprecated(
                    "tx-ipxip6-segmentation",
                    deprecated_by="tx_ipxip6_segmentation",
                ),
                ArgValidatorBool("tx_nocache_copy", default_value=None),
                ArgValidatorDeprecated(
                    "tx-nocache-copy",
                    deprecated_by="tx_nocache_copy",
                ),
                ArgValidatorBool("tx_scatter_gather", default_value=None),
                ArgValidatorDeprecated(
                    "tx-scatter-gather",
                    deprecated_by="tx_scatter_gather",
                ),
                ArgValidatorBool("tx_scatter_gather_fraglist", default_value=None),
                ArgValidatorDeprecated(
                    "tx-scatter-gather-fraglist",
                    deprecated_by="tx_scatter_gather_fraglist",
                ),
                ArgValidatorBool("tx_sctp_segmentation", default_value=None),
                ArgValidatorDeprecated(
                    "tx-sctp-segmentation",
                    deprecated_by="tx_sctp_segmentation",
                ),
                ArgValidatorBool("tx_tcp6_segmentation", default_value=None),
                ArgValidatorDeprecated(
                    "tx-tcp6-segmentation",
                    deprecated_by="tx_tcp6_segmentation",
                ),
                ArgValidatorBool("tx_tcp_ecn_segmentation", default_value=None),
                ArgValidatorDeprecated(
                    "tx-tcp-ecn-segmentation",
                    deprecated_by="tx_tcp_ecn_segmentation",
                ),
                ArgValidatorBool("tx_tcp_mangleid_segmentation", default_value=None),
                ArgValidatorDeprecated(
                    "tx-tcp-mangleid-segmentation",
                    deprecated_by="tx_tcp_mangleid_segmentation",
                ),
                ArgValidatorBool("tx_tcp_segmentation", default_value=None),
                ArgValidatorDeprecated(
                    "tx-tcp-segmentation",
                    deprecated_by="tx_tcp_segmentation",
                ),
                ArgValidatorBool("tx_udp_segmentation", default_value=None),
                ArgValidatorDeprecated(
                    "tx-udp-segmentation",
                    deprecated_by="tx_udp_segmentation",
                ),
                ArgValidatorBool("tx_udp_tnl_csum_segmentation", default_value=None),
                ArgValidatorDeprecated(
                    "tx-udp_tnl-csum-segmentation",
                    deprecated_by="tx_udp_tnl_csum_segmentation",
                ),
                ArgValidatorBool("tx_udp_tnl_segmentation", default_value=None),
                ArgValidatorDeprecated(
                    "tx-udp_tnl-segmentation",
                    deprecated_by="tx_udp_tnl_segmentation",
                ),
                ArgValidatorBool("tx_vlan_stag_hw_insert", default_value=None),
                ArgValidatorDeprecated(
                    "tx-vlan-stag-hw-insert",
                    deprecated_by="tx_vlan_stag_hw_insert",
                ),
            ],
        )
        self.default_value = dict(
            [
                (name, validator.default_value)
                for name, validator in self.nested.items()
                if not isinstance(validator, ArgValidatorDeprecated)
            ]
        )


class ArgValidator_DictBond(ArgValidatorDict):

    VALID_MODES = [
        "balance-rr",
        "active-backup",
        "balance-xor",
        "broadcast",
        "802.3ad",
        "balance-tlb",
        "balance-alb",
    ]

    def __init__(self):
        ArgValidatorDict.__init__(
            self,
            name="bond",
            nested=[
                ArgValidatorStr("mode", enum_values=ArgValidator_DictBond.VALID_MODES),
                ArgValidatorNum(
                    "miimon", val_min=0, val_max=1000000, default_value=None
                ),
            ],
            default_value=ArgValidator.MISSING,
        )

    def get_default_bond(self):
        return {"mode": ArgValidator_DictBond.VALID_MODES[0], "miimon": None}


class ArgValidator_DictInfiniband(ArgValidatorDict):
    def __init__(self):
        ArgValidatorDict.__init__(
            self,
            name="infiniband",
            nested=[
                ArgValidatorStr(
                    "transport_mode", enum_values=["datagram", "connected"]
                ),
                ArgValidatorNum("p_key", val_min=-1, val_max=0xFFFF, default_value=-1),
            ],
            default_value=ArgValidator.MISSING,
        )

    def get_default_infiniband(self):
        return {"transport_mode": "datagram", "p_key": -1}


class ArgValidator_DictVlan(ArgValidatorDict):
    def __init__(self):
        ArgValidatorDict.__init__(
            self,
            name="vlan",
            nested=[ArgValidatorNum("id", val_min=0, val_max=4094, required=True)],
            default_value=ArgValidator.MISSING,
        )

    def get_default_vlan(self):
        return {"id": None}


class ArgValidator_DictMacvlan(ArgValidatorDict):

    VALID_MODES = ["vepa", "bridge", "private", "passthru", "source"]

    def __init__(self):
        ArgValidatorDict.__init__(
            self,
            name="macvlan",
            nested=[
                ArgValidatorStr(
                    "mode",
                    enum_values=ArgValidator_DictMacvlan.VALID_MODES,
                    default_value="bridge",
                ),
                ArgValidatorBool("promiscuous", default_value=True),
                ArgValidatorBool("tap", default_value=False),
            ],
            default_value=ArgValidator.MISSING,
        )

    def get_default_macvlan(self):
        return {"mode": "bridge", "promiscuous": True, "tap": False}

    def _validate_post(self, value, name, result):
        if result["promiscuous"] is False and result["mode"] != "passthru":
            raise ValidationError(
                name, "non promiscuous operation is allowed only in passthru mode"
            )
        return result


class ArgValidatorPath(ArgValidatorStr):
    """
    Valides that the value is a valid posix absolute path
    """

    def __init__(self, name, required=False, default_value=None):
        ArgValidatorStr.__init__(self, name, required, default_value, None)

    def _validate_impl(self, value, name):
        ArgValidatorStr._validate_impl(self, value, name)

        if posixpath.isabs(value) is False:
            raise ValidationError(
                name,
                "value '%s' is not a valid posix absolute path" % (value),
            )
        return value


class ArgValidator_Dict802_1X(ArgValidatorDict):

    VALID_EAP_TYPES = ["tls"]

    VALID_PRIVATE_KEY_FLAGS = ["none", "agent-owned", "not-saved", "not-required"]

    def __init__(self):
        ArgValidatorDict.__init__(
            self,
            name="ieee802_1x",
            nested=[
                ArgValidatorStr(
                    "eap",
                    enum_values=ArgValidator_Dict802_1X.VALID_EAP_TYPES,
                    default_value="tls",
                ),
                ArgValidatorStr("identity", required=True),
                ArgValidatorPath("private_key", required=True),
                ArgValidatorStr("private_key_password"),
                ArgValidatorList(
                    "private_key_password_flags",
                    nested=ArgValidatorStr(
                        "private_key_password_flags[?]",
                        enum_values=ArgValidator_Dict802_1X.VALID_PRIVATE_KEY_FLAGS,
                    ),
                    default_value=None,
                ),
                ArgValidatorPath("client_cert", required=True),
                ArgValidatorPath("ca_cert"),
                ArgValidatorPath("ca_path"),
                ArgValidatorBool("system_ca_certs", default_value=False),
                ArgValidatorStr("domain_suffix_match", required=False),
            ],
            default_value=None,
        )

    def _validate_post(self, value, name, result):
        if result["system_ca_certs"] is True and result["ca_path"] is not None:
            raise ValidationError(
                name,
                "ca_path will be ignored by NetworkManager if system_ca_certs is used",
            )
        return result


class ArgValidator_DictWireless(ArgValidatorDict):

    VALID_KEY_MGMT = [
        "wpa-psk",
        "wpa-eap",
    ]

    def __init__(self):
        ArgValidatorDict.__init__(
            self,
            name="wireless",
            nested=[
                ArgValidatorStr("ssid", max_length=32),
                ArgValidatorStr(
                    "key_mgmt", enum_values=ArgValidator_DictWireless.VALID_KEY_MGMT
                ),
                ArgValidatorStr("password", default_value=None, max_length=63),
            ],
            default_value=None,
        )

    def _validate_post(self, value, name, result):
        if result["key_mgmt"] == "wpa-psk":
            if result["password"] is None:
                raise ValidationError(
                    name,
                    "must supply a password if using 'wpa-psk' key management",
                )
        else:
            if result["password"] is not None:
                raise ValidationError(
                    name,
                    "password only allowed if using 'wpa-psk' key management",
                )

        return result


class ArgValidator_DictConnection(ArgValidatorDict):

    VALID_PERSISTENT_STATES = ["absent", "present"]
    VALID_STATES = VALID_PERSISTENT_STATES + ["up", "down"]
    VALID_TYPES = [
        "ethernet",
        "infiniband",
        "bridge",
        "team",
        "bond",
        "vlan",
        "macvlan",
        "wireless",
    ]
    VALID_SLAVE_TYPES = ["bridge", "bond", "team"]

    def __init__(self):
        ArgValidatorDict.__init__(
            self,
            name="connection",
            nested=[
                ArgValidatorStr("name"),
                ArgValidatorStr(
                    "state", enum_values=ArgValidator_DictConnection.VALID_STATES
                ),
                ArgValidatorStr(
                    "persistent_state",
                    enum_values=ArgValidator_DictConnection.VALID_PERSISTENT_STATES,
                ),
                ArgValidatorBool("force_state_change", default_value=None),
                ArgValidatorNum(
                    "wait",
                    val_min=0,
                    val_max=3600,
                    numeric_type=float,
                    default_value=None,
                ),
                ArgValidatorStr(
                    "type", enum_values=ArgValidator_DictConnection.VALID_TYPES
                ),
                ArgValidatorBool("autoconnect", default_value=True),
                ArgValidatorStr(
                    "slave_type",
                    enum_values=ArgValidator_DictConnection.VALID_SLAVE_TYPES,
                ),
                ArgValidatorStr("master"),
                ArgValidatorStr("interface_name", allow_empty=True),
                ArgValidatorMac("mac"),
                ArgValidatorNum(
                    "mtu", val_min=0, val_max=0xFFFFFFFF, default_value=None
                ),
                ArgValidatorStr("zone"),
                ArgValidatorBool("check_iface_exists", default_value=True),
                ArgValidatorStr("parent"),
                ArgValidatorBool("ignore_errors", default_value=None),
                ArgValidator_DictIP(),
                ArgValidator_DictEthernet(),
                ArgValidator_DictEthtool(),
                ArgValidator_DictBond(),
                ArgValidator_DictInfiniband(),
                ArgValidator_DictVlan(),
                ArgValidator_DictMacvlan(),
                ArgValidator_Dict802_1X(),
                ArgValidator_DictWireless(),
                # deprecated options:
                ArgValidatorStr(
                    "infiniband_transport_mode",
                    enum_values=["datagram", "connected"],
                    default_value=ArgValidator.MISSING,
                ),
                ArgValidatorNum(
                    "infiniband_p_key",
                    val_min=-1,
                    val_max=0xFFFF,
                    default_value=ArgValidator.MISSING,
                ),
                ArgValidatorNum(
                    "vlan_id",
                    val_min=0,
                    val_max=4094,
                    default_value=ArgValidator.MISSING,
                ),
            ],
            default_value=dict,
            all_missing_during_validate=True,
        )

        # valid field based on specified state, used to set defaults and reject
        # bad values
        self.VALID_FIELDS = []

    def _validate_post_state(self, value, name, result):
        """
        Validate state definitions and create a corresponding list of actions.
        """
        actions = []
        state = result.get("state")
        persistent_state = result.get("persistent_state")

        if state in self.VALID_PERSISTENT_STATES:
            if persistent_state:
                raise ValidationError(
                    name,
                    "State cannot be '{0}' if persistent_state is specified".format(
                        state
                    ),
                )
            persistent_state = state
            state = None

        # default persistent_state to present (not done via default_value in the
        # ArgValidatorStr, the value will only be set at the end of
        # _validate_post()
        if not persistent_state:
            persistent_state = "present"

        # If the profile should be absent at the end, it needs to be present in
        # the meantime to allow to (de)activate it. This is only possible if it
        # is completely defined, for which `type` needs to be specified.
        # Otherwise, downing is happening on a best-effort basis
        if persistent_state == "absent" and state and result.get("type"):
            actions.append("present")

        actions.append(persistent_state)

        # Change the runtime state if necessary
        if state:
            actions.append(state)

        result["state"] = state
        result["persistent_state"] = persistent_state
        result["actions"] = actions

        return result

    def _validate_post_fields(self, value, name, result):
        """
        Validate the allowed fields (settings depending on the requested state).
        FIXME: Maybe it should check whether "up"/"down" is present in the
        actions instead of checking the runtime state from "state" to switch
        from state to actions after the state parsing is done.
        """
        state = result.get("state")
        persistent_state = result.get("persistent_state")

        # minimal settings not related to runtime changes
        valid_fields = ["actions", "ignore_errors", "name", "persistent_state", "state"]

        # when type is present, a profile is completely specified (using
        # defaults or other settings)
        if "type" in result:
            valid_fields += list(self.nested.keys())

        # If there are no runtime changes, "wait" and "force_state_change" do
        # not make sense
        # FIXME: Maybe this restriction can be removed. Need to make sure that
        # defaults for wait or force_state_change do not interfer
        if not state:
            while "wait" in valid_fields:
                valid_fields.remove("wait")
            while "force_state_change" in valid_fields:
                valid_fields.remove("force_state_change")
        else:
            valid_fields += ["force_state_change", "wait"]

        # FIXME: Maybe just accept all values, even if they are not
        # needed/meaningful in the respective context
        valid_fields = set(valid_fields)
        for k in result:
            if k not in valid_fields:
                raise ValidationError(
                    name + "." + k,
                    "property is not allowed for state '%s' and persistent_state '%s'"
                    % (state, persistent_state),
                )

        if "name" not in result:
            if persistent_state == "absent":
                result["name"] = ""  # set to empty string to mean *absent all others*
            else:
                raise ValidationError(name, "missing 'name'")

        # FIXME: Seems to be a duplicate check since "wait" will be removed from
        # valid_keys when state is considered to be not True
        if "wait" in result and not state:
            raise ValidationError(
                name + ".wait",
                "'wait' is not allowed for state '%s'" % (result["state"]),
            )

        result["state"] = state
        result["persistent_state"] = persistent_state

        self.VALID_FIELDS = valid_fields
        return result

    def _validate_post_wireless(self, value, name, result):
        """
        Validate wireless settings
        """
        if "type" in result:
            if result["type"] == "wireless":
                if "wireless" in result:
                    if (
                        result["wireless"]["key_mgmt"] == "wpa-eap"
                        and "ieee802_1x" not in result
                    ):
                        raise ValidationError(
                            name + ".wireless",
                            "key management set to wpa-eap but no "
                            "'ieee802_1x' settings defined",
                        )
                else:
                    raise ValidationError(
                        name + ".wireless",
                        "must define 'wireless' settings for 'type' 'wireless'",
                    )

            else:
                if "wireless" in result:
                    raise ValidationError(
                        name + ".wireless",
                        "'wireless' settings are not allowed for 'type' '%s'"
                        % (result["type"]),
                    )

        return result

    def _validate_post(self, value, name, result):
        result = self._validate_post_state(value, name, result)
        result = self._validate_post_fields(value, name, result)
        result = self._validate_post_wireless(value, name, result)

        if "type" in result:

            if "master" in result:
                if "slave_type" not in result:
                    result["slave_type"] = None
                if result["master"] == result["name"]:
                    raise ValidationError(
                        name + ".master", '"master" cannot refer to itself'
                    )
            else:
                if "slave_type" in result:
                    raise ValidationError(
                        name + ".slave_type",
                        "'slave_type' requires a 'master' property",
                    )

            if "ip" in result:
                if "master" in result:
                    raise ValidationError(
                        name + ".ip", 'a slave cannot have an "ip" property'
                    )
            else:
                if "master" not in result:
                    result["ip"] = self.nested["ip"].get_default_value()

            if "zone" in result:
                if "master" in result:
                    raise ValidationError(
                        name + ".zone", '"zone" cannot be configured for slave types'
                    )
            else:
                result["zone"] = None

            if "mac" in result:
                if result["type"] not in ["ethernet", "infiniband"]:
                    raise ValidationError(
                        name + ".mac",
                        "a 'mac' address is only allowed for type 'ethernet' "
                        "or 'infiniband'",
                    )
                maclen = len(Util.mac_aton(result["mac"]))
                if result["type"] == "ethernet" and maclen != 6:
                    raise ValidationError(
                        name + ".mac",
                        "a 'mac' address for type ethernet requires 6 octets "
                        "but is '%s'" % result["mac"],
                    )
                if result["type"] == "infiniband" and maclen != 20:
                    raise ValidationError(
                        name + ".mac",
                        "a 'mac' address for type ethernet requires 20 octets "
                        "but is '%s'" % result["mac"],
                    )

            if result["type"] == "infiniband":
                if "infiniband" not in result:
                    result["infiniband"] = self.nested[
                        "infiniband"
                    ].get_default_infiniband()
                    if "infiniband_transport_mode" in result:
                        result["infiniband"]["transport_mode"] = result[
                            "infiniband_transport_mode"
                        ]
                        del result["infiniband_transport_mode"]
                    if "infiniband_p_key" in result:
                        result["infiniband"]["p_key"] = result["infiniband_p_key"]
                        del result["infiniband_p_key"]
                else:
                    if "infiniband_transport_mode" in result:
                        raise ValidationError(
                            name + ".infiniband_transport_mode",
                            "cannot mix deprecated 'infiniband_transport_mode' "
                            "property with 'infiniband' settings",
                        )
                    if "infiniband_p_key" in result:
                        raise ValidationError(
                            name + ".infiniband_p_key",
                            "cannot mix deprecated 'infiniband_p_key' property "
                            "with 'infiniband' settings",
                        )
                    if result["infiniband"]["transport_mode"] is None:
                        result["infiniband"]["transport_mode"] = "datagram"
                if result["infiniband"]["p_key"] != -1:
                    if "mac" not in result and "parent" not in result:
                        raise ValidationError(
                            name + ".infiniband.p_key",
                            "a infiniband device with 'infiniband.p_key' "
                            "property also needs 'mac' or 'parent' property",
                        )
            else:
                if "infiniband" in result:
                    raise ValidationError(
                        name + ".infiniband",
                        "'infiniband' settings are only allowed for type 'infiniband'",
                    )
                if "infiniband_transport_mode" in result:
                    raise ValidationError(
                        name + ".infiniband_transport_mode",
                        "a 'infiniband_transport_mode' property is only "
                        "allowed for type 'infiniband'",
                    )
                if "infiniband_p_key" in result:
                    raise ValidationError(
                        name + ".infiniband_p_key",
                        "a 'infiniband_p_key' property is only allowed for "
                        "type 'infiniband'",
                    )

            if "interface_name" in result:
                # Ignore empty interface_name
                if result["interface_name"] == "":
                    del result["interface_name"]
                elif not Util.ifname_valid(result["interface_name"]):
                    raise ValidationError(
                        name + ".interface_name",
                        "invalid 'interface_name' '%s'" % (result["interface_name"]),
                    )
            else:
                if not result.get("mac"):
                    if not Util.ifname_valid(result["name"]):
                        raise ValidationError(
                            name + ".interface_name",
                            "'interface_name' as 'name' '%s' is not valid"
                            % (result["name"]),
                        )
                    result["interface_name"] = result["name"]

            if "interface_name" not in result and result["type"] in [
                "bond",
                "bridge",
                "macvlan",
                "team",
                "vlan",
            ]:
                raise ValidationError(
                    name + ".interface_name",
                    "type '%s' requires 'interface_name'" % (result["type"]),
                )

            if result["type"] == "vlan":
                if "vlan" not in result:
                    if "vlan_id" not in result:
                        raise ValidationError(
                            name + ".vlan", 'missing "vlan" settings for "type" "vlan"'
                        )
                    result["vlan"] = self.nested["vlan"].get_default_vlan()
                    result["vlan"]["id"] = result["vlan_id"]
                    del result["vlan_id"]
                else:
                    if "vlan_id" in result:
                        raise ValidationError(
                            name + ".vlan_id",
                            "don't use the deprecated 'vlan_id' together with the "
                            "'vlan' settings'",
                        )
                if "parent" not in result:
                    raise ValidationError(
                        name + ".parent", 'missing "parent" for "type" "vlan"'
                    )
            else:
                if "vlan" in result:
                    raise ValidationError(
                        name + ".vlan", '"vlan" is only allowed for "type" "vlan"'
                    )
                if "vlan_id" in result:
                    raise ValidationError(
                        name + ".vlan_id", '"vlan_id" is only allowed for "type" "vlan"'
                    )

            if "parent" in result:
                if result["type"] not in ["vlan", "macvlan", "infiniband"]:
                    raise ValidationError(
                        name + ".parent",
                        "'parent' is only allowed for type 'vlan', 'macvlan' or "
                        "'infiniband'",
                    )
                if result["parent"] == result["name"]:
                    raise ValidationError(
                        name + ".parent", '"parent" cannot refer to itself'
                    )

            if result["type"] == "bond":
                if "bond" not in result:
                    result["bond"] = self.nested["bond"].get_default_bond()
            else:
                if "bond" in result:
                    raise ValidationError(
                        name + ".bond",
                        "'bond' settings are not allowed for 'type' '%s'"
                        % (result["type"]),
                    )

            if result["type"] in ["ethernet", "vlan", "bridge", "bond", "team"]:
                if "ethernet" not in result:
                    result["ethernet"] = self.nested["ethernet"].get_default_ethernet()
            else:
                if "ethernet" in result:
                    raise ValidationError(
                        name + ".ethernet",
                        "'ethernet' settings are not allowed for 'type' '%s'"
                        % (result["type"]),
                    )

            if result["type"] == "macvlan":
                if "macvlan" not in result:
                    result["macvlan"] = self.nested["macvlan"].get_default_macvlan()
            else:
                if "macvlan" in result:
                    raise ValidationError(
                        name + ".macvlan",
                        "'macvlan' settings are not allowed for 'type' '%s'"
                        % (result["type"]),
                    )

            if "ieee802_1x" in result and result["type"] not in [
                "ethernet",
                "wireless",
            ]:
                raise ValidationError(
                    name + ".ieee802_1x",
                    "802.1x settings only allowed for ethernet or wireless interfaces.",
                )

        for k in self.VALID_FIELDS:
            if k in result:
                continue
            v = self.nested[k]
            vv = v.get_default_value()
            if vv is not ArgValidator.MISSING:
                result[k] = vv

        return result


class ArgValidator_ListConnections(ArgValidatorList):
    def __init__(self):
        ArgValidatorList.__init__(
            self,
            name="connections",
            nested=ArgValidator_DictConnection(),
            default_value=list,
        )

    def _validate_post(self, value, name, result):
        for idx, connection in enumerate(result):
            if "type" in connection:
                if connection["master"]:
                    c = ArgUtil.connection_find_by_name(
                        connection["master"], result, idx
                    )
                    if not c:
                        raise ValidationError(
                            name + "[" + str(idx) + "].master",
                            "references non-existing 'master' connection '%s'"
                            % (connection["master"]),
                        )
                    if c["type"] not in ArgValidator_DictConnection.VALID_SLAVE_TYPES:
                        raise ValidationError(
                            name + "[" + str(idx) + "].master",
                            "references 'master' connection '%s' which is not a master "
                            "type by '%s'" % (connection["master"], c["type"]),
                        )
                    if connection["slave_type"] is None:
                        connection["slave_type"] = c["type"]
                    elif connection["slave_type"] != c["type"]:
                        raise ValidationError(
                            name + "[" + str(idx) + "].master",
                            "references 'master' connection '%s' which is of type '%s' "
                            "instead of slave_type '%s'"
                            % (
                                connection["master"],
                                c["type"],
                                connection["slave_type"],
                            ),
                        )
                if connection["parent"]:
                    if not ArgUtil.connection_find_by_name(
                        connection["parent"], result, idx
                    ):
                        raise ValidationError(
                            name + "[" + str(idx) + "].parent",
                            "references non-existing 'parent' connection '%s'"
                            % (connection["parent"]),
                        )
        return result

    VALIDATE_ONE_MODE_NM = "nm"
    VALIDATE_ONE_MODE_INITSCRIPTS = "initscripts"

    def validate_connection_one(self, mode, connections, idx):
        connection = connections[idx]
        if "type" not in connection:
            return

        if (connection["parent"]) and (
            (
                (mode == self.VALIDATE_ONE_MODE_INITSCRIPTS)
                and (connection["type"] == "vlan")
            )
            or (
                (connection["type"] == "infiniband")
                and (connection["infiniband"]["p_key"] != -1)
            )
        ):
            try:
                ArgUtil.connection_find_master(connection["parent"], connections, idx)
            except MyError:
                raise ValidationError.from_connection(
                    idx,
                    "profile references a parent '%s' which has 'interface_name' "
                    "missing" % (connection["parent"]),
                )

        if (connection["master"]) and (mode == self.VALIDATE_ONE_MODE_INITSCRIPTS):
            try:
                ArgUtil.connection_find_master(connection["master"], connections, idx)
            except MyError:
                raise ValidationError.from_connection(
                    idx,
                    "profile references a master '%s' which has 'interface_name' "
                    "missing" % (connection["master"]),
                )

        # check if 802.1x connection is valid
        if connection["ieee802_1x"]:
            if mode == self.VALIDATE_ONE_MODE_INITSCRIPTS:
                raise ValidationError.from_connection(
                    idx,
                    "802.1x authentication is not supported by initscripts. "
                    "Configure 802.1x in /etc/wpa_supplicant.conf "
                    "if you need to use initscripts.",
                )

        # check if wireless connection is valid
        if connection["type"] == "wireless":
            if mode == self.VALIDATE_ONE_MODE_INITSCRIPTS:
                raise ValidationError.from_connection(
                    idx,
                    "Wireless WPA auth is not supported by initscripts. "
                    "Configure wireless connection in /etc/wpa_supplicant.conf "
                    "if you need to use initscripts.",
                )
