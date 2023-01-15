# vim: fileencoding=utf8
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os
import posixpath
import socket
import re

# pylint: disable=import-error, no-name-in-module
from ansible.module_utils.network_lsr.myerror import MyError  # noqa:E501
from ansible.module_utils.network_lsr.utils import Util  # noqa:E501

UINT32_MAX = 0xFFFFFFFF


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
    def connection_find_controller(name, connections, n_connections=None):
        c = ArgUtil.connection_find_by_name(name, connections, n_connections)
        if not c:
            raise MyError("invalid controller/parent '%s'" % (name))
        if c["interface_name"] is None:
            raise MyError(
                "invalid controller/parent '%s' which needs an 'interface_name'"
                % (name)
            )
        if not Util.ifname_valid(c["interface_name"]):
            raise MyError(
                "invalid controller/parent '%s' with invalid 'interface_name' ('%s')"
                % (name, c["interface_name"])
            )
        return c["interface_name"]

    @staticmethod
    def connection_find_controller_uuid(name, connections, n_connections=None):
        c = ArgUtil.connection_find_by_name(name, connections, n_connections)
        if not c:
            raise MyError("invalid controller/parent '%s'" % (name))
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
        # pylint: disable=non-parent-init-called
        super(ValidationError, self).__init__(name + ": " + message)
        self.error_message = message
        self.name = name

    @staticmethod
    def from_connection(idx, message):
        return ValidationError("connection[" + str(idx) + "]", message)


class ArgValidator:
    MISSING = object()
    DEFAULT = object()

    def __init__(self, name=None, required=False, default_value=None):
        self.name = name
        self.required = required
        self._default_value = default_value

    def get_default_value(self):
        if callable(self._default_value):
            return self._default_value()
        return self._default_value

    def validate(self, value):
        """
        Validate and normalize the input dictionary

        This validate @value or raises a ValidationError() on error.
        It also returns a normalized value, where the settings are
        converted to appropriate types and default values set. You
        should rely on the normalization to fill unspecified values
        and resolve ambiguity.

        You are implementing "types" of ArgValidator instances and
        a major point of them is to implement a suitable validation and
        normalization. The means for that is for subclasses to override
        _validate_impl() and possibly _validate_post(). Some subclasses
        support convenience arguments for simpler validation, like
        ArgValidatorStr.enum_values or ArgValidatorNum.val_min.
        Or ArgValidator.required which is honored by ArgValidatorDict
        to determine whether a mandatory key is missing. Also,
        ArgValidatorDict and ArgValidatorList have a nested parameter
        which is an ArgValidator for the elements of the dictionary and list.
        """
        return self._validate(value, self.name)

    def _validate(self, value, name):
        """
        The internal implementation for validate().

        This is mostly called from internal code and by validate().
        Usually you would not call this directly nor override it.
        Instead, you would implement either _validate_impl() or
        _validate_post().
        """
        validated = self._validate_impl(value, name)
        return self._validate_post(value, name, validated)

    def _validate_impl(self, value, name):
        """
        Implementation of validation.

        Subclasses must implement this validation function. It is
        the main hook to implement validate(). On validation error
        it must raise ValidationError() or otherwise return a pre-normalized
        value that gets passed to _validate_post().
        """
        raise NotImplementedError()

    # pylint: disable=unused-argument,no-self-use
    def _validate_post(self, value, name, result):
        """
        Post validation of the validated result.

        This will be called with the result from _validate_impl().
        By default it does nothing, but subclasses can override
        this to perform additional validation. The use for this
        hook is to split the validation in two steps. When validating
        a dictionary of multiple keys, then _validate_impl() can
        implement the basic pre-validation and pre-normalization of the individual
        keys (which can be in any order). Afterwards, _validate_post()
        can take a more holistic view and validate interdependencies
        between keys and perform additional validation. For example,
        _validate_impl() would validate that the keys are of the correct
        basic type, and _validate_post() would validate that the values
        don't conflict and possibly normalize derived default values.
        """
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
        regex=None,
    ):
        ArgValidator.__init__(self, name, required, default_value)
        self.enum_values = enum_values
        self.allow_empty = allow_empty
        self.regex = regex

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
        if self.regex is not None and not any(re.match(x, value) for x in self.regex):
            raise ValidationError(
                name,
                "is '%s' which does not match the regex '%s'"
                % (value, "' '".join(sorted(self.regex))),
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


class ArgValidatorRouteTable(ArgValidator):
    def __init__(
        self,
        name,
        required=False,
        default_value=None,
    ):
        ArgValidator.__init__(self, name, required, default_value)

    def _validate_impl(self, value, name):
        table = None
        try:
            if isinstance(value, bool):
                # bool can (probably) be converted to integer type,
                # but here we don't want to accept a boolean value.
                pass
            elif isinstance(value, int):
                table = int(value)
            elif isinstance(value, Util.STRING_TYPE):
                try:
                    table = int(value)
                except Exception:
                    table = value
        except Exception:
            pass
        if table is None:
            raise ValidationError(
                name,
                "route table must be the named or numeric tables but is {0}".format(
                    value
                ),
            )
        if isinstance(table, int):
            if table < 1:
                raise ValidationError(
                    name,
                    "route table value is {0} but cannot be less than 1".format(value),
                )
            elif table > 0xFFFFFFFF:
                raise ValidationError(
                    name,
                    "route table value is {0} but cannot be greater than 4294967295".format(
                        value
                    ),
                )
        if isinstance(table, Util.STRING_TYPE):
            if table == "":
                raise ValidationError(name, "route table name cannot be empty string")
            if not IPRouteUtils.ROUTE_TABLE_ALIAS_RE.match(table):
                raise ValidationError(
                    name, "route table name contains invalid characters"
                )

        return table


class ArgValidatorNum(ArgValidator):
    def __init__(  # pylint: disable=too-many-arguments
        self,
        name,
        required=False,
        val_min=None,
        val_max=None,
        default_value=ArgValidator.DEFAULT,
        numeric_type=int,
    ):
        if default_value is ArgValidator.DEFAULT:
            default_value = numeric_type(0)
        ArgValidator.__init__(self, name, required, default_value)
        self.val_min = val_min
        self.val_max = val_max
        self.numeric_type = numeric_type

    def _validate_impl(self, value, name):
        v = None
        try:
            if isinstance(value, bool):
                # bool can (probably) be converted to self.numeric_type,
                # but here we don't want to accept a boolean value.
                pass
            elif isinstance(value, self.numeric_type):
                # ArgValidatorNum should normalize the input values to be of type
                # self.numeric_type, except the default_value
                v = self.numeric_type(value)
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


class ArgValidatorRange(ArgValidator):
    def __init__(  # pylint: disable=too-many-arguments
        self,
        name,
        required=False,
        val_min=None,
        val_max=None,
        default_value=None,
    ):
        ArgValidator.__init__(self, name, required, default_value)
        self.val_min = val_min
        self.val_max = val_max

    def _validate_impl(self, value, name):
        range = None
        if isinstance(value, Util.STRING_TYPE):
            match_group = re.match(r"^ *([0-9]+) *- *([0-9]+) *$", value)
            if match_group:
                try:
                    range = (int(match_group.group(1)), int(match_group.group(2)))
                except Exception:
                    pass
            else:
                try:
                    range = (int(value), int(value))
                except Exception:
                    pass
        elif isinstance(value, bool):
            # bool can (probably) be converted to integer type,
            # but here we don't want to accept a boolean value.
            pass
        elif isinstance(value, int):
            range = (value, value)

        if range is None:
            raise ValidationError(name, "the range value {0} is invalid".format(value))
        if range[0] > range[1]:
            raise ValidationError(
                name,
                "the range start cannot be greater than range end",
            )
        if self.val_min is not None:
            if range[0] < self.val_min:
                raise ValidationError(
                    name,
                    "lower range value is {0} but cannot be less than {1}".format(
                        range[0], self.val_min
                    ),
                )
        if self.val_max is not None:
            if range[1] > self.val_max:
                raise ValidationError(
                    name,
                    "upper range value is {0} but cannot be greater than {1}".format(
                        range[1], self.val_max
                    ),
                )

        return range


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


class ArgValidatorDeprecated(ArgValidator):
    """
    ArgValidatorDeprecated is only used as a marker to indicate that a setting is deprecated
    by another setting. The validator that contains a deprecated setting is responsible for
    processing this and the replacement setting needs to perform the validation.
    """

    def __init__(self, name, deprecated_by):
        ArgValidator.__init__(self, name, default_value=ArgValidator.MISSING)
        self.deprecated_by = deprecated_by

    def _validate_impl(self, value, name):
        raise MyError(
            "Deprecated settings need to be validated by the replacement setting."
        )


class ArgValidatorDict(ArgValidator):
    def __init__(
        self,
        name=None,
        required=False,
        nested=None,
        default_value=ArgValidator.DEFAULT,
        all_missing_during_validate=False,
    ):
        if nested is not None:
            nested = dict([(v.name, v) for v in nested])
        else:
            nested = {}
        if default_value is ArgValidator.DEFAULT:
            default_value = self.generate_default
        ArgValidator.__init__(self, name, required, default_value)
        self.nested = nested
        self.all_missing_during_validate = all_missing_during_validate

    def _validate_impl(self, value, name):
        result = {}
        seen_keys = set()
        if value is None:
            # Users might want to use jinja2 templates to set properties. As such,
            # it's convenient to accept None as an alias for an empty dictionary
            # e.g. setting like `"match": None` will be allowed by the role
            return {}
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
                validator = self.nested[setting]
            if setting in seen_keys:
                raise ValidationError(name, "duplicate key '%s'" % (setting))
            seen_keys.add(setting)
            try:
                validated_value = validator._validate(value, name + "." + setting)
            except ValidationError as e:
                raise ValidationError(e.name, e.error_message)
            result[setting] = validated_value
        for (setting, validator) in self.nested.items():
            if setting in seen_keys:
                continue
            if validator.required:
                raise ValidationError(name, "missing required key '%s'" % (setting))
            if not self.all_missing_during_validate:
                default = validator.get_default_value()
                if default is not ArgValidator.MISSING:
                    result[setting] = default
        return result

    @staticmethod
    def generate_default_from_nested(nested):
        result = {}
        for name, validator in nested.items():
            default = validator.get_default_value()
            if default is not ArgValidator.MISSING:
                result[name] = default
        return result

    def generate_default(self):
        return ArgValidatorDict.generate_default_from_nested(self.nested)


class ArgValidatorList(ArgValidator):
    def __init__(
        self,
        name,
        nested,
        default_value=None,
        remove_none_or_empty=False,
    ):
        ArgValidator.__init__(self, name, required=False, default_value=default_value)
        self.nested = nested
        self.remove_none_or_empty = remove_none_or_empty

    def _validate_impl(self, value, name):

        if value is None:
            # Users might want to use jinja2 templates to set properties. As such,
            # it's convenient to accept None as an alias for an empty list
            # e.g. setting like `"match": {"path": None}` will be allowed by the role
            value = []
        elif isinstance(value, Util.STRING_TYPE):
            # we expect a list. However, for convenience allow to
            # specify a string, separated by space. Escaping is
            # not supported. If you need that, define a proper list.
            value = [s for s in value.split(" ") if s]

        result = []
        for (idx, v) in enumerate(value):
            if (v is None or v == "") and self.remove_none_or_empty:
                continue
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
    def __init__(
        self, name, force_len=None, required=False, default_value=None, enum_values=None
    ):
        ArgValidatorStr.__init__(self, name, required, default_value, None)
        self.force_len = force_len
        self.enum_values_mac = enum_values

    def _validate_impl(self, value, name):
        v = ArgValidatorStr._validate_impl(self, value, name)

        if self.enum_values_mac is not None and value in self.enum_values_mac:
            return v

        try:
            addr = Util.mac_aton(v, self.force_len)
        except MyError:
            enum_ex = ""
            if self.enum_values_mac is not None:
                enum_ex = " nor one of %s" % (self.enum_values_mac)
            raise ValidationError(
                name, "value '%s' is not a valid MAC address%s" % (value, enum_ex)
            )
        if not addr:
            enum_ex = ""
            if self.enum_values_mac is not None:
                enum_ex = " nor one of %s" % (self.enum_values_mac)
            raise ValidationError(
                name, "value '%s' is not a valid MAC address%s" % (value, enum_ex)
            )
        return Util.mac_ntoa(addr)


class ArgValidatorIPAddr(ArgValidatorDict):
    def __init__(self, name, family=None, required=False):
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
            default_value=None,
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
    def __init__(self, name, family=None, required=False):
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
                ArgValidatorRouteTable("table"),
            ],
            default_value=None,
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


class ArgValidatorIPRoutingRule(ArgValidatorDict):
    def __init__(self, name, required=False):
        ArgValidatorDict.__init__(
            self,
            name,
            required,
            nested=[
                ArgValidatorNum(
                    "priority",
                    default_value=None,
                    required=True,
                    val_min=0,
                    val_max=0xFFFFFFFF,
                ),
                ArgValidatorStr(
                    "action",
                    default_value="to-table",
                    enum_values=["to-table", "blackhole", "prohibit", "unreachable"],
                ),
                ArgValidatorRange("dport", val_min=1, val_max=65534),
                ArgValidatorStr(
                    "family",
                    default_value=None,
                    enum_values=["ipv4", "ipv6"],
                ),
                ArgValidatorIPAddr("from"),
                ArgValidatorNum(
                    "fwmark", default_value=None, val_min=1, val_max=0xFFFFFFFF
                ),
                ArgValidatorNum(
                    "fwmask", default_value=None, val_min=1, val_max=0xFFFFFFFF
                ),
                ArgValidatorStr("iif", default_value=None),
                ArgValidatorBool("invert", default_value=False),
                ArgValidatorNum("ipproto", default_value=None, val_min=1, val_max=255),
                ArgValidatorStr("oif", default_value=None),
                ArgValidatorRange("sport", val_min=1, val_max=65534),
                ArgValidatorNum("suppress_prefixlength", default_value=None, val_min=0),
                ArgValidatorRouteTable("table"),
                ArgValidatorIPAddr("to"),
                ArgValidatorNum("tos", default_value=None, val_min=1, val_max=255),
                ArgValidatorRange("uid", val_min=0, val_max=0xFFFFFFFF),
            ],
            default_value=None,
        )

    def _validate_post(self, value, name, result):
        family = None
        if result["family"]:
            family = Util.addr_family_norm(result["family"])
        elif result["from"]:
            family = result["from"]["family"]
        elif result["to"]:
            family = result["to"]["family"]
        if not family:
            raise ValidationError(name, "specify the address family 'family'")

        if result["from"]:
            if result["from"]["family"] != family:
                raise ValidationError(name, "invalid address family in 'from'")

        if result["to"]:
            if result["to"]["family"] != family:
                raise ValidationError(name, "invalid address family in 'to'")

        result["family"] = family
        if result["action"] == "to-table":
            if result["table"] is None:
                raise ValidationError(
                    name,
                    "missing 'table' for the routing rule",
                )

        if result["from"] is not None:
            if result["from"]["prefix"] == 0:
                raise ValidationError(
                    name,
                    "the prefix length for 'from' cannot be zero",
                )

        if result["to"] is not None:
            if result["to"]["prefix"] == 0:
                raise ValidationError(
                    name,
                    "the prefix length for 'to' cannot be zero",
                )

        if (result["fwmask"] is None) != (result["fwmark"] is None):
            raise ValidationError(
                name,
                "'fwmask' and 'fwmark' must be set together",
            )

        if result["iif"] is not None:
            if not Util.ifname_valid(result["iif"]):
                raise ValidationError(
                    name,
                    "the incoming interface '{0}' specified in the routing rule is "
                    "invalid interface_name".format(result["iif"]),
                )

        if result["oif"] is not None:
            if not Util.ifname_valid(result["oif"]):
                raise ValidationError(
                    name,
                    "the outgoing interface '{0}' specified in the routing rule is "
                    "invalid interface_name".format(result["oif"]),
                )

        if result["suppress_prefixlength"] is not None:
            if not Util.addr_family_valid_prefix(
                result["family"], result["suppress_prefixlength"]
            ):
                raise ValidationError(
                    name,
                    "The specified 'suppress_prefixlength' cannot be greater than "
                    "{0}".format(Util.addr_family_prefix_length(result["family"])),
                )

            if result["action"] != "to-table":
                raise ValidationError(
                    name,
                    "'suppress_prefixlength' is only allowed with the to-table action",
                )
        return result


class ArgValidator_DictIP(ArgValidatorDict):
    REGEX_DNS_OPTIONS = [
        r"^attempts:([1-9]\d*|0)$",
        r"^debug$",
        r"^edns0$",
        r"^inet6$",
        r"^ip6-bytestring$",
        r"^ip6-dotint$",
        r"^ndots:([1-9]\d*|0)$",
        r"^no-check-names$",
        r"^no-ip6-dotint$",
        r"^no-reload$",
        r"^no-tld-query$",
        r"^rotate$",
        r"^single-request$",
        r"^single-request-reopen$",
        r"^timeout:([1-9]\d*|0)$",
        r"^trust-ad$",
        r"^use-vc$",
    ]

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
                ArgValidatorBool("ipv6_disabled", default_value=None),
                ArgValidatorIP("gateway6", family=socket.AF_INET6),
                ArgValidatorNum(
                    "route_metric6", val_min=-1, val_max=0xFFFFFFFF, default_value=None
                ),
                ArgValidatorList(
                    "address",
                    nested=ArgValidatorIPAddr("address[?]"),
                    default_value=list,
                ),
                ArgValidatorBool("auto_gateway", default_value=None),
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
                ArgValidatorList(
                    "dns_options",
                    nested=ArgValidatorStr(
                        "dns_options[?]", regex=ArgValidator_DictIP.REGEX_DNS_OPTIONS
                    ),
                    default_value=list,
                ),
                ArgValidatorNum(
                    "dns_priority",
                    val_min=-2147483648,
                    val_max=2147483647,
                    default_value=0,
                ),
                ArgValidatorList(
                    "routing_rule",
                    nested=ArgValidatorIPRoutingRule("routing_rule[?]"),
                    default_value=list,
                ),
            ],
            default_value=lambda: {
                "dhcp4": True,
                "dhcp4_send_hostname": None,
                "gateway4": None,
                "route_metric4": None,
                "auto6": True,
                "ipv6_disabled": False,
                "gateway6": None,
                "route_metric6": None,
                "address": [],
                "auto_gateway": None,
                "route": [],
                "routing_rule": [],
                "route_append_only": False,
                "rule_append_only": False,
                "dns": [],
                "dns_search": [],
                "dns_options": [],
                "dns_priority": 0,
            },
        )

    def _validate_post(self, value, name, result):

        has_ipv6_addresses = any(
            a for a in result["address"] if a["family"] == socket.AF_INET6
        )

        if result["ipv6_disabled"] is True:
            if result["auto6"] is True:
                raise ValidationError(
                    name, "'auto6' and 'ipv6_disabled' are mutually exclusive"
                )
            if has_ipv6_addresses:
                raise ValidationError(
                    name,
                    "'ipv6_disabled' and static IPv6 addresses are mutually exclusive",
                )
            if result["gateway6"] is not None:
                raise ValidationError(
                    name, "'ipv6_disabled' and 'gateway6' are mutually exclusive"
                )
            if result["route_metric6"] is not None:
                raise ValidationError(
                    name, "'ipv6_disabled' and 'route_metric6' are mutually exclusive"
                )
        elif result["ipv6_disabled"] is None:
            # "ipv6_disabled" is not explicitly set, we always set it to False.
            # Either "auto6" is enabled or static addresses are set, then this
            # is clearly correct.
            # Even with "auto6:False" and no IPv6 addresses, we at least enable
            # IPv6 link local addresses.
            result["ipv6_disabled"] = False

        if result["dhcp4"] is None:
            result["dhcp4"] = result["dhcp4_send_hostname"] is not None or not any(
                a for a in result["address"] if a["family"] == socket.AF_INET
            )

        if result["auto6"] is None:
            result["auto6"] = not has_ipv6_addresses

        if result["dhcp4_send_hostname"] is not None:
            if not result["dhcp4"]:
                raise ValidationError(
                    name, "'dhcp4_send_hostname' is only valid if 'dhcp4' is enabled"
                )

        ipv4_gw_defined = result["gateway4"] is not None
        ipv6_gw_defined = result["gateway6"] is not None
        dhcp_enabled = result["dhcp4"] or result["auto6"]

        if result["auto_gateway"] and not (
            ipv4_gw_defined or ipv6_gw_defined or dhcp_enabled
        ):
            raise ValidationError(
                name,
                "must define 'gateway4', 'gateway6', or use dhcp "
                "if 'auto_gateway' is enabled",
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
        return dict([(k, v.get_default_value()) for k, v in self.nested.items()])

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
            nested=[
                ArgValidator_DictEthtoolFeatures(),
                ArgValidator_DictEthtoolCoalesce(),
                ArgValidator_DictEthtoolRing(),
            ],
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


class ArgValidator_DictEthtoolCoalesce(ArgValidatorDict):
    def __init__(self):
        ArgValidatorDict.__init__(
            self,
            name="coalesce",
            nested=[
                ArgValidatorBool("adaptive_rx", default_value=None),
                ArgValidatorBool("adaptive_tx", default_value=None),
                ArgValidatorNum(
                    "pkt_rate_high", val_min=0, val_max=UINT32_MAX, default_value=None
                ),
                ArgValidatorNum(
                    "pkt_rate_low", val_min=0, val_max=UINT32_MAX, default_value=None
                ),
                ArgValidatorNum(
                    "rx_frames", val_min=0, val_max=UINT32_MAX, default_value=None
                ),
                ArgValidatorNum(
                    "rx_frames_high", val_min=0, val_max=UINT32_MAX, default_value=None
                ),
                ArgValidatorNum(
                    "rx_frames_irq", val_min=0, val_max=UINT32_MAX, default_value=None
                ),
                ArgValidatorNum(
                    "rx_frames_low", val_min=0, val_max=UINT32_MAX, default_value=None
                ),
                ArgValidatorNum(
                    "rx_usecs", val_min=0, val_max=UINT32_MAX, default_value=None
                ),
                ArgValidatorNum(
                    "rx_usecs_high", val_min=0, val_max=UINT32_MAX, default_value=None
                ),
                ArgValidatorNum(
                    "rx_usecs_irq", val_min=0, val_max=UINT32_MAX, default_value=None
                ),
                ArgValidatorNum(
                    "rx_usecs_low", val_min=0, val_max=UINT32_MAX, default_value=None
                ),
                ArgValidatorNum(
                    "sample_interval",
                    val_min=0,
                    val_max=UINT32_MAX,
                    default_value=None,
                ),
                ArgValidatorNum(
                    "stats_block_usecs",
                    val_min=0,
                    val_max=UINT32_MAX,
                    default_value=None,
                ),
                ArgValidatorNum(
                    "tx_frames", val_min=0, val_max=UINT32_MAX, default_value=None
                ),
                ArgValidatorNum(
                    "tx_frames_high", val_min=0, val_max=UINT32_MAX, default_value=None
                ),
                ArgValidatorNum(
                    "tx_frames_irq", val_min=0, val_max=UINT32_MAX, default_value=None
                ),
                ArgValidatorNum(
                    "tx_frames_low", val_min=0, val_max=UINT32_MAX, default_value=None
                ),
                ArgValidatorNum(
                    "tx_usecs", val_min=0, val_max=UINT32_MAX, default_value=None
                ),
                ArgValidatorNum(
                    "tx_usecs_high", val_min=0, val_max=UINT32_MAX, default_value=None
                ),
                ArgValidatorNum(
                    "tx_usecs_irq", val_min=0, val_max=UINT32_MAX, default_value=None
                ),
                ArgValidatorNum(
                    "tx_usecs_low", val_min=0, val_max=UINT32_MAX, default_value=None
                ),
            ],
        )


class ArgValidator_DictEthtoolRing(ArgValidatorDict):
    def __init__(self):
        ArgValidatorDict.__init__(
            self,
            name="ring",
            nested=[
                ArgValidatorNum(
                    "rx", val_min=0, val_max=UINT32_MAX, default_value=None
                ),
                ArgValidatorNum(
                    "rx_jumbo", val_min=0, val_max=UINT32_MAX, default_value=None
                ),
                ArgValidatorNum(
                    "rx_mini", val_min=0, val_max=UINT32_MAX, default_value=None
                ),
                ArgValidatorNum(
                    "tx", val_min=0, val_max=UINT32_MAX, default_value=None
                ),
            ],
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
                    "ad_actor_sys_prio", val_min=1, val_max=65535, default_value=None
                ),
                ArgValidatorMac("ad_actor_system"),
                ArgValidatorStr(
                    "ad_select", enum_values=["stable", "bandwidth", "count"]
                ),
                ArgValidatorNum(
                    "ad_user_port_key", val_min=0, val_max=1023, default_value=None
                ),
                ArgValidatorBool("all_ports_active", default_value=None),
                ArgValidatorStr("arp_all_targets", enum_values=["any", "all"]),
                ArgValidatorNum(
                    "arp_interval", val_min=0, val_max=1000000, default_value=None
                ),
                ArgValidatorStr(
                    "arp_validate",
                    enum_values=[
                        "none",
                        "active",
                        "backup",
                        "all",
                        "filter",
                        "filter_active",
                        "filter_backup",
                    ],
                ),
                ArgValidatorStr("arp_ip_target"),
                ArgValidatorNum(
                    "downdelay", val_min=0, val_max=1000000, default_value=None
                ),
                ArgValidatorStr(
                    "fail_over_mac", enum_values=["none", "active", "follow"]
                ),
                ArgValidatorStr("lacp_rate", enum_values=["slow", "fast"]),
                ArgValidatorNum(
                    "lp_interval", val_min=1, val_max=1000000, default_value=None
                ),
                ArgValidatorNum(
                    "miimon", val_min=0, val_max=1000000, default_value=None
                ),
                ArgValidatorNum(
                    "min_links", val_min=0, val_max=1000000, default_value=None
                ),
                ArgValidatorNum(
                    "num_grat_arp", val_min=0, val_max=255, default_value=None
                ),
                ArgValidatorNum(
                    "packets_per_port", val_min=0, val_max=65535, default_value=None
                ),
                ArgValidatorNum(
                    "peer_notif_delay", val_min=0, val_max=1000000, default_value=None
                ),
                ArgValidatorStr("primary"),
                ArgValidatorStr(
                    "primary_reselect", enum_values=["always", "better", "failure"]
                ),
                ArgValidatorNum(
                    "resend_igmp", val_min=0, val_max=255, default_value=None
                ),
                ArgValidatorBool("tlb_dynamic_lb", default_value=None),
                ArgValidatorNum(
                    "updelay", val_min=0, val_max=1000000, default_value=None
                ),
                ArgValidatorBool("use_carrier", default_value=None),
                ArgValidatorStr(
                    "xmit_hash_policy",
                    enum_values=[
                        "layer2",
                        "layer3+4",
                        "layer2+3",
                        "encap2+3",
                        "encap3+4",
                        "vlan+srcmac",
                    ],
                ),
            ],
            default_value=ArgValidator.MISSING,
        )

    def _validate_post(self, value, name, result):
        AD_OPTIONS = [
            "ad_actor_sys_prio",
            "ad_actor_system",
            "ad_user_port_key",
            "lacp_rate",
        ]
        ARP_OPTIONS = ["arp_interval", "arp_ip_target", "arp_validate"]
        ARP_ONLY_MODE = ["balance-rr", "active-backup", "balance-xor", "broadcast"]

        if result["mode"] != "802.3ad":
            for option in AD_OPTIONS:
                if result[option] is not None:
                    raise ValidationError(
                        name,
                        "the bond option {0} is only valid with mode 802.3ad".format(
                            option
                        ),
                    )

        if result["packets_per_port"] is not None and result["mode"] != "balance-rr":
            raise ValidationError(
                name,
                "the bond option packets_per_port is only valid with mode balance-rr",
            )

        if result["mode"] not in ARP_ONLY_MODE:
            for option in ARP_OPTIONS:
                if result[option] is not None:
                    raise ValidationError(
                        name,
                        "the bond option {0} is only valid with mode balance-rr, active-backup, balance-xor or broadcast".format(
                            option
                        ),
                    )

        if result["tlb_dynamic_lb"] is not None and result["mode"] not in [
            "balance-tlb",
            "balance-alb",
        ]:
            raise ValidationError(
                name,
                "the bond option tlb_dynamic_lb is only valid with mode balance-tlb or balance-alb",
            )

        if result["primary"] is not None and result["mode"] not in [
            "active-backup",
            "balance-tlb",
            "balance-alb",
        ]:
            raise ValidationError(
                name,
                "the bond option primary is only valid with mode active-backup, balance-tlb, balance-alb",
            )

        if (
            result["updelay"] is not None or result["downdelay"] is not None
        ) and not result["miimon"]:
            raise ValidationError(
                name,
                "the bond option downdelay or updelay is only valid with miimon enabled",
            )
        if result["peer_notif_delay"]:
            if not result["miimon"] or result["peer_notif_delay"] % result["miimon"]:
                raise ValidationError(
                    name,
                    "the bond option peer_notif_delay needs miimon enabled and must be miimon multiple",
                )
            if result["arp_interval"]:
                raise ValidationError(
                    name,
                    "the bond option peer_notif_delay needs arp_interval disabled",
                )
        if result["arp_ip_target"]:
            if not result["arp_interval"]:
                raise ValidationError(
                    name,
                    "the bond option arp_ip_target requires arp_interval to be set",
                )

        if result["arp_interval"]:
            if not result["arp_ip_target"]:
                raise ValidationError(
                    name,
                    "the bond option arp_interval requires arp_ip_target to be set",
                )

        return result

    def get_default_bond(self):
        return {
            "mode": ArgValidator_DictBond.VALID_MODES[0],
            "ad_actor_sys_prio": None,
            "ad_actor_system": None,
            "ad_select": None,
            "ad_user_port_key": None,
            "all_ports_active": None,
            "arp_all_targets": None,
            "arp_interval": None,
            "arp_ip_target": None,
            "arp_validate": None,
            "downdelay": None,
            "fail_over_mac": None,
            "lacp_rate": None,
            "lp_interval": None,
            "miimon": None,
            "min_links": None,
            "num_grat_arp": None,
            "packets_per_port": None,
            "peer_notif_delay": None,
            "primary": None,
            "primary_reselect": None,
            "resend_igmp": None,
            "tlb_dynamic_lb": None,
            "updelay": None,
            "use_carrier": None,
            "xmit_hash_policy": None,
        }


class ArgValidator_DictInfiniband(ArgValidatorDict):
    def __init__(self):
        ArgValidatorDict.__init__(
            self,
            name="infiniband",
            nested=[
                ArgValidatorStr(
                    "transport_mode", enum_values=["datagram", "connected"]
                ),
                ArgValidatorNum(
                    "p_key", val_min=-1, val_max=0xFFFF, default_value=None
                ),
            ],
            default_value=ArgValidator.MISSING,
        )

    def get_default_infiniband(self):
        return {"transport_mode": "datagram", "p_key": None}


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
        "owe",
        "sae",
        "wpa-eap",
        "wpa-psk",
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
        if result["key_mgmt"] == "wpa-psk" or result["key_mgmt"] == "sae":
            if result["password"] is None:
                raise ValidationError(
                    name,
                    "must supply a password if using {0} key management".format(
                        result["key_mgmt"]
                    ),
                )
        else:
            if result["password"] is not None:
                raise ValidationError(
                    name,
                    "password only allowed if using 'wpa-psk' or 'sae' key management",
                )

        return result


class ArgValidatorListMatchPath(ArgValidatorList):
    def __init__(self, name, nested, default_value, remove_none_or_empty):
        ArgValidatorList.__init__(
            self,
            name,
            nested,
            default_value,
            remove_none_or_empty,
        )

    def _validate_impl(self, value, name):
        result = ArgValidatorList._validate_impl(self, value, name)
        if result == ["|"] or result == ["&"]:
            raise ValidationError(
                name,
                "value '%s' is not a valid 'match.path' setting, after "
                "normalization, '%s' will only match the devices that have no PCI "
                "path" % (value, result),
            )
        return result


class ArgValidator_DictMatch(ArgValidatorDict):
    def __init__(self):
        ArgValidatorDict.__init__(
            self,
            name="match",
            nested=[
                ArgValidatorListMatchPath(
                    "path",
                    nested=ArgValidatorStr("path[?]", allow_empty=True),
                    default_value=None,
                    remove_none_or_empty=True,
                ),
            ],
            default_value={},
        )


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
        # wokeignore:rule=dummy
        "dummy",
    ]
    VALID_PORT_TYPES = ["bridge", "bond", "team"]

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
                    "port_type",
                    enum_values=ArgValidator_DictConnection.VALID_PORT_TYPES,
                ),
                ArgValidatorDeprecated(
                    # wokeignore:rule=slave
                    "slave_type",
                    deprecated_by="port_type",
                ),
                ArgValidatorStr("controller"),
                # wokeignore:rule=master
                ArgValidatorDeprecated("master", deprecated_by="controller"),
                ArgValidatorStr("interface_name", allow_empty=True),
                ArgValidatorMac("mac"),
                ArgValidatorMac(
                    "cloned_mac",
                    enum_values=[
                        "default",
                        "preserve",
                        "permanent",
                        "random",
                        "stable",
                    ],
                    default_value="default",
                ),
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
                ArgValidator_DictMatch(),
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

            if "controller" in result:
                if "port_type" not in result:
                    result["port_type"] = None
                if result["controller"] == result["name"]:
                    raise ValidationError(
                        name + ".controller", '"controller" cannot refer to itself'
                    )
            else:
                if "port_type" in result:
                    raise ValidationError(
                        name + ".port_type",
                        "'port_type' requires a 'controller' property",
                    )

            if "ip" in result:
                if "controller" in result:
                    raise ValidationError(
                        name + ".ip", 'a port cannot have an "ip" property'
                    )
            else:
                if "controller" not in result:
                    result["ip"] = self.nested["ip"].get_default_value()

            if "zone" in result:
                if "controller" in result:
                    raise ValidationError(
                        name + ".zone", '"zone" cannot be configured for port types'
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

            if result.get("match"):
                if "path" in result["match"]:
                    if result["type"] not in ["ethernet", "infiniband"]:
                        raise ValidationError(
                            name + ".match.path",
                            "'match.path' settings are only supported for type "
                            "'ethernet' or 'infiniband'",
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
                # For the compatibility with NetworkManager API and the initial
                # infiniband support in the role (the user may get used to set the
                # `p_key` into `-1` to make the connection created on the physical
                # infiniband interface), normalize the `p_key` setting as follows
                if result["infiniband"]["p_key"] == -1:
                    result["infiniband"]["p_key"] = None
                if result["infiniband"]["p_key"] is not None:
                    if (
                        result["infiniband"]["p_key"] == 0x0000
                        or result["infiniband"]["p_key"] == 0x8000
                    ):
                        raise ValidationError(
                            name,
                            "the pkey value {0} is not allowed as such a pkey value is not "
                            "supported by kernel".format(result["infiniband"]["p_key"]),
                        )
                    if "mac" not in result and "parent" not in result:
                        raise ValidationError(
                            name + ".infiniband.p_key",
                            "a infiniband device with 'infiniband.p_key' "
                            "property also needs 'mac' or 'parent' property",
                        )
                    if "interface_name" in result:
                        raise ValidationError(
                            name + ".interface_name",
                            "the 'interface_name' must be unset for the ipoib "
                            "connection, instead it is {0}".format(
                                result["interface_name"]
                            ),
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
                if (
                    not result.get("mac")
                    and (not result.get("match") or not result["match"].get("path"))
                    and not (
                        result["type"] == "infiniband"
                        and result["infiniband"]["p_key"] is not None
                    )
                ):
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

        for name in self.VALID_FIELDS:
            if name in result:
                continue
            value = self.nested[name].get_default_value()
            if value is not ArgValidator.MISSING:
                result[name] = value

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
                if connection["controller"]:
                    c = ArgUtil.connection_find_by_name(
                        connection["controller"], result, idx
                    )
                    if not c:
                        raise ValidationError(
                            name + "[" + str(idx) + "].controller",
                            "references non-existing 'controller' connection '%s'"
                            % (connection["controller"]),
                        )
                    if c["type"] not in ArgValidator_DictConnection.VALID_PORT_TYPES:
                        raise ValidationError(
                            name + "[" + str(idx) + "].controller",
                            "references 'controller' connection '%s' which is "
                            "not a controller "
                            "type by '%s'" % (connection["controller"], c["type"]),
                        )
                    if connection["type"] == "infiniband":
                        if c["type"] == "bond" and c["bond"]["mode"] != "active-backup":
                            raise ValidationError(
                                name + "[" + str(idx) + "].controller",
                                "bond only supports infiniband ports in active-backup mode",
                            )
                    if connection["port_type"] is None:
                        connection["port_type"] = c["type"]
                    elif connection["port_type"] != c["type"]:
                        raise ValidationError(
                            name + "[" + str(idx) + "].controller",
                            "references 'controller' connection '%s' which is "
                            "of type '%s' instead of port_type '%s'"
                            % (
                                connection["controller"],
                                c["type"],
                                connection["port_type"],
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

    def validate_route_tables(self, connection, idx):
        rule_route_combined_list = (
            connection["ip"]["route"] + connection["ip"]["routing_rule"]
        )
        for r in rule_route_combined_list:
            if isinstance(r["table"], Util.STRING_TYPE):
                mapping = IPRouteUtils.get_route_tables_mapping()
                if r["table"] in mapping:
                    r["table"] = mapping[r["table"]]
                else:
                    raise ValidationError.from_connection(
                        idx,
                        "cannot find route table {0} in `/etc/iproute2/rt_tables` or "
                        "`/etc/iproute2/rt_tables.d/`".format(r["table"]),
                    )

    def validate_connection_one(self, mode, connections, idx):
        def _ipv4_enabled(connection):
            has_addrs4 = any(
                address["family"] == socket.AF_INET
                for address in connection["ip"]["address"]
            )
            return connection["ip"]["dhcp4"] or has_addrs4

        def _ipv6_is_not_configured(connection):
            has_addrs6 = any(
                address["family"] == socket.AF_INET6
                for address in connection["ip"]["address"]
            )
            return (
                not connection["ip"]["ipv6_disabled"]
                and not connection["ip"]["auto6"]
                and not has_addrs6
            )

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
                and (connection["infiniband"]["p_key"] is not None)
            )
        ):
            try:
                ArgUtil.connection_find_controller(
                    connection["parent"], connections, idx
                )
            except MyError:
                raise ValidationError.from_connection(
                    idx,
                    "profile references a parent '%s' which has 'interface_name' "
                    "missing" % (connection["parent"]),
                )

        if (connection["controller"]) and (mode == self.VALIDATE_ONE_MODE_INITSCRIPTS):
            try:
                ArgUtil.connection_find_controller(
                    connection["controller"], connections, idx
                )
            except MyError:
                raise ValidationError.from_connection(
                    idx,
                    "profile references a controller '%s' which has 'interface_name' "
                    "missing" % (connection["controller"]),
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

        # initscripts does not support ip.dns_options, so raise errors when network
        # provider is initscripts
        if connection["ip"]["dns_options"]:
            if mode == self.VALIDATE_ONE_MODE_INITSCRIPTS:
                raise ValidationError.from_connection(
                    idx,
                    "ip.dns_options is not supported by initscripts.",
                )
        # initscripts does not support ip.ipv6_disabled, so raise errors when network
        # provider is initscripts
        if connection["ip"]["ipv6_disabled"]:
            if mode == self.VALIDATE_ONE_MODE_INITSCRIPTS:
                raise ValidationError.from_connection(
                    idx,
                    "ip.ipv6_disabled is not supported by initscripts.",
                )
            if not hasattr(Util.NM(), "SETTING_IP6_CONFIG_METHOD_DISABLED"):
                raise ValidationError.from_connection(
                    idx,
                    "ip.ipv6_disabled is not supported by the running version of "
                    "NetworkManager, it requires at least version 1.20. But you can "
                    "disable IPv6 auto configuration by setting ip.auto6 to False. "
                    "Then NetworkManager will ignore IPv6 for this connection. This "
                    "will still leave the sysctl value 'disable_ipv6' unchanged, but "
                    "setting ip.ipv6_disabled to True in the role will set the sysctl "
                    "value 'disable_ipv6' to True ",
                )
        # Setting ip.dns is not allowed when corresponding IP method for that
        # nameserver is disabled
        for nameserver in connection["ip"]["dns"]:
            if nameserver["family"] == socket.AF_INET and not _ipv4_enabled(connection):
                raise ValidationError.from_connection(
                    idx,
                    "IPv4 needs to be enabled to support IPv4 nameservers.",
                )
            if nameserver["family"] == socket.AF_INET6 and (
                connection["ip"]["ipv6_disabled"] or _ipv6_is_not_configured(connection)
            ):
                raise ValidationError.from_connection(
                    idx,
                    "IPv6 needs to be enabled to support IPv6 nameservers.",
                )
        # when IPv4 and IPv6 are disabled, setting ip.dns_options or
        # ip.dns_search or ip.dns_priority is not allowed
        if (
            connection["ip"]["dns_search"]
            or connection["ip"]["dns_options"]
            or connection["ip"]["dns_priority"]
        ):
            if not _ipv4_enabled(connection) and connection["ip"]["ipv6_disabled"]:
                raise ValidationError.from_connection(
                    idx,
                    "Setting 'dns_search', 'dns_options' and 'dns_priority' are not "
                    "allowed when both IPv4 and IPv6 are disabled.",
                )
            elif not _ipv4_enabled(connection) and _ipv6_is_not_configured(connection):
                raise ValidationError.from_connection(
                    idx,
                    "Setting 'dns_search', 'dns_options' and 'dns_priority' are not "
                    "allowed when IPv4 is disabled and IPv6 is not configured.",
                )
        # DNS options 'inet6', 'ip6-bytestring', 'ip6-dotint', 'no-ip6-dotint' are only
        # supported for IPv6 configuration, so raise errors when IPv6 is disabled
        if any(
            option in connection["ip"]["dns_options"]
            for option in [
                "inet6",
                "ip6-bytestring",
                "ip6-dotint",
                "no-ip6-dotint",
            ]
        ):
            if connection["ip"]["ipv6_disabled"]:
                raise ValidationError.from_connection(
                    idx,
                    "Setting DNS options 'inet6', 'ip6-bytestring', 'ip6-dotint', "
                    "'no-ip6-dotint' is not allowed when IPv6 is disabled.",
                )

        if connection["match"]:
            if connection["match"]["path"]:
                if mode == self.VALIDATE_ONE_MODE_INITSCRIPTS:
                    raise ValidationError.from_connection(
                        idx,
                        "match.path is not supported by initscripts.",
                    )
                else:
                    if not hasattr(Util.NM(), "SETTING_MATCH_PATH"):
                        raise ValidationError.from_connection(
                            idx,
                            "match.path is not supported by the running version of "
                            "NetworkManger.",
                        )

        if "bond" in connection:
            if mode == self.VALIDATE_ONE_MODE_INITSCRIPTS:
                for option in connection["bond"]:
                    if connection["bond"][option] is not None and option not in [
                        "mode",
                        "miimon",
                    ]:
                        raise ValidationError.from_connection(
                            idx,
                            "initscripts only supports the mode and miimon bond "
                            "options. All the other bond options are not supported by "
                            "initscripts.",
                        )
            # the `peer_notif_delay` bond option was supported in NM since NM 1.30
            if connection["bond"]["peer_notif_delay"]:
                if not hasattr(Util.NM(), "SETTING_BOND_OPTION_PEER_NOTIF_DELAY"):
                    raise ValidationError.from_connection(
                        idx,
                        "the bond option peer_notif_delay is not supported in "
                        "NetworkManger until NM 1.30",
                    )

        if connection["ip"]["routing_rule"]:
            if mode == self.VALIDATE_ONE_MODE_INITSCRIPTS:
                raise ValidationError.from_connection(
                    idx,
                    "ip.routing_rule is not supported by initscripts",
                )
            for routing_rule in connection["ip"]["routing_rule"]:
                if routing_rule["suppress_prefixlength"] is not None:
                    if not hasattr(
                        Util.NM(), "NM_IP_ROUTING_RULE_ATTR_SUPPRESS_PREFIXLENGTH"
                    ):
                        raise ValidationError.from_connection(
                            idx,
                            "the routing rule selector 'suppress_prefixlength' is not "
                            "supported in NetworkManger until NM 1.20",
                        )
            for routing_rule in connection["ip"]["routing_rule"]:
                if routing_rule["uid"] is not None:
                    if not hasattr(
                        Util.NM(), "NM_IP_ROUTING_RULE_ATTR_UID_RANGE_START"
                    ):
                        raise ValidationError.from_connection(
                            idx,
                            "the routing rule selector 'uid' is not supported in "
                            "NetworkManger until NM 1.34",
                        )

        if mode == self.VALIDATE_ONE_MODE_INITSCRIPTS and connection["cloned_mac"] in [
            "preserve",
            "permanent",
            "random",
            "stable",
        ]:
            raise ValidationError.from_connection(
                idx,
                "Non-MAC argument is not supported by initscripts.",
            )

        self.validate_route_tables(connection, idx)


class IPRouteUtils(object):

    # iproute2 does not care much about the valid characters of a
    # table alias (it doesn't even require UTF-8 encoding, the only
    # forbidden parts are whitespace).
    #
    # We don't allow such flexibility. Aliases must only contain a
    # certain set of ASCII characters. These aliases are what we accept
    # as input (in the playbook), and there is no need to accept
    # user input with unusual characters or non-ASCII names.
    ROUTE_TABLE_ALIAS_RE = re.compile("^[a-zA-Z0-9_.-]+$")

    @classmethod
    def _parse_route_tables_mapping(cls, file_content, mapping):

        # This parses the /etc/iproute2/rt_tables file and constructs
        # the mapping from table aliases the table numeric IDs.
        #
        # It is thus similar to rtnl_rttable_a2n(), from here:
        # https://git.kernel.org/pub/scm/network/iproute2/iproute2.git/tree/lib/rt_names.c?id=11e41a635cfab54e8e02fbff2a03715467e77ae9#n447
        regex = re.compile(
            b"^\\s*(0x[0-9a-fA-F]+|[0-9]+)\\s+([a-zA-Z0-9_.-]+)(\\s*|\\s+#.*)$"
        )
        for line in file_content.split(b"\n"):

            rmatch = regex.match(line)
            if not rmatch:
                continue

            table = rmatch.group(1)
            name = rmatch.group(2)

            name = name.decode("utf-8")

            if not cls.ROUTE_TABLE_ALIAS_RE.match(name):
                raise AssertionError(
                    "bug: table alias contains unexpected characters: %s" % (name,)
                )

            tableid = None
            try:
                tableid = int(table)
            except Exception:
                if table.startswith(b"0x"):
                    try:
                        tableid = int(table[2:], 16)
                    except Exception:
                        pass
            if tableid is None or tableid < 0 or tableid > 0xFFFFFFFF:
                continue

            # In case of duplicates, the latter wins. That is unlike iproute2's
            # rtnl_rttable_a2n(), which does a linear search over the
            # hash table (thus, the first found name depends on the content
            # of the hash table and the result in face of duplicates is
            # not well defined).
            mapping[name] = tableid

    @classmethod
    def _parse_route_tables_mapping_from_file(cls, filename, mapping):
        try:
            with open(filename, "rb") as f:
                file_content = f.read()
        except Exception:
            return
        cls._parse_route_tables_mapping(file_content, mapping)

    @classmethod
    def get_route_tables_mapping(cls):
        if not hasattr(cls, "_cached_rt_tables"):
            mapping = {}
            cls._parse_route_tables_mapping_from_file(
                "/etc/iproute2/rt_tables", mapping
            )
            # In iproute2, the directory `/etc/iproute2/rt_tables/rt_tables.d`
            # is also iterated when get the mapping between the route table name
            # and route table id,
            # https://git.kernel.org/pub/scm/network/iproute2/iproute2.git/tree/lib/rt_names.c?id=ade99e208c1843ed3b6eb9d138aa15a6a5eb5219#n391
            try:
                fnames = os.listdir("/etc/iproute2/rt_tables.d")
            except Exception:
                fnames = []
            for f in fnames:
                if f.endswith(".conf") and f[0] != ".":
                    cls._parse_route_tables_mapping_from_file(
                        "/etc/iproute2/rt_tables.d/" + f, mapping
                    )
            cls._cached_rt_tables = mapping
        return cls._cached_rt_tables
