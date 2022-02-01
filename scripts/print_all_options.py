#!/usr/bin/python3 -tt
# SPDX-License-Identifier: BSD-3-Clause
# Helper to print all options that the module in the network role accepts for
# profiles

from collections.abc import Mapping
from collections.abc import Sequence
from copy import deepcopy
from unittest import mock
import os
import sys

PRIORITIES = (
    "name",
    "type",
    "interface_name",
    "mac",
    "state",
    "persistent_state",
    "controller",
    "port_type",
    "parent",
    "ignore_errors",
    "force_state_change",
    "check_iface_exists",
    "autoconnect",
    "wait",
    "zone",
    "mtu",
    "ip",
    "ethernet",
    "ethtool",
    "bridge",
    "bond",
    "team",
    "vlan",
    "wireless",
    "macvlan",
    "infiniband",
)


import yaml

parentdir = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))

with mock.patch.object(
    sys,
    "path",
    [parentdir, os.path.join(parentdir, "module_utils/network_lsr")] + sys.path,
):
    with mock.patch.dict(
        "sys.modules",
        {"ansible": mock.Mock(), "ansible.module_utils": __import__("module_utils")},
    ):
        import argument_validator as av

COMMENT = "@@"
EMPTY = "/EMPTY/"


def parse_validator(validator):
    default = validator.default_value
    if isinstance(validator, av.ArgValidatorDict):
        res = {}
        for k, v in validator.nested.items():
            if v.name not in (
                "infiniband_transport_mode",
                "infiniband_p_key",
                "vlan_id",
            ) and not isinstance(v, av.ArgValidatorDeprecated):
                name = k
                if not validator.required:
                    pass
                    # name += "  DICT optional"
                res[name] = parse_validator(v)
    elif isinstance(validator, av.ArgValidatorList):
        res = [parse_validator(validator.nested)]
    elif isinstance(validator, av.ArgValidatorNum):

        minval = validator.val_min
        maxval = validator.val_max
        comment = f"  {COMMENT}"
        if not validator.required:
            comment += " optional"
        if minval is not None:
            comment += " mininum=" + str(minval)
        if maxval:
            if maxval == 0xFFFFFFFF:
                maxval = hex(maxval)
            comment += " maximum=" + str(maxval)

        if default is not None:
            res = str(default)
        elif minval is not None:
            res = str(minval)
        elif maxval is not None:
            res = str(maxval)
        else:
            res = ""

        res += comment
    elif isinstance(validator, av.ArgValidatorIP):
        res = f"{EMPTY}  {COMMENT} IP Address"
    elif isinstance(validator, av.ArgValidatorStr):
        if default:
            res = default
        elif validator.enum_values:
            res = "|".join(validator.enum_values)
        else:
            res = EMPTY
        if not validator.required:
            res += f"  {COMMENT} optional"

        # res += "   " + str(validator.__class__)
    elif isinstance(validator, av.ArgValidatorBool):
        if default is not None:
            res = "yes" if default else "no"
        else:
            res = "yes|no"

        if not validator.required:
            res += f"  {COMMENT} optional"
    else:
        res = validator.name + f"  {COMMENT} FIXME " + str(validator.__class__)

    return res


def represent_dict(dumper, data):
    """
    Represent dictionary with insert order
    """
    value = []

    for item_key, item_value in data.items():
        node_key = dumper.represent_data(item_key)
        node_value = dumper.represent_data(item_value)
        value.append((node_key, node_value))

    return yaml.nodes.MappingNode("tag:yaml.org,2002:map", value)


def priority_sorted(data):
    if isinstance(data, Sequence) and not isinstance(data, str):
        return [priority_sorted(item) for item in data]

    if isinstance(data, Mapping):
        sorted_data = {}
        for key in sorted(data, key=prioritize):
            sorted_data[key] = priority_sorted(data[key])
        return sorted_data

    return deepcopy(data)


def prioritize(key):
    try:
        priority = PRIORITIES.index(key)
    except ValueError:
        priority = len(PRIORITIES)
    return (priority, key)


yaml.add_representer(dict, represent_dict)
sorted_data = priority_sorted([parse_validator(av.ArgValidator_DictConnection())])
yaml_example = (
    yaml.dump(
        sorted_data,
        explicit_start=True,
        default_flow_style=False,
        width=100,
    )
    .replace(COMMENT, "#")
    .replace(EMPTY, "")
)

# yaml_example = re.sub(r"# ([^:]*):", r": # \1", yaml_example)

print(yaml_example)
