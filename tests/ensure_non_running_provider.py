#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
""" Check that there is a playbook to run all role tests with the non-default
provider as well """
# vim: fileencoding=utf8

import glob
import os
import sys


import yaml

OTHER_PROVIDER_SUFFIX = "_other_provider.yml"

IGNORE = ["tests_unit.yml", "tests_helpers-and-asserts.yml"]

OTHER_PLAYBOOK = """
# SPDX-License-Identifier: BSD-3-Clause
---
- hosts: all
  vars:
      network_provider_current:
  tasks:
  # required for the code to set network_provider_current
  - service_facts:
  - set_fact:
      network_provider: "{{{{ 'initscripts' if network_provider_current == 'nm' else 'nm' }}}}"

- import_playbook: "{tests_playbook}"
  when:
    - ansible_distribution_major_version != '6'
"""  # noqa: E501 # ignore that the line is too long


def get_current_provider_code():
    with open("../defaults/main.yml") as defaults:
        yaml_defaults = yaml.safe_load(defaults)
    current_provider = yaml_defaults["network_provider_current"]
    return current_provider


def generate_nominal_other_playbook(tests_playbook):
    nominal_other_testfile_data = OTHER_PLAYBOOK.format(tests_playbook=tests_playbook)
    nominal = yaml.safe_load(nominal_other_testfile_data)
    nominal[0]["vars"]["network_provider_current"] = get_current_provider_code()
    return yaml.dump(nominal, default_flow_style=False)


def main():
    testsfiles = glob.glob("tests_*.yml")
    missing = []
    returncode = 0

    # Generate files when specified
    generate = bool(len(sys.argv) > 1 and sys.argv[1] == "generate")

    if not testsfiles:
        print("ERROR: No tests found")
        returncode = 1

    for filename in testsfiles:
        if filename.endswith(OTHER_PROVIDER_SUFFIX):
            continue

        if filename in IGNORE:
            continue

        fileroot = os.path.splitext(filename)[0]
        other_testfile = fileroot + OTHER_PROVIDER_SUFFIX
        nominal_other_testfile_data = generate_nominal_other_playbook(filename)

        if generate:
            with open(other_testfile, "w") as ofile:
                ofile.write(nominal_other_testfile_data)

        if other_testfile not in testsfiles:
            missing.append(filename)
        else:
            with open(other_testfile) as ifile:
                testdata = ifile.read()
                if testdata != nominal_other_testfile_data:
                    print(
                        "ERROR: Playbook does not match nominal value " + other_testfile
                    )
                    returncode = 1

    if missing:
        print("ERROR: No tests for other provider found for:\n" + ", \n".join(missing))
        print("Try to generate them with '{} generate'".format(sys.argv[0]))
        returncode = 1

    return returncode


if __name__ == "__main__":
    sys.exit(main())
