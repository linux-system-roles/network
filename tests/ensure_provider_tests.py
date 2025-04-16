#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Check that there is a playbook to run all role tests with both providers"""
# vim: fileencoding=utf8

import difflib
import glob
import os
import sys


GET_NM_VERSION = """
    - name: Install NetworkManager and get NetworkManager version
      when:
        - ansible_distribution_major_version != '6'
      tags:
        - always
      block:
        - name: Install NetworkManager
          package:
            name: NetworkManager
            state: present
            use: "{{ (__network_is_ostree | d(false)) |
                     ternary('ansible.posix.rhel_rpm_ostree', omit) }}"
        - name: Get package info
          package_facts:
        - name: Get NetworkManager version
          set_fact:
            networkmanager_version: "{{
              ansible_facts.packages['NetworkManager'][0]['version'] }}"
"""

MINIMUM_NM_VERSION_CHECK = """
    - networkmanager_version is version({minimum_nm_version}, '>=')
"""

EXTRA_RUN_CONDITION_PREFIX = "    - "

RUN_PLAYBOOK_WITH_NM = """# SPDX-License-Identifier: BSD-3-Clause
# This file was generated by ensure_provider_tests.py
---
# set network provider and gather facts
# yamllint disable rule:line-length
- name: Run playbook '{test_playbook}' with nm as provider
  hosts: all
  tasks:
    - name: Include the task 'el_repo_setup.yml'
      include_tasks: tasks/el_repo_setup.yml
    - name: Set network provider to 'nm'
      set_fact:
        network_provider: nm
      tags:
        - always
{get_nm_version}

# The test requires or should run with NetworkManager, therefore it cannot run
# on RHEL/CentOS 6
{comment}- name: Import the playbook '{test_playbook}'
  import_playbook: {test_playbook}
  when:
    - ansible_distribution_major_version != '6'
{minimum_nm_version_check}{extra_run_condition}"""

MINIMUM_VERSION = "minimum_version"
EXTRA_RUN_CONDITION = "extra_run_condition"
NM_ONLY_TESTS = {
    "playbooks/tests_802_1x_updated.yml": {
        EXTRA_RUN_CONDITION: "ansible_distribution != 'RedHat' or\n      ansible_distr\
ibution_major_version | int < 9",
    },
    "playbooks/tests_802_1x.yml": {
        EXTRA_RUN_CONDITION: "ansible_distribution != 'RedHat' or\n      ansible_distr\
ibution_major_version | int < 9",
    },
    "playbooks/tests_ignore_auto_dns.yml": {},
    "playbooks/tests_bond_options.yml": {},
    "playbooks/tests_bond_port_match_by_mac.yml": {},
    "playbooks/tests_eth_dns_support.yml": {},
    "playbooks/tests_dummy.yml": {},  # wokeignore:rule=dummy
    "playbooks/tests_infiniband.yml": {},
    "playbooks/tests_ipv6_disabled.yml": {},
    "playbooks/tests_ipv6_dns_search.yml": {},
    "playbooks/tests_mac_address_match.yml": {},
    "playbooks/tests_provider.yml": {
        MINIMUM_VERSION: "'1.20.0'",
        "comment": "# NetworKmanager 1.20.0 added support for forgetting profiles",
        EXTRA_RUN_CONDITION: (
            "(ansible_distribution == 'Fedora'\n"
            "       and ansible_distribution_major_version | int < 41)\n"
            "      or ansible_distribution not in ['RedHat', 'CentOS', 'Fedora']\n"
            "      or ansible_distribution_major_version | int < 9"
        ),
    },
    "playbooks/tests_eth_pci_address_match.yml": {
        MINIMUM_VERSION: "'1.26.0'",
        "comment": "# NetworkManager 1.26.0 added support for match.path setting",
    },
    "playbooks/tests_network_state.yml": {
        EXTRA_RUN_CONDITION: "ansible_distribution_major_version | int > 7",
    },
    "playbooks/tests_reapply.yml": {},
    "playbooks/tests_route_table.yml": {},
    "playbooks/tests_route_type.yml": {
        MINIMUM_VERSION: "'1.36.0'",
        "comment": "# NetworkManager 1.36.0 added support for special route types: \
blackhole, prohibit and unreachable",
    },
    "playbooks/tests_routing_rules.yml": {},
    # teaming support dropped in EL10
    "playbooks/tests_team.yml": {
        EXTRA_RUN_CONDITION: "ansible_distribution not in ['RedHat', 'CentOS'] or\n      ansible_distr\
ibution_major_version | int < 10",
    },
    "playbooks/tests_team_plugin_installation.yml": {
        EXTRA_RUN_CONDITION: "ansible_distribution not in ['RedHat', 'CentOS'] or\n      ansible_distr\
ibution_major_version | int < 10",
    },
    # mac80211_hwsim (used for tests_wireless) only seems to be available
    # and working on RHEL/CentOS 7
    "playbooks/tests_wireless.yml": {
        EXTRA_RUN_CONDITION: "ansible_distribution_major_version == '7'",
    },
    "playbooks/tests_wireless_and_network_restart.yml": {},
    "playbooks/tests_wireless_plugin_installation.yml": {},
    "playbooks/tests_wireless_wpa3_owe.yml": {
        "comment": "# OWE has not been supported by NetworkManager 1.18.8 on \
RHEL 7(dist-tag). Failed in setting up mock wifi on RHEL 8",
        EXTRA_RUN_CONDITION: "ansible_distribution_major_version > '7' and \
ansible_distribution == 'CentOS' or\n     ansible_distribution_major_version > '32' \
and ansible_distribution == 'Fedora'",
    },
    "playbooks/tests_wireless_wpa3_sae.yml": {
        "comment": "# SAE has not been supported by NetworkManager 1.18.8 on \
RHEL 7. Failed in setting up mock wifi on RHEL 8",
        EXTRA_RUN_CONDITION: "ansible_distribution_major_version != '7' and \
ansible_distribution != 'RedHat'",
    },
}
# NM_CONDITIONAL_TESTS is used to store the test playbooks which are demanding for NM
# minimum version or extra running condition, test playbooks in NM_CONDITIONAL_TESTS
# can also run with initscripts provider
NM_CONDITIONAL_TESTS = {
    "playbooks/tests_ethtool_coalesce.yml": {
        MINIMUM_VERSION: "'1.25.1'",
        "comment": "# NetworkManager 1.25.1 introduced ethtool coalesce support",
    },
    "playbooks/tests_ethtool_features.yml": {
        MINIMUM_VERSION: "'1.20.0'",
        "comment": "# NetworkManager 1.20.0 introduced ethtool settings support",
    },
    "playbooks/tests_ethtool_ring.yml": {
        MINIMUM_VERSION: "'1.25.2'",
        "comment": "# NetworkManager 1.25.2 introduced ethtool ring support",
    },
}


IGNORE = [
    # checked by tests_regression_nm.yml
    "playbooks/tests_checkpoint_cleanup.yml",
    "playbooks/tests_switch_provider.yml",
]

RUN_PLAYBOOK_WITH_INITSCRIPTS = """# SPDX-License-Identifier: BSD-3-Clause
# This file was generated by ensure_provider_tests.py
---
# yamllint disable rule:line-length
- name: Run playbook '{test_playbook}' with initscripts as provider
  hosts: all
  tasks:
    - name: Include the task 'el_repo_setup.yml'
      include_tasks: tasks/el_repo_setup.yml
    - name: Set network provider to 'initscripts'
      set_fact:
        network_provider: initscripts
      tags:
        - always

- name: Import the playbook '{test_playbook}'
  import_playbook: {test_playbook}
  when: (ansible_distribution in ['CentOS','RedHat'] and\n    \
ansible_distribution_major_version | int < 9)
"""


def create_nm_playbook(test_playbook):
    fileroot = os.path.splitext(os.path.basename(test_playbook))[0]
    nm_testfile = fileroot + "_nm.yml"
    if test_playbook in NM_CONDITIONAL_TESTS:
        minimum_nm_version = NM_CONDITIONAL_TESTS[test_playbook].get(MINIMUM_VERSION)
        extra_run_condition = NM_CONDITIONAL_TESTS[test_playbook].get(
            EXTRA_RUN_CONDITION, ""
        )
        comment = NM_CONDITIONAL_TESTS.get(test_playbook, {}).get("comment", "")
    else:
        minimum_nm_version = NM_ONLY_TESTS.get(test_playbook, {}).get(MINIMUM_VERSION)
        extra_run_condition = NM_ONLY_TESTS.get(test_playbook, {}).get(
            EXTRA_RUN_CONDITION, ""
        )
        comment = NM_ONLY_TESTS.get(test_playbook, {}).get("comment", "")

    if extra_run_condition:
        extra_run_condition = f"{EXTRA_RUN_CONDITION_PREFIX}{extra_run_condition}\n"

    nm_version_check = ""
    if minimum_nm_version:
        nm_version_check = MINIMUM_NM_VERSION_CHECK.format(
            minimum_nm_version=minimum_nm_version
        )
    if comment:
        comment = f"{comment}\n"

    nominal_nm_testfile_data = RUN_PLAYBOOK_WITH_NM.format(
        test_playbook=test_playbook,
        get_nm_version=minimum_nm_version and GET_NM_VERSION or "",
        comment=comment,
        minimum_nm_version_check=nm_version_check,
        extra_run_condition=extra_run_condition,
    )

    return nm_testfile, nominal_nm_testfile_data


def create_initscripts_playbook(test_playbook):
    fileroot = os.path.splitext(os.path.basename(test_playbook))[0]
    init_testfile = fileroot + "_initscripts.yml"

    nominal_data = RUN_PLAYBOOK_WITH_INITSCRIPTS.format(test_playbook=test_playbook)

    return init_testfile, nominal_data


def check_playbook(generate, testfile, test_playbook, nominal_data):
    is_missing = False
    returncode = None
    if generate:
        print(testfile)
        with open(testfile, "w") as ofile:
            ofile.write(nominal_data)

    if not os.path.isfile(testfile) and not generate:
        is_missing = True
    else:
        with open(testfile) as ifile:
            testdata = ifile.read()
            if testdata != nominal_data:
                print(f"ERROR: Playbook does not match nominal value: {testfile}")
                sys.stdout.writelines(
                    difflib.unified_diff(
                        nominal_data.splitlines(keepends=True),
                        testdata.splitlines(keepends=True),
                        fromfile=f"{testfile}.expected",
                        tofile=f"{testfile}.actual",
                    )
                )

                returncode = 1

    return is_missing, returncode


def main():
    testsfiles = glob.glob("playbooks/tests_*.yml")
    missing = []
    returncode = 0

    # Generate files when specified
    generate = bool(len(sys.argv) > 1 and sys.argv[1] == "generate")

    if not testsfiles:
        print("ERROR: No tests found")
        returncode = 1

    for test_playbook in testsfiles:
        if test_playbook in IGNORE:
            continue

        nm_testfile, nominal_nm_testfile_data = create_nm_playbook(test_playbook)

        is_missing, new_returncode = check_playbook(
            generate=generate,
            testfile=nm_testfile,
            test_playbook=test_playbook,
            nominal_data=nominal_nm_testfile_data,
        )
        if is_missing:
            missing.append(test_playbook)
        if new_returncode:
            returncode = new_returncode

        if test_playbook not in NM_ONLY_TESTS:
            init_testfile, nominal_init_testfile_data = create_initscripts_playbook(
                test_playbook
            )
            is_missing, new_returncode = check_playbook(
                generate=generate,
                testfile=init_testfile,
                test_playbook=test_playbook,
                nominal_data=nominal_init_testfile_data,
            )
            if is_missing:
                missing.append(test_playbook)
            if new_returncode:
                returncode = new_returncode

    if missing:
        print("ERROR: No NM or initscripts tests found for:\n" + ", \n".join(missing))
        print(f"Try to generate them with '{sys.argv[0]} generate'")
        returncode = 1

    return returncode


if __name__ == "__main__":
    sys.exit(main())
