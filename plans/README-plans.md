# Introduction CI Testing Plans

Linux System Roles CI runs [tmt](https://tmt.readthedocs.io/en/stable/index.html) test plans in [Testing farm](https://docs.testing-farm.io/Testing%20Farm/0.1/index.html) with the [tmt.yml](https://github.com/linux-system-roles/network/blob/main/.github/workflows/tmt.yml) GitHub workflow.

The plans/general.fmf plan is a test plan that is general for all roles. It does the following steps:

1. Provisions two machines, one used as an Ansible control node, and second used as a managed node.
2. Does the required preparation on machines.
3. For the given role and the given PR, runs the general test from [test.sh](https://github.com/linux-system-roles/tft-tests/blob/main/tests/general/test.sh).

The [tmt.yml](https://github.com/linux-system-roles/network/blob/main/.github/workflows/tmt.yml) workflow runs the above plan and uploads the results to our Fedora storage for public access.
This workflow uses Testing Farm's Github Action [Schedule tests on Testing Farm](https://github.com/marketplace/actions/schedule-tests-on-testing-farm).

## Running Tests

You can run tests locally with the `tmt try` cli.

### Prerequisites

* Install `tmt` as described in [Installation](https://tmt.readthedocs.io/en/stable/stories/install.html).

### Running Tests Locally

To run tests locally, in the role repository, enter `tmt try -p plans/general <platform>`.

This command identifies the plans/general plan and provisions two local VMs, one used as an Ansible control node, and second used as a managed node.

tmt try is in development and does not identify tests from URL automatically, so after provisioning the machines, you must type `t`, `p`, `t` from the interactive prompt to identify tests, run preparation steps, and run the tests.

You can modify environment variables in  `plans/general.fmf` to, e.g. run only specified test playbooks by overwriting `SYSTEM_ROLES_ONLY_TESTS`.
