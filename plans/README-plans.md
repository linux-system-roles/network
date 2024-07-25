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

For now, this functionality requires you to push changes to a PR because the plan only runs from the main branch, or from the PR branch.
So this is WIP.

To run tests locally, in the role repository, enter `tmt run plans --name plans/general <platform>`.
Where `<platform>` is the name of the platform you want to run tests against.

For example, `tmt run plans --name plans/general Fedora-40`.

This command identifies the plans/general plan and provisions two machines, one used as an Ansible control node, and second used as a managed node.

You can also use `tmt try` to get to an interreactive prompt and be able to ssh into test machines.
You must run `tmt try -p plans/general Fedora-40`, and the in the promt type `p` to prepare the machines, then `t` to run the tests.
