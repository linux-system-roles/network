# Introduction CI Testing Plans

Linux System Roles CI runs [tmt](https://tmt.readthedocs.io/en/stable/index.html) test plans in [Testing farm](https://docs.testing-farm.io/Testing%20Farm/0.1/index.html) with the [tft.yml](https://github.com/linux-system-roles/network/blob/main/.github/workflows/tft.yml) GitHub workflow.

The `plans/test_playbooks_parallel.fmf` plan is a test plan that runs test playbooks in parallel on multiple managed nodes.
`plans/test_playbooks_parallel.fmf` is generated centrally from `https://github.com/linux-system-roles/.github/`.
The automation calculates the number of managed nodes to provision with this formula:

```plain
number-of-test-playbooks / 10 + 1
```

The `plans/test_playbooks_parallel.fmf` plan does the following steps:

1. Provisions systems to be used as a control node and as managed nodes.
2. Does the required preparation on systems.
3. For the given role and the given PR, runs the general test from [test.sh](https://github.com/linux-system-roles/tft-tests/blob/main/tests/general/test.sh).

The [tft.yml](https://github.com/linux-system-roles/network/blob/main/.github/workflows/tft.yml) workflow runs the above plan and uploads the results to our Fedora storage for public access.
This workflow uses Testing Farm's Github Action [Schedule tests on Testing Farm](https://github.com/marketplace/actions/schedule-tests-on-testing-farm).

## Running Tests

You can run tests locally with the `tmt try` cli or remotely in Testing Farm.

### Running Tests Locally

1. Install `tmt` as described in [Installation](https://tmt.readthedocs.io/en/stable/stories/install.html).
2. Change to the role repository directory.
3. Modify `plans/test_playbooks_parallel.fmf` to suit your requirements:
    1. Due to [issue #3138](https://github.com/teemtee/tmt/issues/3138), comment out all managed nodes except for one.
    2. Optionally modify environment variables to, e.g. run only specified test playbooks by modifying `SYSTEM_ROLES_ONLY_TESTS`.
4. Enter `tmt try -p plans/test_playbooks_parallel <platform>`.
    This command identifies the `plans/test_playbooks_parallel.fmf` plan and provisions local VMs, a control node and a managed node.
5. `tmt try` is in development and does not identify tests from URL automatically, so after provisioning the machines, you must type `t`, `p`, `t` from the interactive prompt to identify tests, run preparation steps, and run the tests.

### Running in Testing Farm

1. Install `testing-farm` as described in [Installation](https://gitlab.com/testing-farm/cli/-/blob/main/README.adoc#user-content-installation).
2. Change to the role repository directory.
3. If you want to run tests with edits in your branch, you need to commit and push changes first to some branch.
4. You can uncomment "Inject your ssh public key to test systems" discover step in the plan if you want to troubleshoot tests by SSHing into test systems in Testing Farm.
5. Enter `testing-farm request`.
    Edit to your needs.

    ```bash
    $ TESTING_FARM_API_TOKEN=<your_api_token> \
        testing-farm request --pipeline-type="tmt-multihost" \
        --plan-filter="tag:playbooks_parallel" \
        --git-url "https://github.com/<my_user>/network" \
        --git-ref "<my_branch>" \
        --compose CentOS-Stream-9 \
        -e "SYSTEM_ROLES_ONLY_TESTS=tests_default.yml" \
        --no-wait
    ```
