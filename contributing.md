# Contributing to the network Linux System Role

## Where to start

The first place to go is [Contribute](https://linux-system-roles.github.io/contribute.html).
This has all of the common information that all role developers need:

* Role structure and layout
* Development tools - How to run tests and checks
* Ansible recommended practices
* Basic git and github information
* How to create git commits and submit pull requests

**Bugs and needed implementations** are listed on
[Github Issues](https://github.com/linux-system-roles/network/issues).
Issues labeled with
[**help wanted**](https://github.com/linux-system-roles/network/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)
are likely to be suitable for new contributors!

**Code** is managed on [Github](https://github.com/linux-system-roles/network), using
[Pull Requests](https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/about-pull-requests).

## Python Code

The Python code needs to be **compatible with the Python versions supported by
the role platform**.

For example, see [meta](https://github.com/linux-system-roles/network/blob/main/meta/main.yml)
for the platforms supported by the role.

If the role provides Ansible modules (code in `library/` or `module_utils/`) -
these run on the *managed* node, and typically[1] use the default system python:

* EL6 - python 2.6
* EL7 - python 2.7 or python 3.6 in some cases
* EL8 - python 3.6
* EL9 - python 3.9

If the role provides some other sort of Ansible plugin such as a filter, test,
etc. - these run on the *control* node and typically use whatever version of
python that Ansible uses, which in many cases is *not* the system python, and
may be a modularity release such as python311.

In general, it is a good idea to ensure the role python code works on all
versions of python supported by `tox-lsr` from py36 on, and on py27 if the role
supports EL7, and on py26 if the role supports EL6.[1]

[1] Advanced users may set
[ansible_python_interpreter](https://docs.ansible.com/ansible/latest/reference_appendices/special_variables.html#term-ansible_python_interpreter)
to use a non-system python on the managed node, so it is a good idea to ensure
your code has broad python version compatibility, and do not assume your code
will only ever be run with the default system python.

## Debugging network system role

When using the `nm` provider, NetworkManager create a checkpoint and reverts the
changes on failures. This makes it hard to debug the error. To disable this, set
the Ansible variable `__network_debug_flags` to include the value
`disable-checkpoints`. Also tests clean up by default in case there are
failures. They should be tagged as `tests::cleanup` and can be skipped. To use
both, run the test playbooks like this:

```bash
ansible-playbook --skip-tags tests::cleanup \
    -e "__network_debug_flags=disable-checkpoints" \
    -i testhost, tests/playbooks/tests_802_1x.yml
```

### NetworkManager Documentation

[NM 1.0](https://lazka.github.io/pgi-docs/#NM-1.0), it contains a full
explanation about the NetworkManager API.

### Integration tests with podman

1. Create `~/.ansible/collections/ansible_collections/containers/podman/` if this
  directory does not exist and `cd` into this directory.

    ```bash
    mkdir -p ~/.ansible/collections/ansible_collections/containers/podman/
    cd ~/.ansible/collections/ansible_collections/containers/podman/
    ```

2. Clone the collection plugins for Ansible-Podman into the current directory.

    ```bash
    git clone https://github.com/containers/ansible-podman-collections.git .
    ```

3. Change directory into the `tests` subdirectory.

    ```bash
    cd ~/network/tests
    ```

4. Use podman with `-d` to run in the background (daemon). Use `c7` because
  `centos/systemd` is centos7.

    ```bash
    podman run --name lsr-ci-c7 --rm --privileged \
    -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
    -d registry.centos.org/centos/systemd
    ```

5. Use `podman unshare` first to run "podman mount" in root mode, use `-vi` to
  run ansible as inventory in verbose mode, use `-c podman` to use the podman
  connection plugin. NOTE: Some of the tests do not work with podman - see
  `.github/run_test.sh` for the list of tests that do not work.

    ```bash
    podman unshare
    ansible-playbook -vi lsr-ci-c7, -c podman tests_provider_nm.yml
    ```

6. NOTE that this leaves the container running in the background, to kill it:

    ```bash
    podman stop lsr-ci-c7
    podman rm lsr-ci-c7
    ```
