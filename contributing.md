Contributing to the Network Linux System Role
=============================================

Where to start
--------------

- **Bugs and needed implementations** are listed on [Github
  Issues](https://github.com/linux-system-roles/network/issues). Issues labeled with
[**help
wanted**](https://github.com/linux-system-roles/network/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)
are likely to be suitable for new contributors!

- **Code** is managed on
  [Github](https://github.com/linux-system-roles/network), using [Pull
Requests](https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/about-pull-requests).

- The code needs to be **compatible with Python 2.6, 2.7, 3.6, 3.7 and 3.8**.

Code structure
--------------

The repository is structured as follows:

- `./defaults/` - Contains the default role configuration.

- `./examples/` - Contains YAML examples for different configurations.

- `./library/network_connections.py` - Contains the internal Ansible module, which is
  the main script. It controls the communication between the role and Ansible, imports
  the YAML configuration and applies the changes to the provider (i.e. NetworkManager,
  initscripts).

- `./meta/` - Metadata of the project.

- `./module_utils/network_lsr/` - Contains other files that are useful for the network
  role (e.g. the YAML argument validator)

- `./tasks/` - Declaration of the different tasks that the role is going to execute.

- `./tests/playbooks/` - Contains the complete tests for the role. `./tests/test_*.yml`
  are shims to run tests once for every provider. `./tests/tasks/` contains task
  snippets that are used in multiple tests to avoid having the same code repeated
  multiple times.

The rest of files in the root folder mostly serve as configuration files for different
testing tools and bots that help with the maintenance of the project.

The code files will always have the imports on the first place, followed by constants
and in the last place, classes and methods. The style of python coding for this project
is [**PEP 8**](https://www.python.org/dev/peps/pep-0008/), with automatic formatting
thanks to [Python Black](https://black.readthedocs.io/en/stable/). Make sure to install
the formatter, it will help you a lot throughout the whole coding process!

Configuring Git
---------------

Before starting to contribute, make sure you have the basic git configuration: Your name
and email. This will be useful when signing your contributions. The following commands
will set your global name and email, although you can change it later for every repo:

```bash
git config --global user.name "Jane Doe"
git config --global user.email janedoe@example.com
```

The git editor is your system's default. If you feel more comfortable with a different
editor for writing your commits (such as Vim), change it with:

```bash
git config --global core.editor vim
```

If you want to check your settings, use `git config --list` to see all the settings Git
can find.

How to contribute
-----------------

1. Make a
   [fork](https://help.github.com/en/github/getting-started-with-github/fork-a-repo)
of this repository.

2. Create a new git branch on your local fork (the name is not relevant) and make the
   changes you need to complete an issue.

3. Do not forget to run unit and integration tests before pushing any changes!
    1. This project uses [tox](https://tox.readthedocs.io/en/latest/) with a plugin to
       run unit tests. Install the
       [tox_lsr](https://github.com/linux-system-roles/tox-lsr) plugin with:
       `pip install --user git+https://github.com/linux-system-roles/tox-lsr@main`.
       This installs the latest development version. The CI tests might use a different
       version. Check the [GitHub workflow](https://github.com/linux-system-roles/network/blob/main/.github/workflows/tox.yml#L7)`
       for the version that is used in the CI.

    2. You can try it with `tox -e py36` in case you want to try it using Python 3.6, or
       just `tox` if you want to run all the tests.

    3. Check the formatting of the code with
      [Python Black](https://black.readthedocs.io/en/stable/)

    4. Check the YAML files are correctly formatted using `tox -e yamllint`.

    5. Integration tests are executed as
       [Ansible Playbooks](https://docs.ansible.com/ansible/latest/user_guide/playbooks.html).

       To run them you can use a cloud image like the [CentOS Linux 8.1
       VM](https://cloud.centos.org/centos/8/x86_64/images/CentOS-8-GenericCloud-8.1.1911-20200113.3.x86_64.qcow2)
       and execute the command and download the package
       `standard-test-roles-inventory-qemu` from the Fedora repository:

       ```bash
       dnf install standard-test-roles-inventory-qemu
       ```

       Note that the last path is the one of the test you want to run:

       ```bash
       TEST_SUBJECTS=CentOS-8-GenericCloud-8.1.1911-20200113.3.x86_64.qcow2 \
       ansible-playbook -v -i /usr/share/ansible/inventory/standard-inventory-qcow2 \
       tests/test_default.yml
       ```

    6. Check the markdown format with
       [mdl](https://github.com/markdownlint/markdownlint) after changing any
       markdown document.

4. Once the work is ready and commited, push the branch to your remote fork and click on
   "new Pull Request" on Github.

5. All set! Now wait for the continuous integration to pass and go over your commit if
   there are any errors. If there is no problem with your contribution, the mantainer
   will merge it to the main project.

### Find other images for testing

The CentOS project publishes cloud images for
[CentOS Linux 6](https://cloud.centos.org/centos/6/images/),
[CentOS Linux 7](https://cloud.centos.org/centos/7/images/) and
[CentOS Linux 8](https://cloud.centos.org/centos/8/x86_64/images/).

- For qemu testing cases, we prefer the image architecture to be `x86_64-GenericCloud`.
- `2003` in `CentOS-7-x86_64-GenericCloud-2003.qcow2c` stands for image released in
  March 2020.
- We can use the image with extension `.qcow2` and `.qcow2c`.
- To save the image, right click on the link above, then select "Save link as...".

For Fedora, we recommend to use the [latest qcow2
images](https://kojipkgs.fedoraproject.org/compose/cloud/).

### Some important tips

- Make sure your fork and branch are up-to-date with the main project. First of all,
  [configure a remote upstream for your
fork](https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/configuring-a-remote-for-a-fork),
and keep your branch up-to-date with the upstream using
`git pull --rebase upstream main`.

- Try to make a commit per issue.

- If you are asked to make changes to your PR, don't panic! Many times it is enough to
  amend your previous commit adding the new content to it (`git commit --amend`). Be
sure to pull the latest upstream changes after that, and use `git push
--force-with-lease` to re-upload your commit with the changes!  Another way of doing
changes to a PR is by [squashing
commits](https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/about-pull-request-merges#squash-and-merge-your-pull-request-commits).

- There are times when someone has made changes on a file you were modifying while you
  were making changes to your unfinished commit. At times like this, you need to make a
[**rebase**](https://help.github.com/en/github/using-git/about-git-rebase) with
conflicts. On the rebase you have to compare what the other person added to what you
added, and merge both file versions into one that combines it all.

- If you have any doubt, do not hesitate to ask! You can join IRC channel
  \#systemroles on [Libera](https://libera.chat/), or ask on the PR/issue
  itself.

### Naming Ansible Items

- All YAML or Python files, variables, arguments, repositories, and other such names
  should follow standard Python naming conventions of being in
  `snake_case_naming_schemes`.

- Names should be mnemonic and descriptive and not strive to shorten more than
  necessary. Systems support long identifier names, so use them to be descriptive

- All defaults and all arguments to a role should have a name that begins with the role
  name to help avoid collision with other names. Avoid names like `packages` in favor of
  a name like `network_packages`.

- Same argument applies for modules provided in the roles, they also need a `$ROLENAME_`
  prefix: `network_module`. While they are usually implementation details and not intended
  for direct use in playbooks, the unfortunate fact is that importing a role makes them
  available to the rest of the playbook and therefore creates opportunities for name
  collisions.

- Moreover, internal variables (those that are not expected to be set by users) are to
  be prefixed by two underscores: `__network_variable`. This includes variables set by
  `set_fact` and `register`, because they persist in the namespace after the role has
  finished!

- Do not use special characters other than underscore in variable names, even if
  YAML/JSON allow them. (Using such variables in Jinja2 or Python would be then very
  confusing and probably not functional.)

*Find more explanation on this matter in the [meta
standards](https://github.com/oasis-roles/meta_standards#naming-things).*

### Write a good commit message

Here are a few rules to keep in mind while writing a commit message

1. Separate subject from body with a blank line
2. Limit the subject line to 50 characters
3. Capitalize the subject line
4. Do not end the subject line with a period
5. Use the imperative mood in the subject line
6. Wrap the body at 72 characters
7. Use the body to explain what and why vs. how

 A good commit message looks something like this:

```text
  Summarize changes in around 50 characters or less

 More detailed explanatory text, if necessary. Wrap it to about 72
 characters or so. In some contexts, the first line is treated as the
 subject of the commit and the rest of the text as the body. The
 blank line separating the summary from the body is critical (unless
 you omit the body entirely); various tools like `log`, `shortlog`
 and `rebase` can get confused if you run the two together.

 Explain the problem that this commit is solving. Focus on why you
 are making this change as opposed to how (the code explains that).
 Are there side effects or other unintuitive consequences of this
 change? Here's the place to explain them.

 Further paragraphs come after blank lines.

  - Bullet points are okay, too

  - Typically a hyphen or asterisk is used for the bullet, preceded
    by a single space, with blank lines in between, but conventions
    vary here

 If you use an issue tracker, put references to them at the bottom,
 like this:

 Resolves: #123
 See also: #456, #789

Do not forget to sign your commit! Use `git commit -s`
```

This is taken from [chris beams git commit](https://chris.beams.io/posts/git-commit/).
You may want to read this for a more detailed explanation (and links to other posts on
how to write a good commit message). This content is licensed under
[CC-BY-SA](https://creativecommons.org/licenses/by-sa/4.0/).

### Sign off your commit

You need to sign off your commit. By adding your 'Signed-off-by' line to the commit
messages you adhere to the
[Developer Certificate of Origin (DCO)](https://developercertificate.org/).

Use the `-s` command-line option to append the `Signed-off-by` line when committing your
code:

`$ git commit -s`

This is the full text of the Developer Certificate of Origin:

```text
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
1 Letterman Drive
Suite D4700
San Francisco, CA, 94129

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

### Debugging

When using the `nm` provider, NetworkManager create a checkpoint and reverts the changes
on failures. This makes it hard to debug the error. To disable this, set the Ansible
variable `__network_debug_flags` to include the value `disable-checkpoints`. Also tests
clean up by default in case there are failures. They should be tagged as
`tests::cleanup` and can be skipped. To use both, run the test playbooks like this:

```bash
ansible-playbook --skip-tags tests::cleanup \
    -e "__network_debug_flags=disable-checkpoints" \
    -i testhost, tests/playbooks/tests_802_1x.yml
```

### NetworkManager Documentation

- [NM 1.0](https://lazka.github.io/pgi-docs/#NM-1.0), it contains a full explanation
  about the NetworkManager API.

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
    podman run --name lsr-ci-c7 --rm --privileged -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
    -d registry.centos.org/centos/systemd
    ```

5. Use `podman unshare` first to run "podman mount" in root mode, use `-vi` to run
  ansible as inventory in verbose mode, use `-c podman` to use collection plugins. Note,
  the following tests are currently not working with podman:
  - `tests_802_1x_nm.yml`
  - `tests_802_1x_updated_nm.yml`
  - `tests_bond_initscripts.yml`
  - `tests_bond_nm.yml`
  - `tests_bridge_initscripts.yml`
  - `tests_bridge_nm.yml`
  - `tests_default_nm.yml`
  - `tests_ethernet_nm.yml`
  - `tests_reapply_nm.yml`
  - `tests_states_nm.yml`
  - `tests_vlan_mtu_initscripts.yml`
  - `tests_vlan_mtu_nm.yml`
  - `tests_wireless_nm.yml`

    ```bash
    podman unshare
    ansible-playbook -vi lsr-ci-c7, -c podman tests_provider_nm.yml
    ```

6. NOTE that this leaves the container running in the background, to kill it:

    ```bash
    podman stop lsr-ci-c7
    podman rm lsr-ci-c7
    ```

### Continuous integration

The [continuous integration](https://en.wikipedia.org/wiki/Continuous_integration) (CI)
contains a set of automated tests that are triggered on a remote server. Some of them
are immediately triggered when pushing new content to a PR (i.e. the tests hosted on
TravisCI) while other need to be triggered by members of the project. This second
set of tests can be manually triggered. To trigger them, write a command as a PR
comment. The available commands are:

- [citest] - Trigger a re-test for all machines.
- [citest bad] - Trigger a re-test for all machines with an error or failure status.
- [citest pending] - Trigger a re-test for all machines with a pending status.
- [citest commit:<sha1\>] - Whitelist a commit to be tested if the submitter is not
  trusted.

How to reach us
---------------

The mailing list for developers: systemroles@lists.fedorahosted.org

[Subscribe to the mailing list](https://lists.fedorahosted.org/admin/lists/systemroles.lists.fedorahosted.org/)

[Archive of the mailing list](https://lists.fedorahosted.org/archives/list/systemroles@lists.fedorahosted.org/)

If you are using IRC, join the `#systemroles` IRC channel on
[Libera](https://libera.chat/).

*Thanks for contributing and happy coding!!*
