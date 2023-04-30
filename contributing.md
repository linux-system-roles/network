Contributing to the Network Linux System Role
=============================================

Where to start
--------------

The first place to go is [Contribute](https://linux-system-roles.github.io/contribute.html).
This has all of the common information that all role developers need:
* Role structure and layout
* Development tools - How to run tests and checks
* Ansible recommended practices
* Basic git and github information
* How to create git commits and submit pull requests

- **Bugs and needed implementations** are listed on [Github
  Issues](https://github.com/linux-system-roles/network/issues). Issues labeled with
[**help
wanted**](https://github.com/linux-system-roles/network/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)
are likely to be suitable for new contributors!

- **Code** is managed on
  [Github](https://github.com/linux-system-roles/network), using [Pull
Requests](https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/about-pull-requests).

- The code needs to be **compatible with the Python versions supported by the role platform**.

For example, see [meta](https://github.com/linux-system-roles/network/blob/main/meta/main.yml)
for the platforms supported by the role.

For example, EL6 requires python 2.6 support.  EL7 requires python 2.7 and python 3.6 support.  EL8 requires
python 3.8 and later support.  EL9 requires python 3.9 and later support.
