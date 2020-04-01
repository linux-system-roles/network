# SPDX-License-Identifier: MIT
#
# Use this file to specify custom configuration for a project. Generally, this
# involves the modification of the content of LSR_* environment variables, see
#
#   * .travis/preinstall:
#
#       - LSR_EXTRA_PACKAGES
#
#   * .travis/runtox:
#
#       - LSR_ANSIBLES
#       - LSR_MSCENARIOS
#
# Environment variables that not start with LSR_* but have influence on CI
# process:
#
#   * .travis/runpylint.sh:
#
#       - RUN_PYLINT_INCLUDE
#       - RUN_PYLINT_EXCLUDE
#       - RUN_PYLINT_DISABLED
#       - RUN_PYLINT_SETUP_MODULE_UTILS
#
#   * .travis/runblack.sh:
#
#       - RUN_BLACK_INCLUDE
#       - RUN_BLACK_EXCLUDE
#       - RUN_BLACK_DISABLED
#
#   * .travis/runflake8.sh:
#
#       - RUN_FLAKE8_DISABLED
#
#   * .travis/runpytest.sh:
#
#       - RUN_PYTEST_SETUP_MODULE_UTILS
