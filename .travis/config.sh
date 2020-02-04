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
#   * .travis/runcoveralls.sh:
#
#       - LSR_PUBLISH_COVERAGE
#       - LSR_TESTSDIR
#
# Environment variables that not start with LSR_* but have influence on CI
# process:
#
#   * .travis/runpylint.sh:
#
#       - RUN_PYLINT_INCLUDE
#       - RUN_PYLINT_EXCLUDE
#       - RUN_PYLINT_DISABLED
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

# Allow publishing coverage reports:
export LSR_PUBLISH_COVERAGE=yes
