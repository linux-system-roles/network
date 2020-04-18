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
#       - function lsr_runcoveralls_hook
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
#       - RUN_BLACK_EXTRA_ARGS
#
#   * .travis/runflake8.sh:
#
#       - RUN_FLAKE8_DISABLED
#       - RUN_FLAKE8_EXTRA_ARGS
if [[ "$(python2 -c "import sys; print(sys.version_info.major)")" == "2" ]]
then
    PYTHON2_EXCLUDES="tests/ensure_provider_tests.py"
    FLAKE8_DEFAULT_EXCLUDES=".svn,CVS,.bzr,.hg,.git,__pycache__,.tox,.eggs,*.egg"
    RUN_PYLINT_EXCLUDE='^(\..*|ensure_provider_tests\.py)$'
    RUN_FLAKE8_EXTRA_ARGS="--exclude ${FLAKE8_DEFAULT_EXCLUDES},${PYTHON2_EXCLUDES}"
fi
#
#   * .travis/runsyspycmd.sh:
#
#       - function lsr_runsyspycmd_hook
#
#   * .travis/runpytest.sh:
#
#       - RUN_PYTEST_SETUP_MODULE_UTILS
LSR_PUBLISH_COVERAGE=normal
