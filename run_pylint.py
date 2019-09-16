#                                                         -*- coding: utf-8 -*-
# SPDX-License-Identifier: MIT
#
# Copyright (c) 2019 Red Hat, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
"""
Probe directory tree for python files and pass them to pylint.

Usage: python run_pylint.py ARGUMENTS

Run pylint with ARGUMENTS followed by the list of python files contained in the
working directory and its subdirectories.  As a python file is recognized a
file that match INCPAT.  Files and directories that match EXPAT are skipped.
Symbolic links are also skipped.

There are several cases when argument from ARGUMENTS is not passed to pylint
but it is handled by run_pylint.py instead:

  1. if -h or --help is contained in ARGUMENTS, this help screen is printed to
     the standard output and run_pylint.py exits with 0;
  2. if --include followed by a PATTERN is contained in ARGUMENTS, the PATTERN
     is used instead of INCPAT to recognize whether the file is a python file
     or not;
  3. if --exclude followed by a PATTERN is contained in ARGUMENTS, the PATTERN
     is used instead of EXPAT to recognize whether the file or directory should
     be skipped.

Exclusion takes a priority over inclusion, i.e. if a file or directory can be
both included and excluded, it is excluded.

The default value of INCPAT is .*\\.py[iw]?$.  For EXPAT, it is ^\\..*.

Environment variables:

  RUN_PYLINT_INCLUDE
    overrides default value of INCPAT;

  RUN_PYLINT_EXCLUDE
    overrides default value of EXPAT;

  RUN_PYLINT_DISABLED
    if set to an arbitrary non-empty value, pylint will be not executed
"""

import os
import re
import sys

from colorama import Fore
from pylint.lint import Run


def blue(s):
    """
    Return string `s` colorized to blue.
    """

    return "%s%s%s" % (Fore.BLUE, s, Fore.RESET)


def print_line(s):
    """
    Write `s` followed by the line feed character to the standard output.
    """

    sys.stdout.write("%s\n" % s)


def probe_args():
    """
    Analyze the command line arguments and return a tuple containing a list of
    pylint arguments, pattern string to recognize files to be included, and
    pattern string to recognize files and directories to be skipped.

    Default values of pattern strings are taken from RUN_PYLINT_INCLUDE and
    RUN_PYLINT_EXCLUDE environment variables. In the case they are not defined,
    .*\\.py[iw]?$ and ^\\..* are used, respectively.
    """

    args = []
    include_pattern = os.getenv("RUN_PYLINT_INCLUDE", r".*\.py[iw]?$")
    exclude_pattern = os.getenv("RUN_PYLINT_EXCLUDE", r"^\..*")
    i, nargs = 1, len(sys.argv)
    while i < nargs:
        arg = sys.argv[i]
        if arg == "--include":
            i += 1
            assert i < nargs, "--include: missing PATTERN"
            include_pattern = sys.argv[i]
        elif arg == "--exclude":
            i += 1
            assert i < nargs, "--exclude: missing PATTERN"
            exclude_pattern = sys.argv[i]
        else:
            args.append(arg)
        i += 1
    return args, include_pattern, exclude_pattern


def probe_dir(path, include_re, exclude_re):
    """
    Recursively go through directory structure starting at `path`, collect
    files that match `include_re`, skip files and directories that are either
    symbolic links or match `exclude_re`. Return the list of collected files.
    """

    files = []
    for direntry in os.listdir(path):
        fullpath = os.path.join(path, direntry)
        if os.path.islink(fullpath) or exclude_re.match(direntry):
            continue
        elif os.path.isdir(fullpath):
            files.extend(probe_dir(fullpath, include_re, exclude_re))
        elif os.path.isfile(fullpath) and include_re.match(direntry):
            files.append(fullpath)
    return files


def show_files(files):
    """
    Print `files` to the standard output, one item per line, in a blue color.
    """

    if not files:
        return
    print_line(blue("%s: files to be checked:" % sys.argv[0]))
    for f in files:
        print_line(blue("    %s" % f))


def main():
    """
    Script entry point. Return exit code.
    """

    args, include_pattern, exclude_pattern = probe_args()
    if "-h" in args or "--help" in args:
        print_line(__doc__)
        return 0
    if os.getenv("RUN_PYLINT_DISABLED", "") != "":
        return 0
    files = probe_dir(
        os.getcwd(), re.compile(include_pattern), re.compile(exclude_pattern)
    )
    show_files(files)
    args.extend(files)
    sys.argv[0] = "pylint"
    return Run(args, None, False).linter.msg_status


if __name__ == "__main__":
    sys.exit(main())
