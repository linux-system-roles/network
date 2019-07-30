#                                                         -*- coding: utf-8 -*-
# Probe directory tree for python files and pass them to pylint
# Copyright (C) 2019  Red Hat, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
"""
Usage: python run_pylint.py ARGUMENTS

Run pylint with ARGUMENTS followed by the list of python files contained in the
working directory and its subdirectories.  As a python file is recognized a
file that match the regular expression .*\\.py[iw]?$.  Files and directories
that match the regular expression ^\\..* are skipped.  Symbolic links are also
skipped.

There are several cases when argument from ARGUMENTS is not passed to pylint
but it is handled by run_pylint.py instead:

  1. if -h or --help is contained in ARGUMENTS, this help screen is printed to
     the standard output and run_pylint.py exits with 0;
  2. if --include followed by a PATTERN is contained in ARGUMENTS, the PATTERN
     is used to recognize whether the file is a python file or not, instead of
     default .*\\.py[iw]?$;
  3. if --exclude followed by a PATTERN is contained in ARGUMENTS, the PATTERN
     is used to recognize whether the file or directory should be skipped (i.e.
     instead of default ^\\..*, the PATTERN is used).

Exclusion takes a priority over inclusion, i.e. if a file or directory can be
both included and excluded, it is excluded.
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
    """

    args = []
    include_pattern = r".*\.py[iw]?$"
    exclude_pattern = r"^\..*"
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
        sys.stdout.write(__doc__)
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
