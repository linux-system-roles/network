# -*- coding: utf-8 -*
# SPDX-License-Identifier: BSD-3-Clause


def pytest_addoption(parser):
    parser.addoption(
        "--provider", action="store", default="nm", help="Network provider"
    )
