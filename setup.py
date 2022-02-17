#!/usr/bin/env python3

#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

import setuptools
import sys
import os

os.chdir(os.path.join(os.path.dirname(__file__), "python"))

setuptools.setup(
    name="anvill",
    version="1.0.2",
    description="Specification-based decompilation library",
    author="Peter Goodman",
    author_email="peter@trailofbits.com",
    url="https://github.com/lifting-bits/anvill",
    license="AGPL 3",
    data_files=[('anvill', ['anvill/logging.ini'])],
    py_modules=[
        "anvill.__init__", "anvill.__main__", "anvill.arch", "anvill.binja.__init__",
        "anvill.binja.bnfunction", "anvill.binja.bninstruction", "anvill.binja.bnprogram",
        "anvill.binja.bnvariable", "anvill.binja.callingconvention", "anvill.binja.typecache",
        "anvill.binja.xreftype", "anvill.binja.table", "anvill.call", "anvill.exc", "anvill.function",
        "anvill.ida.__init__", "anvill.ida.idafunction", "anvill.ida.idaprogram",
        "anvill.ida.idavariable", "anvill.ida.utils", "anvill.imageparser.__init__",
        "anvill.imageparser.elfparser", "anvill.loc", "anvill.mem", "anvill.os", "anvill.program",
        "anvill.type", "anvill.var", "anvill.util"])
