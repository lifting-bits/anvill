#!/usr/bin/env python3

# Copyright (c) 2021-present Trail of Bits, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import setuptools
import sys
import os

os.chdir(os.path.join(os.path.dirname(__file__), "anvill", "python"))

setuptools.setup(
    name="anvill",
    version="1.0.1",
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
        "anvill.binja.xreftype", "anvill.binja.table", "anvill.exc", "anvill.function",
        "anvill.ida.__init__", "anvill.ida.idafunction", "anvill.ida.idaprogram",
        "anvill.ida.idavariable", "anvill.ida.utils", "anvill.imageparser.__init__",
        "anvill.imageparser.elfparser", "anvill.loc", "anvill.mem", "anvill.os", "anvill.program",
        "anvill.type", "anvill.var", "anvill.util"])
