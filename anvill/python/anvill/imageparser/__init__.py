# Copyright (c) 2020 Trail of Bits, Inc.
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


from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List


@dataclass
class ImageFunctionThunk:
    """A function thunk, used to call imported functions"""

    rva: int = 0
    name: str = ""


class ImageReader:
    """This is the interface for the memory reader used by image parser"""

    def __init__(self):
        pass

    @abstractmethod
    def get_function_thunk_list(self) -> List[ImageFunctionThunk]:
        """Returns a list of function thunks found in the image"""
        pass


class ImageParser:
    """This is the interface for image parser classes"""

    def __init__(self):
        pass

    @abstractmethod
    def get_function_thunk_list(self) -> List[ImageFunctionThunk]:
        """Returns a list of function thunks found in the image"""
        pass

    @abstractmethod
    def get_image_bitness(self) -> int:
        """Returns the bitness of this image (i.e. 16, 32, 64)"""
        pass


from .elfparser import *


def create_elf_image_parser(input_file_path: str) -> ImageParser:
    """Creates a new ImageParser object for ELF files

    Args:
        The path to the input file

    Returns:
        An image parser object for ELF files
    """

    return ELFParser(input_file_path)
