#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List

from ..util import *


@dataclass
class ImageFunctionThunk:
    """A function thunk, used to call imported functions"""

    start: int = 0
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
        input_file_path: The path to the input file

    Returns:
        An image parser object for ELF files
    """

    return ELFParser(input_file_path)
