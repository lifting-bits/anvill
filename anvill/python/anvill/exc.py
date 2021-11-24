#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

class AnvillException(Exception):
    pass


class UnhandledArchitectureType(AnvillException):
    pass


class UnhandledTypeException(AnvillException):
    def __init__(self, msg, ty):
        super(UnhandledTypeException, self).__init__(msg)
        self.type = ty


class UnhandledOSException(AnvillException):
    pass


class InvalidFunctionException(AnvillException):
    pass


class InvalidParameterException(AnvillException):
    pass


class InvalidVariableException(AnvillException):
    pass


class InvalidLocationException(AnvillException):
    pass


class ParseException(AnvillException):
    pass
