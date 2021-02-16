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


class InvalidVariableException(AnvillException):
    pass


class InvalidLocationException(AnvillException):
    pass


class ParseException(AnvillException):
    pass
