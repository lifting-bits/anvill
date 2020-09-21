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


class Memory(object):
    def __init__(self):
        self._bytes = {}

    def map_byte(self, ea, val, can_write, can_exec):
        self._bytes[ea] = (int(val & 0xFF), can_write, can_exec)

    def _extend_range(self, range_proto, ea, val, can_write, can_exec):
        if not len(range_proto):
            range_proto["address"] = ea
            range_proto["is_writeable"] = can_write
            range_proto["is_executable"] = can_exec
            range_proto["data"] = "{:02x}".format(val)
            return True

        elif (
            range_proto["is_writeable"] == can_write
            and range_proto["is_executable"] == can_exec
        ):

            next_ea = range_proto["address"] + (len(range_proto["data"]) / 2)
            if next_ea != ea:
                return False
            else:
                range_proto["data"] += "{:02x}".format(val)
                return True
        else:
            return False

    def proto(self):
        proto = []
        if not len(self._bytes):
            return proto

        range_proto = {}
        for ea in sorted(self._bytes.keys()):

            val, can_write, can_exec = self._bytes[ea]
            if not self._extend_range(range_proto, ea, val, can_write, can_exec):
                proto.append(range_proto)
                range_proto = {}
                ret = self._extend_range(range_proto, ea, val, can_write, can_exec)
                assert ret

        if len(range_proto):
            proto.append(range_proto)

        return proto
