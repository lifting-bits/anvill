#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

from typing import Tuple, Dict, Any, List


class Memory(object):
    def __init__(self):
        self._bytes: Dict[int, Tuple[int, bool, bool]] = {}

    def map_byte(self, ea: int, val: int, can_write: bool, can_exec: bool):
        self._bytes[ea] = (int(val & 0xFF), can_write, can_exec)

    def _extend_range(self, range_proto: Dict[str, Any], ea: int, val: int,
                      can_write: bool, can_exec: bool) -> bool:
        if not len(range_proto):
            range_proto["address"] = ea
            range_proto["is_writeable"] = can_write
            range_proto["is_executable"] = can_exec
            range_proto["data"] = "{:02x}".format(val & 0xFF)
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

    def proto(self) -> List[Dict[str, Any]]:
        proto: List[Dict[str, Any]] = []
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
