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

    def proto(self) -> List[Dict[str, Any]]:
        proto: List[Dict[str, Any]] = []
        if not len(self._bytes):
            return proto

        for ea in sorted(self._bytes.keys()):
            val, can_write, can_exec = self._bytes[ea]
            if not len(proto) or \
               proto[-1]["is_writeable"] != can_write or \
               proto[-1]["is_executable"] != can_exec or \
               (proto[-1]["address"] + (len(proto[-1]["data"]) / 2)) != ea:
                proto.append({
                    "address": ea,
                    "is_executable": can_exec,
                    "is_writeable": can_write,
                    "data": ""
                })
            proto[-1]["data"] += "{:02x}".format(val & 0xFF)

        return proto
