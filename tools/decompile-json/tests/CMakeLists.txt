# Copyright (c) 2020-presente Trail of Bits, Inc.
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

add_test(NAME test_roundtrip
  COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/scripts/roundtrip.py" "$<TARGET_FILE:anvill-decompile-json>" "${CMAKE_CURRENT_SOURCE_DIR}/samples" "${CMAKE_C_COMPILER}"
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)
