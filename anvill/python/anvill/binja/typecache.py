# Copyright (c) 2020-present Trail of Bits, Inc.
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

import sys
from typing import Dict, cast, Optional, Union

import binaryninja as bn

from .callingconvention import *

from ..type import *
from ..function import *
from ..util import *

CacheKey = str


def _cache_key(tinfo: bn.Type) -> CacheKey:
    """ Convert bn Type instance to cache key"""
    return str(tinfo)


try:
    _80_PERCENT_CONFIDENCE = bn.core.max_confidence.__class__(bn.core.max_confidence * 0.8)
except:
    _80_PERCENT_CONFIDENCE = int(255 * 0.8)


def _bool(b: bn.BoolWithConfidence, default_val: bool = False) -> bool:
    """Convert a Binary Ninja confidence boolean to a normal boolean."""
    global _80_PERCENT_CONFIDENCE
    if b.confidence >= _80_PERCENT_CONFIDENCE:
        return b.value
    else:
        return default_val


class TypeCache:
    """The class provides API to recursively visit the binja types and convert
    them to the anvill `Type` instance. It maintains a cache of visited binja
    types to reduce lookup time.
    """

    _arch: Arch
    _bv: bn.BinaryView
    _cache: Dict[CacheKey, Type]
    _named_cache: Dict[str, Type]
    _core_types: Dict[str, Type]

    # list of unhandled type classes which should log error
    _err_type_class = {
        bn.TypeClass.VarArgsTypeClass: "VarArgsTypeClass",
        bn.TypeClass.ValueTypeClass: "ValueTypeClass",
        bn.TypeClass.WideCharTypeClass: "WideCharTypeClass",
    }

    def __init__(self, arch: Arch, bv: bn.BinaryView):
        self._arch = arch
        self._bv = bv
        self._cache = {}
        self._named_cache = {}
        self._core_types = {
            "size_t": IntegerType(self._bv.address_size, False),
            "ssize_t": IntegerType(self._bv.address_size, True),
            "ptrdiff_t": IntegerType(self._bv.address_size, True),
            "int8_t": IntegerType(1, True),
            "int16_t": IntegerType(2, True),
            "int32_t": IntegerType(4, True),
            "int64_t": IntegerType(8, True),
            "int128_t": IntegerType(16, True),
            "__int128": IntegerType(16, True),
            "uint8_t": IntegerType(1, False),
            "uint16_t": IntegerType(2, False),
            "uint32_t": IntegerType(4, False),
            "uint64_t": IntegerType(8, False),
            "uint128_t": IntegerType(16, False),
            "__uint128": IntegerType(16, False),
            "__m64": MMXType(),
            "u_char": IntegerType(1, False),
            "u_short": IntegerType(2, False),
            "u_int": IntegerType(4, False),
            "u_quad_t": IntegerType(8, False),
            "__u_char": IntegerType(1, False),
            "__u_short": IntegerType(2, False),
            "__u_int": IntegerType(4, False),
            "__u_quad_t": IntegerType(8, False),
            "__ino64_t": IntegerType(8, False),
        }

    def _convert_struct(self, tinfo_: bn.Type) -> Type:
        """Convert bn struct type into a `Type` instance"""

        assert tinfo_.type_class == bn.TypeClass.StructureTypeClass
        tinfo = cast(bn.types.StructureType, tinfo_)

        if tinfo.type == bn.StructureVariant.UnionStructureType:
            return self._convert_union(tinfo)

        assert (
                tinfo.type == bn.StructureVariant.StructStructureType
                or tinfo.type == bn.StructureVariant.ClassStructureType
        )

        ret = StructureType()

        at_offset: List[Union[int, Type]] = [1] * tinfo.width
        num_bytes: int = len(at_offset)
        at_offset.append(0)

        # Collect the structure members that fall within the bounds of the
        # structure... just in case some elements manage to be outside.
        members: List[bn.StructureMember] = []
        for elem_ in tinfo.members:
            elem: bn.StructureMember = cast(bn.StructureMember, elem_)
            elem_offset: int = int(elem.offset * 1)
            elem_size: int = len(elem.type)
            if (elem_offset + elem_size) <= num_bytes:
                members.append(elem)

        # If struct has no registered name, don't put it in the
        # cache. It
        # is anonymous struct and can cause cache collision
        if tinfo.registered_name:
            self._cache[_cache_key(tinfo)] = ret

        # Assign slots to all fields that have a non-zero (i.e. non-void) size.
        skipped_members: List[bn.StructureMember] = []
        for elem in members:
            elem_size: int = len(elem.type)
            elem_ty: Type = self._convert_bn_type(elem.type)
            if isinstance(elem_ty, VoidType):
                skipped_members.append(elem)
                continue
            elif isinstance(elem_ty, FunctionType):
                WARN("Converting function type {elem} in structure {tinfo} into function pointer type")
                pt = PointerType()
                pt.set_element_type(elem_ty)
                elem_ty = pt
                elem_size = self._bv.address_size
            elif not elem_size:
                elem_size = elem_ty.size(self._arch)
                if not elem_size:
                    skipped_members.append(elem)
                    continue
            elem_offset: int = int(elem.offset * 1)
            for i in range(elem_offset, elem_offset + elem_size):
                at_offset[i] = 0
            assert not isinstance(elem_ty, FunctionType)
            assert not isinstance(elem_ty, VoidType)
            at_offset[elem_offset] = elem_ty

        # Try to handle "void" typed things. See if we can match them to being
        # pointers.
        for elem in skipped_members:

            # Count the amount of apparent padding.
            elem_offset: int = int(elem.offset)
            num_padding_found = 0
            i = elem_offset
            while i < num_bytes:
                if isinstance(at_offset[i], int) and at_offset[i] == 1:
                    num_padding_found += 1
                    i += 1
                else:
                    break

            if not num_padding_found:
                continue

            # Go fudge a type that fits within the padding and with the
            # alignment of the element.
            elem_ty: Optional[Type] = None
            if num_padding_found <= self._bv.address_size and \
                    (elem_offset % self._bv.address_size) == 0:
                elem_ty = IntegerType(self._bv.address_size, False)
                elem_size = self._bv.address_size
            elif num_padding_found <= 4 and (elem_offset % 4) == 0:
                elem_ty = IntegerType(4, False)
                elem_size = 4
            elif num_padding_found <= 2 and (elem_offset % 2) == 0:
                elem_ty = IntegerType(2, False)
                elem_size = 2
            else:
                elem_ty = IntegerType(1, False)
                elem_size = 1

            WARN(f"Treating structure {tinfo} element {elem} as having type {elem_ty}")

            # Clear out the padding.
            for i in range(elem_offset, elem_offset + elem_size):
                at_offset[i] = 0
            at_offset[elem_offset] = elem_ty

        # Introduce padding byte types.
        i: int = 0
        while i < num_bytes:
            if not isinstance(at_offset[i], int):
                i += 1
                continue

            # Accumulate the number of bytes of padding.
            j = i
            num_padding_bytes = 0
            while j <= num_bytes:
                if isinstance(at_offset[j], int):
                    num_padding_bytes += at_offset[j]
                    j += 1
                else:
                    break

            if num_padding_bytes:
                pt = PaddingType()
                pt.set_num_elements(num_padding_bytes)
                at_offset[i] = pt

            i = j

        for elem in at_offset:
            if isinstance(elem, Type):
                ret.add_element_type(elem)

        return ret

    def _convert_union(self, tinfo_: bn.Type) -> Type:
        """Convert bn union type into a `Type` instance"""

        assert tinfo_.type_class == bn.TypeClass.StructureTypeClass
        tinfo = cast(bn.types.StructureType, tinfo_)
        assert tinfo.type == bn.StructureVariant.UnionStructureType

        ret = UnionType()

        # If union has no registered name, don't put it in the cache. It
        # is anonymous union and can cause cache collision
        if tinfo.registered_name:
            self._cache[_cache_key(tinfo)] = ret
        for elem in tinfo.members:
            ret.add_element_type(self._convert_bn_type(elem.type))

        return ret

    def _convert_enum(self, tinfo_: bn.Type) -> Type:
        """Convert bn enum type into a `Type` instance"""

        assert tinfo_.type_class == bn.TypeClass.EnumerationTypeClass
        tinfo = cast(bn.types.EnumerationType)
        ret = EnumType()

        # If enum has no registered name, don't put it in the cache. It
        # is anonymous enum and can cause cache collision with other
        # anonymous enum
        if tinfo.registered_name:
            self._cache[_cache_key(tinfo)] = ret
        # The underlying type of enum will be an Integer of size info.width
        ret.set_underlying_type(IntegerType(tinfo.width, False))
        return ret

    def _convert_typedef(self, tinfo_: bn.Type) -> Type:
        """ Convert bn typedef into a `Type` instance"""

        assert tinfo_.type_class == \
               bn.NamedTypeReferenceClass.TypedefNamedTypeClass

        tinfo = cast(bn.NamedTypeReferenceType, tinfo_)
        ret = TypedefType()
        self._named_cache[tinfo.type_id] = ret
        ref_type = tinfo.target(self._bv)
        ret.set_underlying_type(self._convert_bn_type(ref_type))
        return ret

    def _convert_array(self, tinfo: bn.Type) -> Type:
        """ Convert bn pointer type into a `Type` instance"""

        assert tinfo.type_class == bn.TypeClass.ArrayTypeClass

        ret = ArrayType()
        self._cache[_cache_key(tinfo)] = ret
        ret.set_element_type(self._convert_bn_type(tinfo.element_type))
        ret.set_num_elements(tinfo.count)
        return ret

    def _convert_pointer(self, tinfo_: bn.Type) -> Type:
        """ Convert bn pointer type into a `Type` instance"""

        assert tinfo_.type_class == bn.TypeClass.PointerTypeClass
        tinfo = cast(bn.types.PointerType, tinfo_)

        ret = PointerType()
        self._cache[_cache_key(tinfo)] = ret
        ret.set_element_type(self._convert_bn_type(tinfo.target))
        return ret

    def _convert_function(self, tinfo_: bn.Type) -> Type:
        """ Convert bn function type into a `Type` instance"""

        assert tinfo_.type_class == bn.TypeClass.FunctionTypeClass
        tinfo = cast(bn.types.FunctionType, tinfo_)

        ret: FunctionType = FunctionType()
        self._cache[_cache_key(tinfo)] = ret
        ret.set_return_type(self._convert_bn_type(tinfo.return_value))

        for var in tinfo.parameters:
            param_type: Type = self._convert_bn_type(var.type)
            if isinstance(param_type, VoidType):
                WARN(f"Treating parameter type of {var} as address sized integer")
                ret.add_parameter_type(IntegerType(self._bv.address_size, False))
            else:
                ret.add_parameter_type(param_type)

        if tinfo.has_variable_arguments:
            ret.set_is_variadic()

        return ret

    def _convert_integer(self, tinfo_: bn.Type) -> Type:
        """ Convert bn integer type into a `Type` instance"""

        assert tinfo_.type_class == bn.TypeClass.IntegerTypeClass
        tinfo = cast(bn.types.IntegerType, tinfo_)

        # long double ty may get represented as int80_t. If the size
        # of the IntegerTypeClass is [10, 12], create a float type
        # int32_t (int32_t arg1, int80_t arg2 @ st0)
        if tinfo.width == 10 or tinfo.width == 12:
            return FloatingPointType(tinfo.width)
        else:
            return IntegerType(tinfo.width, _bool(tinfo.signed))

    def _convert_named_reference(self, tinfo_: bn.Type) -> Type:
        """ Convert named type references into a `Type` instance"""

        assert tinfo_.type_class == bn.TypeClass.NamedTypeReferenceClass
        tinfo = cast(bn.types.NamedTypeReferenceType, tinfo_)

        # See if we've already converted this type.
        type_id: str = tinfo.type_id
        if type_id in self._named_cache:
            return self._named_cache[type_id]

        ret: Optional[Type] = None
        ref_type = tinfo.target(self._bv)
        if ref_type is None:
            ret = VoidType()
        else:
            ret = self._convert_bn_type(ref_type)

        assert ret is not None
        self._named_cache[type_id] = ret
        return ret

    def _convert_bn_type(self, tinfo: bn.Type) -> Type:
        """Convert an bn `Type` instance into a `Type` instance."""

        try:
            if tinfo.altname in self._core_types:
                return self._core_types[tinfo.altname]

            if tinfo.name in self._core_types:
                return self._core_types[tinfo.name]
        except NotImplementedError:
            pass

        if tinfo.type_class == bn.TypeClass.NamedTypeReferenceClass:
            return self._convert_named_reference(tinfo)

        if _cache_key(tinfo) in self._cache:
            return self._cache[_cache_key(tinfo)]

        # Void type
        if tinfo.type_class == bn.TypeClass.VoidTypeClass:
            return VoidType()

        elif tinfo.type_class == bn.TypeClass.PointerTypeClass:
            return self._convert_pointer(tinfo)

        elif tinfo.type_class == bn.TypeClass.FunctionTypeClass:
            return self._convert_function(tinfo)

        elif tinfo.type_class == bn.TypeClass.ArrayTypeClass:
            return self._convert_array(tinfo)

        elif tinfo.type_class == bn.TypeClass.StructureTypeClass:
            return self._convert_struct(tinfo)

        elif tinfo.type_class == bn.TypeClass.EnumerationTypeClass:
            return self._convert_enum(tinfo)

        elif tinfo.type_class == bn.TypeClass.BoolTypeClass:
            return BoolType()

        elif tinfo.type_class == bn.TypeClass.IntegerTypeClass:
            return self._convert_integer(tinfo)

        elif tinfo.type_class == bn.TypeClass.FloatTypeClass:
            return FloatingPointType(tinfo.width)

        elif tinfo.type_class in TypeCache._err_type_class.keys():
            WARN(
                f"WARNING: Unhandled type class "
                f"{TypeCache._err_type_class[tinfo.type_class]}"
            )
            return VoidType()

        else:
            raise UnhandledTypeException(
                "Unhandled type: {}".format(str(tinfo)), tinfo)

    def get(self, ty: Optional[Union[bn.Type, Type, Function]]) -> Type:
        """Type class that gives access to type sizes, printings, etc."""

        if ty is None:
            return VoidType()

        elif isinstance(ty, Type):
            return ty

        elif isinstance(ty, Function):
            return ty.type()

        elif isinstance(ty, bn.Type):
            return self._convert_bn_type(ty)

        raise UnhandledTypeException("Unrecognized type passed to `Type`.", ty)
