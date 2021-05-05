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


import binaryninja as bn


from .callingconvention import *


from anvill.type import *
from anvill.function import *
from anvill.util import *


class TypeCache:
    """The class provides API to recursively visit the binja types and convert
    them to the anvill `Type` instance. It maintains a cache of visited binja
    types to reduce lookup time.
    """

    __slots__ = ("_bv", "_cache")

    # list of unhandled type classes which should log error
    _err_type_class = {
        bn.TypeClass.VarArgsTypeClass: "VarArgsTypeClass",
        bn.TypeClass.ValueTypeClass: "ValueTypeClass",
        bn.TypeClass.WideCharTypeClass: "WideCharTypeClass",
    }

    def __init__(self, bv):
        self._bv = bv
        self._cache = dict()

    def _cache_key(self, tinfo: bn.types.Type):
        """ Convert bn Type instance to cache key"""
        return str(tinfo)

    def _convert_struct(self, tinfo: bn.types.Type) -> Type:
        """Convert bn struct type into a `Type` instance"""

        assert tinfo.type_class == bn.TypeClass.StructureTypeClass

        if tinfo.structure.type == bn.StructureType.UnionStructureType:
            return self._convert_union(tinfo)

        assert (
            tinfo.structure.type == bn.StructureType.StructStructureType
            or tinfo.structure.type == bn.StructureType.ClassStructureType
        )

        ret = StructureType()
        self._cache[self._cache_key(tinfo)] = ret
        for elem in tinfo.structure.members:
            ret.add_element_type(self._convert_bn_type(elem.type))

        return ret

    def _convert_union(self, tinfo: bn.types.Type) -> Type:
        """Convert bn union type into a `Type` instance"""

        assert tinfo.structure.type == bn.StructureType.UnionStructureType

        ret = UnionType()
        self._cache[self._cache_key(tinfo)] = ret
        for elem in tinfo.structure.members:
            ret.add_element_type(self._convert_bn_type(elem.type))

        return ret

    def _convert_enum(self, tinfo: bn.types.Type) -> Type:
        """Convert bn enum type into a `Type` instance"""

        assert tinfo.type_class == bn.TypeClass.EnumerationTypeClass

        ret = EnumType()
        self._cache[self._cache_key(tinfo)] = ret
        # The underlying type of enum will be an Interger of size info.width
        ret.set_underlying_type(IntegerType(tinfo.width, False))
        return ret

    def _convert_typedef(self, tinfo: bn.types.Type) -> Type:
        """ Convert bn typedef into a `Type` instance"""

        assert tinfo.type_class == bn.NamedTypeReferenceClass.TypedefNamedTypeClass

        ret = TypedefType()
        self._cache[self._cache_key(tinfo)] = ret
        ret.set_underlying_type(
            self._convert_bn_type(self._bv.get_type_by_name(tinfo.name))
        )
        return ret

    def _convert_array(self, tinfo: bn.types.Type) -> Type:
        """ Convert bn pointer type into a `Type` instance"""

        assert tinfo.type_class == bn.TypeClass.ArrayTypeClass

        ret = ArrayType()
        self._cache[self._cache_key(tinfo)] = ret
        ret.set_element_type(self._convert_bn_type(tinfo.element_type))
        ret.set_num_elements(tinfo.count)
        return ret

    def _convert_pointer(self, tinfo) -> Type:
        """ Convert bn pointer type into a `Type` instance"""

        assert tinfo.type_class == bn.TypeClass.PointerTypeClass

        ret = PointerType()
        self._cache[self._cache_key(tinfo)] = ret
        ret.set_element_type(self._convert_bn_type(tinfo.element_type))
        return ret

    def _convert_function(self, tinfo) -> Type:
        """ Convert bn function type into a `Type` instance"""

        assert tinfo.type_class == bn.TypeClass.FunctionTypeClass

        ret = FunctionType()
        self._cache[self._cache_key(tinfo)] = ret
        ret.set_return_type(self._convert_bn_type(tinfo.return_value))

        for var in tinfo.parameters:
            ret.add_parameter_type(self._convert_bn_type(var.type))

        if tinfo.has_variable_arguments:
            ret.set_is_variadic()

        return ret

    def _convert_integer(self, tinfo) -> Type:
        """ Convert bn integer type into a `Type` instance"""

        assert tinfo.type_class == bn.TypeClass.IntegerTypeClass

        # long double ty may get represented as int80_t. If the size
        # of the IntegerTypeClass is [10, 12], create a float type
        # int32_t (int32_t arg1, int80_t arg2 @ st0)
        if tinfo.width in [1, 2, 4, 8, 16]:
            return IntegerType(tinfo.width, True)
        elif tinfo.width in [10, 12]:
            return FloatingPointType(tinfo.width)
        else:
            # if width is not from one specified. get the default size
            # to bv.address_size
            return IntegerType(self._bv.address_size, True)

    def _convert_named_reference(self, tinfo: bn.types.Type) -> Type:
        """ Convert named type references into a `Type` instance"""

        assert tinfo.type_class == bn.TypeClass.NamedTypeReferenceClass

        named_tinfo = tinfo.named_type_reference

        ref_type = self._bv.get_type_by_name(named_tinfo.name)
        if ref_type is None:
            # check if the reference is present with type_id
            ref_type = self._bv.get_type_by_id(named_tinfo.type_id)

            # A reference type for the named references could be None. Add warning
            # log and return Interger of width tinfo.width or self._bv.address_size
            if ref_type is None:
                DEBUG(
                    "WARNING: failed to get reference type for named references {}".format(
                        named_tinfo
                    )
                )
                return (
                    IntegerType(self._bv.address_size, False)
                    if tinfo.width == 0
                    else IntegerType(tinfo.width, False)
                )

        if named_tinfo.type_class == bn.NamedTypeReferenceClass.StructNamedTypeClass:
            return self._convert_struct(ref_type)

        elif named_tinfo.type_class == bn.NamedTypeReferenceClass.UnionNamedTypeClass:
            return self._convert_union(ref_type)

        elif named_tinfo.type_class == bn.NamedTypeReferenceClass.TypedefNamedTypeClass:
            return self._convert_typedef(named_tinfo)

        elif named_tinfo.type_class == bn.NamedTypeReferenceClass.EnumNamedTypeClass:
            return self._convert_enum(ref_type)

        else:
            WARN(f"WARNING: Unknown named type {named_tinfo} not handled")
            return (
                IntegerType(self._bv.address_size, False)
                if tinfo.width == 0
                else IntegerType(tinfo.width, False)
            )

    def _convert_bn_type(self, tinfo: bn.types.Type) -> Type:
        """Convert an bn `Type` instance into a `Type` instance."""

        if self._cache_key(tinfo) in self._cache:
            return self._cache[self._cache_key(tinfo)]

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

        elif tinfo.type_class == bn.TypeClass.NamedTypeReferenceClass:
            return self._convert_named_reference(tinfo)

        elif tinfo.type_class in TypeCache._err_type_class.keys():
            WARN(
                f"WARNING: Unhandled type class {TypeCache._err_type_class[tinfo.type_class]}"
            )
            return VoidType()

        else:
            raise UnhandledTypeException("Unhandled type: {}".format(str(tinfo)), tinfo)

    def get(self, ty) -> Type:
        """Type class that gives access to type sizes, printings, etc."""

        if isinstance(ty, Type):
            return ty

        elif isinstance(ty, Function):
            return ty.type()

        elif isinstance(ty, bn.Type):
            return self._convert_bn_type(ty)

        elif not ty:
            return VoidType()

        raise UnhandledTypeException("Unrecognized type passed to `Type`.", ty)
