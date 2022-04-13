/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <remill/Arch/Arch.h>

namespace anvill {

remill::Arch::ArchPtr BuildArch(llvm::LLVMContext &context,
                                remill::ArchName arch_name,
                                remill::OSName os_name);

}  // namespace anvill
