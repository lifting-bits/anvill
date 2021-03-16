/*
 * Copyright (c) 2021 Trail of Bits, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "TransformationErrorManager.h"

namespace anvill {

void TransformationErrorManager::Insert(const TransformationError &error) {
  if (error.severity == SeverityType::Fatal) {
    has_fatal_error = true;
  }

  error_list.push_back(error);
}

void TransformationErrorManager::Reset(void) {
  error_list.clear();
  has_fatal_error = false;
}

bool TransformationErrorManager::HasFatalError(void) const {
  return has_fatal_error;
}

const std::vector<TransformationError> &
TransformationErrorManager::ErrorList(void) const {
  return error_list;
}

ITransformationErrorManager::Ptr ITransformationErrorManager::Create(void) {
  try {
    return Ptr(new TransformationErrorManager());

  } catch (const std::bad_alloc &) {
    return nullptr;
  }
}

}  // namespace anvill
