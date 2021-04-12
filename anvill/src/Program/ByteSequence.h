#pragma once

#include "Byte.h"

namespace anvill {

// Abstraction around a byte sequence.
class ByteSequence {
 public:
  ByteSequence(uint64_t addr_, Byte::Data *first_data_, Byte::Meta *first_meta_, size_t size_);

  operator bool(void) const;
  size_t Size(void) const;
  uint64_t Address(void) const;

  // Convert this byte sequence to a string.
  std::string_view ToString(void) const;

  // Extract a substring of bytes from this byte sequence.
  std::string_view Substring(uint64_t ea, size_t seq_size) const;

  // Index a specific byte within this sequence. Indexing is based off of the
  // byte's address.
  Byte operator[](uint64_t ea) const;

 private:
  uint64_t address{0};
  Byte::Data *first_data{nullptr};
  Byte::Meta *first_meta{nullptr};  // Inclusive.
  size_t size{0};
};

}
