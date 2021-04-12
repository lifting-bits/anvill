
#include "Byte.h"
#include "ByteSequence.h"

namespace anvill {
ByteSequence::ByteSequence(uint64_t addr_, Byte::Data *first_data_, Byte::Meta *first_meta_, size_t size_) : address(addr_), first_data(first_data_), first_meta(first_meta_), size(size_) {}

ByteSequence::operator bool(void) const {
  return first_data != nullptr;
}

size_t ByteSequence::Size(void) const {
  return size;
}

uint64_t ByteSequence::Address(void) const {
  return address;
}

std::string_view ByteSequence::ToString(void) const {
  if (first_data) {
    return std::string_view(reinterpret_cast<const char *>(first_data), size);
  } else {
    return std::string_view();
  }
}

std::string_view ByteSequence::Substring(uint64_t ea, size_t seq_size) const {
  if (const auto offset = ea - address; address <= ea && offset < size) {
    std::string_view data(reinterpret_cast<const char *>(first_data), size);
    if (auto max_ea = ea + seq_size; max_ea > (address + size)) {
      return data.substr(offset, size - offset);
    } else {
      return data.substr(offset, seq_size);
    }
  } else {
    return std::string_view();
  }
}

Byte ByteSequence::operator[](uint64_t ea) const {
  if (const auto offset = ea - address; address <= ea && offset < size) {
    return Byte(ea, &(first_data[offset]), &(first_meta[offset]));
  } else {
    return Byte();
  }
}

}
