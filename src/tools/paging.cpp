// SPDX-License-Identifier: GPL-2.0
#include "paging.hpp"

#include <zlib.h>

namespace uidfake {

std::uint32_t crc32(std::span<const Pair> pairs) {
  return static_cast<std::uint32_t>(
      ::crc32(0, reinterpret_cast<const Bytef *>(pairs.data()),
              static_cast<uInt>(pairs.size() * sizeof(Pair))));
}

} // namespace uidfake
