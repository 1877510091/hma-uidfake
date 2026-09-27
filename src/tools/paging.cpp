// SPDX-License-Identifier: GPL-2.0
#include "paging.hpp"

#include <zlib.h>

namespace uidfake {

std::uint32_t crc32(std::span<const Pair> pairs) {
  return static_cast<std::uint32_t>(
      ::crc32(0, reinterpret_cast<const Bytef *>(pairs.data()),
              static_cast<uInt>(pairs.size() * sizeof(Pair))));
}

namespace {

void put_u32(std::byte *out, std::size_t index, std::uint32_t value) {
  for (std::uint32_t i = 0; i < 4; i++)
    out[index + i] = static_cast<std::byte>((value >> (8 * i)) & 0xffu);
}

} // namespace

std::vector<std::byte> begin_payload(std::uint32_t total, std::uint32_t crc) {
  std::vector<std::byte> out(12);
  put_u32(out.data(), 0, total);
  put_u32(out.data(), 4, 2 * total);
  put_u32(out.data(), 8, crc);
  return out;
}

std::vector<std::byte> page_payload(std::uint32_t seq,
                                    std::span<const Pair> pairs) {
  std::vector<std::byte> out(8 + 8 * pairs.size());
  put_u32(out.data(), 0, seq);
  put_u32(out.data(), 4, static_cast<std::uint32_t>(pairs.size()));
  for (std::size_t i = 0; i < pairs.size(); i++) {
    put_u32(out.data(), 8 + 8 * i, pairs[i].caller);
    put_u32(out.data(), 12 + 8 * i, pairs[i].target);
  }
  return out;
}

} // namespace uidfake
