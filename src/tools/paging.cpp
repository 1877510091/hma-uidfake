// SPDX-License-Identifier: GPL-2.0
#include "paging.hpp"

#include <cstring>
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

std::uint32_t crc32_bytes(std::span<const std::byte> bytes) {
  return ::crc32(0, reinterpret_cast<const Bytef *>(bytes.data()),
                 static_cast<uInt>(bytes.size()));
}

std::vector<std::byte> begin_payload(std::uint32_t kind,
                                     std::uint32_t total_bytes,
                                     std::uint32_t crc) {
  std::vector<std::byte> out(12);
  put_u32(out.data(), 0, kind);
  put_u32(out.data(), 4, total_bytes);
  put_u32(out.data(), 8, crc);
  return out;
}

std::vector<std::byte> page_payload(std::uint32_t offset,
                                    std::span<const std::byte> bytes) {
  const std::size_t padded = (bytes.size() + 3u) & ~std::size_t{3};
  std::vector<std::byte> out(8 + padded);

  put_u32(out.data(), 0, offset);
  put_u32(out.data(), 4, static_cast<std::uint32_t>(bytes.size()));
  std::memcpy(out.data() + 8, bytes.data(), bytes.size());
  return out;
}

std::vector<std::byte> page_payload(std::uint32_t first_pair,
                                    std::span<const Pair> pairs) {
  std::vector<std::byte> out(8 + 8 * pairs.size());
  put_u32(out.data(), 0, first_pair * 8u);
  put_u32(out.data(), 4, static_cast<std::uint32_t>(pairs.size() * 8u));
  for (std::size_t i = 0; i < pairs.size(); i++) {
    put_u32(out.data(), 8 + 8 * i, pairs[i].caller);
    put_u32(out.data(), 12 + 8 * i, pairs[i].target);
  }
  return out;
}

} // namespace uidfake
