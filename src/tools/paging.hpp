// SPDX-License-Identifier: GPL-2.0
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "common.hpp"

namespace uidfake {

/* The CRC32 the kernel checks the staged policy with. The kernel uses crc32_le
 * and this is zlib's crc32; the two agree on the same bytes, which paging_test
 * pins down against an independent value. */
[[nodiscard]] std::uint32_t crc32(std::span<const Pair> pairs);

/* Pairs per message: the page header is 8 bytes and the kernel takes at most
 * 32 KiB (MAX_BLOB_BYTES). */
inline constexpr std::size_t kPagePairs = 4090;

} // namespace uidfake
