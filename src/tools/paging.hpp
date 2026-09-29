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

/* The three messages a policy upload is made of, byte for byte as src/netlink.c
 * reads them. */
[[nodiscard]] std::vector<std::byte>
begin_payload(std::uint32_t kind, std::uint32_t total_bytes, std::uint32_t crc);
[[nodiscard]] std::vector<std::byte>
page_payload(std::uint32_t offset, std::span<const std::byte> bytes);
/* The same header for a page of pairs, which the policy upload still sends. */
[[nodiscard]] std::vector<std::byte> page_payload(std::uint32_t first_pair,
                                                  std::span<const Pair> pairs);

/* A blob's CRC, over exactly the bytes that go up. */
[[nodiscard]] std::uint32_t crc32_bytes(std::span<const std::byte> bytes);

/* Pairs per message: the page header is 8 bytes and the kernel takes at most
 * 32 KiB (MAX_BLOB_BYTES). */
inline constexpr std::size_t kPagePairs = 4090;
/* Bytes per message for a blob that is not pairs. */
inline constexpr std::size_t kPageBytes = 8184;

} // namespace uidfake
