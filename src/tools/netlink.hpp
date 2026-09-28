// SPDX-License-Identifier: GPL-2.0
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "common.hpp"

namespace uidfake {

/* One apk of an app that has rules: the numbers the kernel compares, nothing
 * else. */
struct ApkEntry {
  std::uint32_t dev = 0; /* st_dev exactly as stat(2) reported it */
  std::uint64_t ino = 0;
  std::uint32_t uid = 0;
};

/*
 * Talks to the module's generic netlink family. The family itself only accepts
 * requests from processes holding CAP_NET_ADMIN and is invisible to app
 * domains, so the policy never travels over a path an app could read.
 */
class NetlinkClient {
public:
  NetlinkClient() = default;

  NetlinkClient(const NetlinkClient &) = delete;
  NetlinkClient &operator=(const NetlinkClient &) = delete;

  /* The kernel holds at most POLICY_MAX_PAIRS pairs (src/include/uidfake.h),
   * and one page carries kPagePairs of them. */
  static constexpr std::size_t kMaxPairs = 65536;

  /* Replaces the kernel's policy with `pairs` (an empty list clears it).
   * Failures are logged; false means the kernel side is not reachable yet. */
  [[nodiscard]] bool push(std::span<const Pair> pairs);

  /* Replaces the kernel's caller-apk inode table (an empty list clears it). */
  [[nodiscard]] bool push_apks(std::span<const ApkEntry> entries);

private:
  static constexpr std::string_view kFamilyName = "kaux";
  /* Must match the enum and the version in src/netlink.c. */
  static constexpr std::uint8_t kCmdSetBegin = 1;
  static constexpr std::uint8_t kCmdSetPage = 2;
  static constexpr std::uint8_t kCmdSetCommit = 3;
  static constexpr std::uint8_t kCmdPing = 4;
  static constexpr std::uint8_t kCmdApk = 5;
  static constexpr std::uint8_t kUapiVersion = 2;
  static constexpr std::uint16_t kAttrBlob = 1;
  static constexpr std::size_t kReplySize = 4096;

  /* One line per outage, and one when it ends. */
  void note_reachable();
  [[nodiscard]] bool ensure_connected();
  [[nodiscard]] bool send_apks_once(std::span<const ApkEntry> entries);
  [[nodiscard]] bool send_paged(std::span<const Pair> pairs);
  [[nodiscard]] bool send_command(std::uint8_t cmd,
                                  std::span<const std::byte> blob);
  [[nodiscard]] std::optional<std::uint16_t> resolve_family();
  [[nodiscard]] bool exchange(std::span<const std::byte> request,
                              std::span<std::byte> reply);

  Fd socket_;
  std::optional<std::uint16_t> family_;
  /* One line per outage, not one per attempt: the syncer retries while the
   * module is not loaded, and the same warning every ten seconds is noise. */
  bool warned_ = false;
  std::uint32_t seq_ = 0; /* one per request; replies are matched against it */
};

} // namespace uidfake
