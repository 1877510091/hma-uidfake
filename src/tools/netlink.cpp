// SPDX-License-Identifier: GPL-2.0
#include "netlink.hpp"

#include "paging.hpp"

#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <cstring>
#include <vector>

namespace uidfake {
namespace {

/*
 * The NDK UAPI headers only ship NLA_ALIGN/NLA_HDRLEN plus macros that do not
 * handle const pointers, so iterate explicitly with a byte cursor and these two
 * predicates.
 */
[[nodiscard]] bool nlmsg_ok(const nlmsghdr *header, int left) {
  return left >= static_cast<int>(sizeof(nlmsghdr)) &&
         header->nlmsg_len >= sizeof(nlmsghdr) &&
         static_cast<int>(header->nlmsg_len) <= left;
}

[[nodiscard]] bool nlattr_ok(const nlattr *attr, int left) {
  return left >= static_cast<int>(sizeof(nlattr)) &&
         attr->nla_len >= sizeof(nlattr) &&
         static_cast<int>(attr->nla_len) <= left;
}

[[nodiscard]] const nlmsghdr *nlmsg_next(const nlmsghdr *header) {
  return reinterpret_cast<const nlmsghdr *>(
      reinterpret_cast<const std::byte *>(header) +
      NLMSG_ALIGN(header->nlmsg_len));
}

[[nodiscard]] const nlattr *nlattr_next(const nlattr *attr) {
  return reinterpret_cast<const nlattr *>(
      reinterpret_cast<const std::byte *>(attr) + NLA_ALIGN(attr->nla_len));
}

/* Little endian, matching the kernel side (see src/netlink.c). */
void store_u32(std::span<std::byte> out, std::size_t index,
               std::uint32_t value) {
  out[index + 0] = static_cast<std::byte>(value & 0xff);
  out[index + 1] = static_cast<std::byte>((value >> 8) & 0xff);
  out[index + 2] = static_cast<std::byte>((value >> 16) & 0xff);
  out[index + 3] = static_cast<std::byte>((value >> 24) & 0xff);
}

/* A netlink buffer with typed views into its header area. */
struct Buffer {
  std::vector<std::byte> bytes;

  [[nodiscard]] nlmsghdr *nlmsg() {
    return reinterpret_cast<nlmsghdr *>(bytes.data());
  }
  [[nodiscard]] genlmsghdr *genlmsg() {
    return reinterpret_cast<genlmsghdr *>(bytes.data() + NLMSG_HDRLEN);
  }
};

} // namespace

bool NetlinkClient::exchange(std::span<const std::byte> request,
                             std::span<std::byte> reply) {
  sockaddr_nl address{};
  address.nl_family = AF_NETLINK;

  iovec iov{.iov_base = const_cast<std::byte *>(request.data()),
            .iov_len = request.size()};
  msghdr message{};
  message.msg_name = &address;
  message.msg_namelen = sizeof(address);
  message.msg_iov = &iov;
  message.msg_iovlen = 1;

  if (::sendmsg(socket_.get(), &message, 0) < 0) {
    Log::warn("sendmsg: {}", std::strerror(errno));
    return false;
  }

  iov.iov_base = reply.data();
  iov.iov_len = reply.size();
  const ssize_t received = ::recvmsg(socket_.get(), &message, 0);
  if (received < 0) {
    /* EAGAIN is the read deadline firing: the module is gone or never answered.
     */
    Log::warn("recvmsg: {}", errno == EAGAIN
                                 ? "timed out waiting for the kernel"
                                 : std::strerror(errno));
    return false;
  }

  const auto *header = reinterpret_cast<const nlmsghdr *>(reply.data());
  bool answered = false;
  for (int left = static_cast<int>(received); nlmsg_ok(header, left);) {
    const int step = static_cast<int>(NLMSG_ALIGN(header->nlmsg_len));
    if (header->nlmsg_seq != seq_) {
      /* A late reply to a request that already timed out; ignore it. */
      left -= step;
      header = nlmsg_next(header);
      continue;
    }
    if (header->nlmsg_type == NLMSG_ERROR) {
      const auto *error =
          reinterpret_cast<const nlmsgerr *>(NLMSG_DATA(header));
      if (error->error != 0) {
        Log::warn("netlink error: {}", std::strerror(-error->error));
        return false;
      }
    }
    answered = true;
    left -= step;
    header = nlmsg_next(header);
  }
  return answered;
}

std::optional<std::uint16_t> NetlinkClient::resolve_family() {
  if (!ensure_connected())
    return std::nullopt;

  Buffer request{};
  const std::size_t name_len = kFamilyName.size() + 1;
  request.bytes.assign(NLMSG_SPACE(GENL_HDRLEN) + NLA_HDRLEN + name_len,
                       std::byte{0});

  auto *nlh = request.nlmsg();
  nlh->nlmsg_len =
      NLMSG_LENGTH(GENL_HDRLEN + NLA_HDRLEN + static_cast<int>(name_len));
  nlh->nlmsg_type = GENL_ID_CTRL;
  nlh->nlmsg_flags = NLM_F_REQUEST;
  nlh->nlmsg_seq = ++seq_;

  auto *genl = request.genlmsg();
  genl->cmd = CTRL_CMD_GETFAMILY;
  genl->version = kUapiVersion;

  auto *attr = reinterpret_cast<nlattr *>(reinterpret_cast<std::byte *>(genl) +
                                          GENL_HDRLEN);
  attr->nla_type = CTRL_ATTR_FAMILY_NAME;
  attr->nla_len = NLA_HDRLEN + static_cast<int>(name_len);
  std::memcpy(reinterpret_cast<std::byte *>(attr) + NLA_HDRLEN,
              kFamilyName.data(), name_len);

  std::vector<std::byte> reply(kReplySize);
  if (!exchange(request.bytes, reply))
    return std::nullopt;

  const auto *header = reinterpret_cast<const nlmsghdr *>(reply.data());
  for (int left = static_cast<int>(reply.size()); nlmsg_ok(header, left);) {
    if (header->nlmsg_type == NLMSG_ERROR)
      break;

    const auto *genl = reinterpret_cast<const genlmsghdr *>(NLMSG_DATA(header));
    int attr_left = static_cast<int>(header->nlmsg_len) -
                    static_cast<int>(NLMSG_LENGTH(GENL_HDRLEN));
    const auto *attr = reinterpret_cast<const nlattr *>(
        reinterpret_cast<const std::byte *>(genl) + GENL_HDRLEN);
    while (nlattr_ok(attr, attr_left)) {
      if (attr->nla_type == CTRL_ATTR_FAMILY_ID) {
        std::uint16_t id = 0;
        std::memcpy(&id, reinterpret_cast<const std::byte *>(attr) + NLA_HDRLEN,
                    sizeof(id));
        return id;
      }
      attr_left -= static_cast<int>(NLA_ALIGN(attr->nla_len));
      attr = nlattr_next(attr);
    }

    left -= static_cast<int>(NLMSG_ALIGN(header->nlmsg_len));
    header = nlmsg_next(header);
  }

  if (!warned_) {
    warned_ = true;
    Log::warn("generic netlink family {} not found (module not loaded?)",
              kFamilyName);
  }
  return std::nullopt;
}

bool NetlinkClient::ensure_connected() {
  if (socket_.valid())
    return true;

  const int fd = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
  if (fd < 0) {
    Log::warn("socket: {}", std::strerror(errno));
    return false;
  }

  sockaddr_nl address{};
  address.nl_family = AF_NETLINK;
  if (::bind(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) < 0) {
    Log::warn("bind: {}", std::strerror(errno));
    ::close(fd);
    return false;
  }

  /*
   * Both directions need a deadline. If the module is unloaded between our
   * request and the reply there is nothing to receive, and without one the
   * helper would sit in recvmsg() forever: that is the "cannot connect after
   * rmmod/insmod" symptom.
   */
  timeval deadline{.tv_sec = 0, .tv_usec = 500'000};
  ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &deadline, sizeof(deadline));
  ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &deadline, sizeof(deadline));

  socket_.reset(fd);
  return true;
}

void NetlinkClient::note_reachable() {
  if (!warned_)
    return;
  warned_ = false;
  Log::info("kernel side reachable again");
}

bool NetlinkClient::push(std::span<const Pair> pairs) {
  /* Every policy goes up in pages: one message per page, then a commit that the
   * kernel checks against the total and the CRC before it switches. A policy
   * that arrives half way never takes effect. */
  for (int attempt = 0; attempt < 2; ++attempt) {
    if (send_paged(pairs)) {
      note_reachable();
      return true;
    }
    family_.reset();
    socket_.reset();
  }
  if (!warned_) {
    warned_ = true;
    Log::warn("kernel side unreachable, keeping the previous policy");
  }
  return false;
}

bool NetlinkClient::send_command(std::uint8_t cmd,
                                 std::span<const std::byte> blob) {
  if (!ensure_connected())
    return false;

  if (!family_) {
    const auto resolved = resolve_family();
    if (!resolved)
      return false;
    family_ = resolved;
  }

  Buffer request{};
  request.bytes.assign(NLMSG_SPACE(GENL_HDRLEN) +
                           NLA_ALIGN(NLA_HDRLEN + blob.size()),
                       std::byte{0});

  auto *nlh = request.nlmsg();
  nlh->nlmsg_len =
      NLMSG_LENGTH(GENL_HDRLEN + NLA_HDRLEN + static_cast<int>(blob.size()));
  nlh->nlmsg_type = *family_;
  nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  nlh->nlmsg_seq = ++seq_;

  auto *genl = request.genlmsg();
  genl->cmd = cmd;
  genl->version = 1;

  auto *attr = reinterpret_cast<nlattr *>(reinterpret_cast<std::byte *>(genl) +
                                          GENL_HDRLEN);
  attr->nla_type = kAttrBlob;
  attr->nla_len = NLA_HDRLEN + static_cast<int>(blob.size());
  std::memcpy(reinterpret_cast<std::byte *>(attr) + NLA_HDRLEN, blob.data(),
              blob.size());

  std::vector<std::byte> reply(kReplySize);
  return exchange(std::span{request.bytes}.first(nlh->nlmsg_len), reply);
}

bool NetlinkClient::send_paged(std::span<const Pair> pairs) {
  const auto total = static_cast<std::uint32_t>(pairs.size());
  std::vector<std::byte> begin(12);
  store_u32(begin, 0, total);
  store_u32(begin, 4, 2 * total);
  store_u32(begin, 8, crc32(pairs));
  if (!send_command(kCmdSetBegin, begin))
    return false;

  for (std::size_t sent = 0; sent < pairs.size();) {
    const std::size_t n = std::min(kPagePairs, pairs.size() - sent);
    std::vector<std::byte> page(8 + 8 * n);
    store_u32(page, 0, static_cast<std::uint32_t>(sent));
    store_u32(page, 4, static_cast<std::uint32_t>(n));
    for (std::size_t i = 0; i < n; ++i) {
      store_u32(page, 8 + 8 * i, pairs[sent + i].caller);
      store_u32(page, 12 + 8 * i, pairs[sent + i].target);
    }
    if (!send_command(kCmdSetPage, page))
      return false; /* the kernel never saw a commit: the live policy stays */
    sent += n;
  }

  return send_command(kCmdSetCommit, {});
}

bool NetlinkClient::push_apks(std::span<const ApkEntry> entries) {
  for (int attempt = 0; attempt < 2; ++attempt) {
    if (send_apks_once(entries)) {
      note_reachable();
      return true;
    }
    family_.reset();
    socket_.reset();
  }
  if (!warned_) {
    warned_ = true;
    Log::warn("kernel side unreachable, caller apk table unchanged");
  }
  return false;
}

bool NetlinkClient::send_apks_once(std::span<const ApkEntry> entries) {
  if (!ensure_connected())
    return false;

  if (!family_) {
    const auto resolved = resolve_family();
    if (!resolved)
      return false;
    family_ = resolved;
  }

  const std::size_t blob_len = sizeof(std::uint32_t) * (1 + 4 * entries.size());
  Buffer request{};
  request.bytes.assign(NLMSG_SPACE(GENL_HDRLEN) +
                           NLA_ALIGN(NLA_HDRLEN + blob_len),
                       std::byte{0});

  auto *nlh = request.nlmsg();
  nlh->nlmsg_len =
      NLMSG_LENGTH(GENL_HDRLEN + NLA_HDRLEN + static_cast<int>(blob_len));
  nlh->nlmsg_type = *family_;
  nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  nlh->nlmsg_seq = ++seq_;

  auto *genl = request.genlmsg();
  genl->cmd = kCmdApk;
  genl->version = 1;

  auto *attr = reinterpret_cast<nlattr *>(reinterpret_cast<std::byte *>(genl) +
                                          GENL_HDRLEN);
  attr->nla_type = kAttrBlob;
  attr->nla_len = NLA_HDRLEN + static_cast<int>(blob_len);

  std::span<std::byte> blob(reinterpret_cast<std::byte *>(attr) + NLA_HDRLEN,
                            blob_len);
  store_u32(blob, 0, static_cast<std::uint32_t>(entries.size()));
  for (std::size_t i = 0; i < entries.size(); ++i) {
    const std::size_t at = 4 + 16 * i;
    store_u32(blob, at + 0, entries[i].dev);
    store_u32(blob, at + 4,
              static_cast<std::uint32_t>(entries[i].ino & 0xffffffffu));
    store_u32(blob, at + 8, static_cast<std::uint32_t>(entries[i].ino >> 32));
    store_u32(blob, at + 12, entries[i].uid);
  }

  std::vector<std::byte> reply(kReplySize);
  return exchange(std::span{request.bytes}.first(nlh->nlmsg_len), reply);
}

} // namespace uidfake
