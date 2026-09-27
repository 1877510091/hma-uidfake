// SPDX-License-Identifier: GPL-2.0
#pragma once

#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "netlink.hpp"
#include "paths.hpp"
#include "watcher.hpp"

namespace uidfake {

/* Command line. The rule places and the package database are not options: this
 * reads where the tools and the package manager keep them. */
struct Config {
  bool once = false;
};

/* Prints the usage line to stderr and returns nullopt on a bad command line. */
[[nodiscard]] std::optional<Config> parse_args(int argc, char **argv);

class Syncer {
public:
  explicit Syncer(Config config) : config_(config) {}

  void sync_now(std::string_view why = "startup");

  /* Syncs once, then keeps following the files until it is killed. */
  [[nodiscard]] bool run();

private:
  /* One install or update: the "~~" directories that appeared or went away. */
  void handle_packages(const std::vector<std::string> &dirs);
  /* stat() every caller's code directory and push the result. */
  void publish_code_dirs();

  /* Where a config can be. Not a command line option: this reads where the apps
   * keep them. */
  const std::vector<RuleSource> sources_ = RuleSource::known();
  Config config_;
  bool config_refused_ = false;
  NetlinkClient netlink_;
  Watcher watcher_;
  /* The callers of the current policy: package name -> uid, and where their
   * code lives once it is known. */
  std::map<std::string, std::uint32_t, std::less<>> callers_;
  std::map<std::string, std::filesystem::path, std::less<>> code_dirs_;

  std::vector<Pair> pushed_;
  std::vector<ApkEntry> published_;
};

} // namespace uidfake
