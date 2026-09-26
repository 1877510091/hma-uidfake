// SPDX-License-Identifier: GPL-2.0
#pragma once

#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "netlink.hpp"
#include "watcher.hpp"

namespace uidfake {

/* Paths and flags coming from the command line. */
struct Config {
  std::filesystem::path config =
      "/data/user/0/com.tsng.hidemyapplist/files/config.json";
  std::filesystem::path packages_xml = "/data/system/packages.xml";
  bool once = false;
};

/* Prints the usage line to stderr and returns nullopt on a bad command line. */
[[nodiscard]] std::optional<Config> parse_args(int argc, char **argv);

/*
 * Ties everything together: evaluate HMA's rules against the package database
 * and hand the result to the kernel. One process, no temporary files.
 *
 * Two sources, two jobs. The rules and the uid of every package come from
 * packages.list, which is read when something changed and never watched; the
 * directory a package's code lives in comes from the package manager itself
 * ("pm list packages -f -U"), because that name is random and asking for it is
 * the only way to learn it without reading /data/app. After that, installs and
 * updates arrive as events from /data/app, and only the directory named by the
 * event is read - one readdir, one stat, no walking.
 */
class Syncer {
public:
  explicit Syncer(Config config) : config_(std::move(config)) {}

  /* Parses and pushes once; failures are logged, never fatal. */
  void sync_now();

  /* Syncs once, then keeps following the files until it is killed. */
  [[nodiscard]] bool run();

private:
  /* One install or update: the "~~" directories that appeared or went away. */
  void handle_packages(const std::vector<std::string> &dirs);
  /* stat() every caller's code directory and push the result. */
  void publish_code_dirs();

  Config config_;
  bool config_refused_ = false;
  NetlinkClient netlink_;
  Watcher watcher_;
  /* The callers of the current policy: package name -> uid, and where their
   * code lives once it is known. */
  std::map<std::string, std::uint32_t, std::less<>> callers_;
  std::map<std::string, std::filesystem::path, std::less<>> code_dirs_;
};

} // namespace uidfake
