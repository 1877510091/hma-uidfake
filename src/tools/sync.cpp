// SPDX-License-Identifier: GPL-2.0
#include "sync.hpp"

#include <sys/stat.h>

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <utility>

#include "common.hpp"
#include "hma.hpp"
#include "packages.hpp"

namespace uidfake {
namespace {

/* /data/user/0/<pkg> is a bind mount of /data/data/<pkg>; an old ROM or a
 * plain adb shell may only have the second one. */
constexpr std::string_view kDataUserPrefix = "/data/user/0/";
constexpr std::string_view kDataDataPrefix = "/data/data/";

std::filesystem::path resolve_config_path(const std::filesystem::path &path) {
  std::error_code ignored;
  if (std::filesystem::exists(path, ignored))
    return path;

  auto text = path.string();
  if (text.starts_with(kDataUserPrefix)) {
    text.replace(0, kDataUserPrefix.size(), kDataDataPrefix);
    const std::filesystem::path alternative{text};
    if (std::filesystem::exists(alternative, ignored))
      return alternative;
  }
  return path;
}

/* Where installed code lives; the same root the watcher reports events from. */
constexpr std::string_view kAppRoot = "/data/app";
/* The kernel takes this many caller code dirs. */
constexpr std::size_t kApkLimit = 1024;

/* "<package>-<random suffix>": the entry that names a package inside an install
 * directory. The suffix is base64 and may contain "-" itself, so the caller's
 * name is matched as a prefix rather than by splitting the string. */
[[nodiscard]] bool dir_matches(std::string_view leaf, std::string_view pkg) {
  return leaf.size() > pkg.size() && leaf.compare(0, pkg.size(), pkg) == 0 &&
         leaf[pkg.size()] == '-';
}

} // namespace

std::optional<Config> parse_args(int argc, char **argv) {
  Config config;
  for (int i = 1; i < argc; ++i) {
    const std::string_view arg = argv[i];
    const bool has_value = i + 1 < argc;
    if (arg == "--once") {
      config.once = true;
    } else if (arg == "--config" && has_value) {
      config.config = argv[++i];
    } else if (arg == "--xml" && has_value) {
      config.packages_xml = argv[++i];
    } else {
      std::fprintf(
          stderr,
          "usage: %s [--once] [--config <json>] [--xml <packages.xml>]\n",
          argc > 0 ? argv[0] : "sync-tool");
      return std::nullopt;
    }
  }
  config.config = resolve_config_path(config.config);
  return config;
}

void Syncer::sync_now(std::string_view why) {
  const auto policy = HmaPolicy::load(config_.config);
  if (!policy) {
    /* Once per outage: before the unlock this used to repeat on every tick. */
    if (!config_refused_) {
      config_refused_ = true;
      Log::warn("cannot read {} yet (keeping the previous policy)",
                config_.config.string());
    }
    return;
  }
  if (config_refused_) {
    config_refused_ = false;
    Log::info("{} is readable again", config_.config.string());
  }

  const auto packages = PackageDb::load(config_.packages_xml);
  if (!packages) {
    Log::warn("cannot read {} (will retry on the next event)",
              config_.packages_xml.string());
    return;
  }

  const Pairs pairs = policy->expand(*packages);

  const auto same_pair = [](const Pair &a, const Pair &b) {
    return a.caller == b.caller && a.target == b.target;
  };
  if (!std::ranges::equal(pairs, pushed_, same_pair)) {
    if (!netlink_.push(pairs)) {
      /* The kernel keeps its policy, and this pass asks for a retry: a module
       * loaded a second later would otherwise wait for the next event. */
      watcher_.arm_retry();
      return;
    }
    pushed_.assign(pairs.begin(), pairs.end());
    Log::info("synced {} pair(s) ({})", pairs.size(), why);
  }

  /*
   * Which packages are callers. A rule with caller == 0 applies to anyone, so
   * then every package is one. Names, not only uids: the directory a caller's
   * code lives in is looked up by name.
   */
  std::set<std::uint32_t> caller_uids;
  bool wild = false;
  for (const auto &pair : pairs) {
    if (pair.caller == 0)
      wild = true;
    else
      caller_uids.insert(pair.caller);
  }

  callers_.clear();
  for (const auto &[name, info] : packages->by_name()) {
    if (wild || caller_uids.contains(info.uid))
      callers_.emplace(name, info.uid);
  }

  /* The code directory comes from the same file, so it is refreshed with every
   * policy: what the package manager recorded is what the kernel is told. The
   * /data/app events only keep it fresh between two of these passes. */
  std::size_t missing = 0;
  for (const auto &[name, uid] : callers_) {
    const auto dir = packages->code_dir_of(name);
    if (!dir) {
      ++missing;
      continue;
    }
    code_dirs_.insert_or_assign(name, *dir);
  }
  if (missing != 0)
    Log::warn("{} caller(s) have no code directory in {}", missing,
              config_.packages_xml.string());

  publish_code_dirs();
}

void Syncer::publish_code_dirs() {
  std::vector<ApkEntry> entries;
  entries.reserve(callers_.size());
  /* One entry per directory, even when several packages share a uid. */
  std::set<std::pair<std::uint32_t, std::uint64_t>> seen;

  for (const auto &[name, uid] : callers_) {
    const auto dir = code_dirs_.find(name);
    if (dir == code_dirs_.end())
      continue;
    struct stat info{};
    if (::stat(dir->second.c_str(), &info) != 0)
      continue;
    const auto key = std::pair{static_cast<std::uint32_t>(info.st_dev),
                               static_cast<std::uint64_t>(info.st_ino)};
    if (!seen.insert(key).second)
      continue;
    if (entries.size() >= kApkLimit)
      break;
    entries.push_back(
        ApkEntry{.dev = key.first, .ino = key.second, .uid = uid});
  }

  const auto same_entry = [](const ApkEntry &a, const ApkEntry &b) {
    return a.dev == b.dev && a.ino == b.ino && a.uid == b.uid;
  };
  if (std::ranges::equal(entries, published_, same_entry))
    return;
  if (!netlink_.push_apks(entries)) {
    watcher_.arm_retry();
    return;
  }
  published_.assign(entries.begin(), entries.end());
  Log::info("registered {} caller code dir(s)", entries.size());
}

void Syncer::handle_packages(const std::vector<std::string> &dirs) {
  /* Nothing is known before the first policy arrives, and a policy change reads
   * the whole map again anyway. */
  if (callers_.empty())
    return;

  bool changed = false;
  for (const auto &name : dirs) {
    const std::filesystem::path base = std::filesystem::path{kAppRoot} / name;
    std::error_code ec;

    if (std::filesystem::is_directory(base, ec)) {
      /*
       * The directory that just arrived: its entries name the packages that
       * landed in it. This is the only application directory this program ever
       * reads, it is the one the event pointed at, and it is read once.
       */
      for (const auto &entry : std::filesystem::directory_iterator{base, ec}) {
        if (ec)
          break;
        if (!entry.is_directory(ec))
          continue;
        const auto leaf = entry.path().filename().string();
        const auto caller = std::ranges::find_if(callers_, [&](const auto &c) {
          return dir_matches(leaf, c.first);
        });
        if (caller == callers_.end())
          continue;
        Log::info("{} now lives in {}", caller->first, entry.path().string());
        code_dirs_.insert_or_assign(caller->first, entry.path());
        changed = true;
      }
    } else {
      /*
       * The install directory is gone (replaced by a new one, or uninstalled).
       * Forget the packages that lived there; if the new directory has already
       * been seen, its entry took over, and otherwise the next full sync asks
       * the package manager again.
       */
      for (auto it = code_dirs_.begin(); it != code_dirs_.end();) {
        if (it->second.parent_path() == base) {
          Log::info("{} no longer lives in {}", it->first, it->second.string());
          it = code_dirs_.erase(it);
          changed = true;
        } else {
          ++it;
        }
      }
    }
  }

  if (changed)
    publish_code_dirs();
}

bool Syncer::run() {
  sync_now();
  if (config_.once)
    return true;

  if (!watcher_.open(config_.config))
    return false;
  Log::info("watching {}", config_.config.string());

  for (;;) {
    const auto tick = watcher_.wait();
    if (!tick)
      return false;
    /*
     * A key of the policy may have been written mid-replace, so every event
     * ends in a full pass; an install, on the other hand, only changes one
     * directory, and that one is read directly.
     */
    if (tick->kind == Watcher::Tick::Kind::Packages)
      handle_packages(tick->dirs);
    else
      sync_now(tick->kind == Watcher::Tick::Kind::Config ? "config.json changed"
                                                         : "retry");
  }
}

} // namespace uidfake
