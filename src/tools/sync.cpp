// SPDX-License-Identifier: GPL-2.0
#include "sync.hpp"

#include "oss_presets.hpp"

#include <sys/stat.h>

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <nlohmann/json.hpp>
#include <set>
#include <sstream>
#include <string>
#include <utility>

#include "common.hpp"
#include "packages.hpp"
#include "rules.hpp"

namespace uidfake {
namespace {

[[nodiscard]] Presets
load_preset_cache(const std::filesystem::path &config_file,
                  PresetFacts &facts) {
  Presets presets;
  std::error_code ignored;
  auto cache = config_file.parent_path() / kPresetCacheNew;
  if (!std::filesystem::exists(cache, ignored))
    cache = config_file.parent_path() / kPresetCacheOld;

  nlohmann::json json;
  try {
    std::ifstream in{cache};
    if (!in)
      return presets;
    in >> json;
  } catch (const std::exception &e) {
    Log::warn("cannot parse {}: {}", cache.string(), e.what());
    return presets;
  }

  for (const auto &[name, list] :
       json.value("cache", nlohmann::json::object()).items()) {
    if (!list.is_array())
      continue;
    auto &packages = presets[name];
    for (const auto &item : list)
      if (item.is_string())
        packages.insert(item.get<std::string>());
  }

  /* The same cache says which packages are connected to GMS: a preset hit still
   * leaves those visible to a caller that asks as one of the GMS packages. */
  for (const auto &item :
       json.value("riskyPackageCache", nlohmann::json::array()))
    if (item.is_string())
      facts.gms_connected.insert(item.get<std::string>());
  return presets;
}

/* Where installed code lives; the same root the watcher reports events from. */
constexpr std::string_view kAppRoot = "/data/app";
/* The kernel takes this many caller code dirs. */
constexpr std::size_t kApkLimit = 1024;

[[nodiscard]] bool dir_matches(std::string_view leaf, std::string_view pkg) {
  return leaf.size() > pkg.size() && leaf.compare(0, pkg.size(), pkg) == 0 &&
         leaf[pkg.size()] == '-';
}

} // namespace

std::optional<Config> parse_args(int argc, char **argv) {
  Config config;
  for (int i = 1; i < argc; ++i) {
    const std::string_view arg = argv[i];
    if (arg == "--once") {
      config.once = true;
    } else if (arg == "--write-config") {
      config.write_config = true;
    } else if (arg == "--template" && i + 1 < argc) {
      config.make_template = std::string{argv[++i]};
    } else if (arg == "--list" && i + 1 < argc) {
      config.list = std::string{argv[++i]};
    } else if (arg == "--explain" && i + 2 < argc) {
      config.explain =
          std::pair{std::string{argv[++i]}, std::string{argv[++i]}};
    } else {
      std::fprintf(
          stderr,
          "usage: %s [--once] [--explain CALLER TARGET] [--list CALLER] "
          "[--template CALLER [--write-config]]\n",
          argc > 0 ? argv[0] : "sync-tool");
      return std::nullopt;
    }
  }
  return config;
}

const PackageDb *Syncer::packages() {
  struct stat info{};
  if (::stat(std::string{kPackagesXml}.c_str(), &info) != 0) {
    Log::warn("cannot read {} (will retry on the next event)", kPackagesXml);
    return nullptr;
  }

  const PackageStamp stamp{.mtime_sec = info.st_mtim.tv_sec,
                           .mtime_nsec = info.st_mtim.tv_nsec,
                           .size = (std::uint64_t)info.st_size,
                           .inode = (std::uint64_t)info.st_ino};
  const bool cached = packages_ &&
                      stamp.mtime_sec == packages_stamp_.mtime_sec &&
                      stamp.mtime_nsec == packages_stamp_.mtime_nsec &&
                      stamp.size == packages_stamp_.size &&
                      stamp.inode == packages_stamp_.inode;
  if (cached)
    return &*packages_;

  auto db = PackageDb::load(std::string{kPackagesXml});
  if (!db)
    return nullptr;
  Log::info("read {} ({} package(s))", kPackagesXml, db->by_name().size());
  packages_ = std::move(db);
  packages_stamp_ = stamp;
  return &*packages_;
}

/* One place that reads the source through its rules, with the presets' three
 * sources: the sync, --explain, --list and --template cannot disagree. */
std::optional<Syncer::OpenedRules>
Syncer::open_rules(const std::filesystem::path &file,
                   const PackageDb &packages) {
  std::unique_ptr<Rules> rules;
  const std::optional<RuleSource> source = RuleSource::active(sources_);
  if (source && source->tool() == Tool::HmaOss)
    rules = HmaOssRules::load(file);
  else
    rules = HmaRules::load(file);
  if (!rules) {
    Log::warn("cannot read {}", file.string());
    return std::nullopt;
  }

  PresetFacts facts;
  Presets presets;
  if (rules->uses_presets()) {
    presets = load_preset_cache(file, facts);
    /* The app rebuilds its own presets per process from a view its hooks
     * filter, so the scanned half is computed here instead. */
    facts.scanned = scan_presets(packages);
  }
  rules->set_preset_facts(std::move(facts));
  return OpenedRules{.rules = std::move(rules), .presets = std::move(presets)};
}

void Syncer::sync_now(std::string_view why) {
  const std::optional<RuleSource> source = RuleSource::active(sources_);
  if (!source) {
    /* Once per outage: before the unlock this used to repeat on every tick. */
    if (!config_refused_) {
      config_refused_ = true;
      Log::warn("no readable rule source yet (keeping the previous policy)");
    }
    return;
  }
  if (config_refused_) {
    config_refused_ = false;
    Log::info("rule source readable again");
  }

  const PackageDb *packages = this->packages();
  if (packages == nullptr)
    return;
  const auto file = source->config();
  if (!file)
    return; /* it went away between the check and the read */

  const auto opened = open_rules(*file, *packages);
  if (!opened)
    return;
  Rules *rules = opened->rules.get();
  const Presets &presets = opened->presets;
  Pairs pairs = rules->expand(*packages, presets);

  /* The rules are per package, so every user answers
   * for its own uids. */
  pairs = expand_users(pairs, android_users());
  std::ranges::sort(pairs, [](const Pair &a, const Pair &b) {
    return a.caller != b.caller ? a.caller < b.caller : a.target < b.target;
  });
  pairs.erase(std::unique(pairs.begin(), pairs.end(),
                          [](const Pair &a, const Pair &b) {
                            return a.caller == b.caller && a.target == b.target;
                          }),
              pairs.end());

  /* The kernel holds this many pairs; another
   * attempt cannot change the count.
   */
  if (pairs.size() > NetlinkClient::kMaxPairs) {
    Log::warn("{} pair(s) is more than the kernel "
              "holds ({}); keeping the "
              "previous policy",
              pairs.size(), NetlinkClient::kMaxPairs);
    return;
  }

  const auto same_pair = [](const Pair &a, const Pair &b) {
    return a.caller == b.caller && a.target == b.target;
  };
  if (!std::ranges::equal(pairs, pushed_, same_pair)) {
    if (!netlink_.push(pairs)) {
      /* The kernel keeps its policy, and this pass
       * asks for a retry: a module loaded a second
       * later would otherwise wait for the next
       * event. */
      watcher_.arm_retry();
      return;
    }
    pushed_.assign(pairs.begin(), pairs.end());
    Log::info("synced {} pair(s) ({})", pairs.size(), why);
  }

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
              kPackagesXml);

  publish_code_dirs();
}

void Syncer::publish_code_dirs() {
  std::vector<ApkEntry> entries;
  entries.reserve(callers_.size());
  /* One entry per directory, even when several
   * packages share a uid. */
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
  /* Nothing is known before the first policy
   * arrives, and a policy change reads the whole map
   * again anyway. */
  if (callers_.empty())
    return;

  bool changed = false;
  for (const auto &name : dirs) {
    const std::filesystem::path base = std::filesystem::path{kAppRoot} / name;
    std::error_code ec;

    if (std::filesystem::is_directory(base, ec)) {

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

/* One decision, printed with everything it was read
 * from: the per-caller lines the expander writes,
 * the preset summary, and then the answer. */
void Syncer::explain(std::string_view caller, std::string_view target) {
  const std::optional<RuleSource> source = RuleSource::active(sources_);
  if (!source) {
    Log::warn("no readable rule source");
    return;
  }
  const PackageDb *packages = this->packages();
  if (packages == nullptr)
    return;
  const auto file = source->config();
  if (!file)
    return;

  auto opened = open_rules(*file, *packages);
  if (!opened)
    return;
  Rules *rules = opened->rules.get();
  const Presets &presets = opened->presets;

  /* The same call the sync makes, so its log lines
   * are the parse itself. */
  const Pairs pairs = rules->expand(*packages, presets);

  if (!packages->by_name().contains(target))
    Log::warn("{} is not in {}", target, kPackagesXml);
  const bool hidden =
      rules->hides(caller, target, packages->is_system(target), presets);
  Log::info("{}: {} hides {} = {} ({} pair(s) in "
            "the policy)",
            file->string(), caller, target, hidden ? "yes" : "no",
            pairs.size());
}

/* Every target one caller hides, by name: the same
 * list the kernel is given, printed so it can be
 * read next to what an app itself sees. */
void Syncer::list_targets(std::string_view caller) {
  const std::optional<RuleSource> source = RuleSource::active(sources_);
  if (!source) {
    Log::warn("no readable rule source");
    return;
  }
  const PackageDb *packages = this->packages();
  if (packages == nullptr)
    return;
  const auto file = source->config();
  if (!file)
    return;
  auto opened = open_rules(*file, *packages);
  if (!opened)
    return;
  Rules *rules = opened->rules.get();
  const Presets &presets = opened->presets;

  const Pairs pairs = rules->expand(*packages, presets);
  /* One uid can carry several package names, and the
   * kernel hides the uid: list them all, or a target
   * looks missing when it is the same uid under
   * another name. */
  std::map<std::uint32_t, std::vector<std::string>> names_of_uid;
  for (const auto &[name, info] : packages->by_name())
    names_of_uid[info.uid].push_back(std::string{name});

  std::vector<std::string> targets;
  const auto caller_uid = packages->uid_of(caller);
  if (!caller_uid) {
    Log::warn("{} is not installed", caller);
    return;
  }
  for (const auto &pair : pairs) {
    if (pair.caller != *caller_uid)
      continue;
    const auto names = names_of_uid.find(pair.target);
    if (names == names_of_uid.end()) {
      targets.push_back(std::to_string(pair.target));
      continue;
    }
    std::string joined;
    for (const auto &name : names->second) {
      if (!joined.empty())
        joined += " + ";
      joined += name;
    }
    targets.push_back(std::move(joined));
  }
  std::ranges::sort(targets);
  targets.erase(std::unique(targets.begin(), targets.end()), targets.end());

  Log::info("{} hides {} target(s):", caller, targets.size());
  for (const auto &name : targets)
    Log::info("  {}", name);
}

/* The caller's hidden set as a template in the
 * config language: HMA-OSS reads a template from the
 * config in every process, while it rebuilds a
 * preset per process from a view its own hooks
 * filter. */
void Syncer::template_for(std::string_view caller, bool write) {
  const std::optional<RuleSource> source = RuleSource::active(sources_);
  if (!source) {
    Log::warn("no readable rule source");
    return;
  }
  const PackageDb *packages = this->packages();
  if (packages == nullptr)
    return;
  const auto file = source->config();
  if (!file)
    return;
  auto opened = open_rules(*file, *packages);
  if (!opened)
    return;
  Rules *rules = opened->rules.get();
  const Presets &presets = opened->presets;

  const Pairs pairs = rules->expand(*packages, presets);
  const auto caller_uid = packages->uid_of(caller);
  if (!caller_uid) {
    Log::warn("{} is not installed", caller);
    return;
  }

  std::vector<std::string> names;
  for (const auto &pair : pairs) {
    if (pair.caller != *caller_uid)
      continue;
    for (const auto &[name, info] : packages->by_name())
      if (info.uid == pair.target && !std::ranges::contains(names, name))
        names.emplace_back(name);
  }
  std::ranges::sort(names);
  names.erase(std::unique(names.begin(), names.end()), names.end());

  const std::string template_name = "uidfake";
  Log::info("{} hides {} package(s); the template "
            "'{}' would carry them:",
            caller, names.size(), template_name);
  nlohmann::json snippet = {
      {template_name, {{"appList", names}, {"isWhitelist", false}}}};
  Log::info("\n{}", snippet.dump(2));
  Log::info("apply it by adding \"{}\" to {}'s "
            "applyTemplates",
            template_name, caller);
  if (!write)
    return;

  /* Writing into another app's config: keep a copy,
   * write beside the file and rename, and only when
   * something actually changes. */
  std::ifstream in{*file};
  nlohmann::json config;
  try {
    in >> config;
  } catch (const std::exception &e) {
    Log::warn("cannot parse {}: {}", file->string(), e.what());
    return;
  }
  config["templates"][template_name] = {{"appList", names},
                                        {"isWhitelist", false}};
  auto &applied = config["scope"][std::string{caller}]["applyTemplates"];
  if (!applied.is_array())
    applied = nlohmann::json::array();
  if (!applied.contains(template_name))
    applied.push_back(template_name);

  const auto backup = file->string() + ".uidfake.bak";
  std::error_code ignored;
  if (!std::filesystem::exists(backup, ignored))
    std::filesystem::copy_file(*file, backup, ignored);
  const auto tmp = file->string() + ".uidfake.tmp";
  {
    std::ofstream out{tmp, std::ios::trunc};
    out << config.dump();
  }
  std::filesystem::rename(tmp, *file, ignored);
  Log::info("wrote {} (backup {})", file->string(), backup);
}

bool Syncer::run() {
  sync_now();
  if (config_.once)
    return true;

  if (!watcher_.open(sources_))
    return false;
  if (const auto active = RuleSource::active(sources_)) {
    if (const auto file = active->config())
      Log::info("watching {}", file->string());
  } else {
    Log::info("no rule config yet (waiting for the "
              "known places)");
  }

  for (;;) {
    const auto tick = watcher_.wait();
    if (!tick)
      return false;

    if (tick->kind == Watcher::Tick::Kind::Packages)
      handle_packages(tick->dirs);
    else
      sync_now(tick->kind == Watcher::Tick::Kind::Config ? "config.json changed"
                                                         : "retry");
  }
}

} // namespace uidfake
