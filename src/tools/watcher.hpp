// SPDX-License-Identifier: GPL-2.0
#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "common.hpp"
#include "paths.hpp"

namespace uidfake {

/*
 * fsnotify watches on the rule sources and on /data/app. Directory events are
 * followed too, so an atomic write-to-temp-then-rename of a config is caught.
 *
 * /data/app is watched at its first level only: an install or an update ends
 * with "~~[random]" being renamed in there, and that event names the directory
 * whose contents say which package landed. Watching deeper would mean waking up
 * for every dexopt write instead.
 *
 * Watches are declared first and armed best effort afterwards: a file that does
 * not exist yet, or that is being replaced while we look, used to be dropped
 * for good when inotify_add_watch() failed, which is how changes went missing
 * entirely. Now anything can ask for a re-arm: the directory events, an
 * IN_IGNORED, or the periodic tick.
 */
class Watcher {
public:
  /* What the caller should do next. Packages carries the "~~" directories that
   * just appeared or disappeared under /data/app; the rest is a plain resync.
   */
  struct Tick {
    enum class Kind { Config, Packages, Resync };

    Kind kind = Kind::Resync;
    std::vector<std::string> dirs;
  };

  static constexpr auto kDebounce = std::chrono::milliseconds{400};
  /* A continuous stream of changes must not postpone the sync forever. */
  static constexpr auto kDebounceMax = std::chrono::seconds{2};
  /*
   * One shot, and only while something is known to be pending: a watch that
   * could not be created yet (config.json after the unlock, which inotify
   * cannot see either) or an upload that did not reach the kernel (module not
   * loaded yet). A module that is working has no timer running at all --
   * config changes and installs arrive as events.
   */
  static constexpr auto kRetry = std::chrono::seconds{10};

  /* One read of the inotify queue: the kernel drops events that do not fit, and
   * this is the size the kernel's own examples use. */
  static constexpr std::size_t kReadBuffer = std::size_t{64} * 1024;

  [[nodiscard]] bool open(std::span<const RuleSource> sources);

  /* Blocks until something worth resyncing happens; nullopt if polling broke.
   */
  [[nodiscard]] std::optional<Tick> wait();

  /* (Re)arms every watch we want. Cheap and idempotent, so it runs after events
   * too. */
  void apply_watches();

  /* Arms one retry. Called while a watch is missing or a push did not land. */
  void arm_retry();

  /* False while a wanted watch is still missing (typically /data before the
   * first unlock). */
  [[nodiscard]] bool watches_complete() const;

private:
  struct Watch {
    int wd = -1;
    std::filesystem::path path;
    std::uint32_t mask = 0;
    std::string filter;    /* directory entries this watch is armed for */
    bool app_root = false; /* /data/app: its events are installs */
    bool warned = false;   /* only for desired_: a failure already logged */
  };

  void add(const Watch &want);
  [[nodiscard]] bool handle_inotify_events();
  void arm_debounce();

  Fd inotify_;
  Fd debounce_;
  Fd resync_;
  std::vector<Watch> watches_; /* what inotify actually gave us */
  std::vector<Watch> desired_; /* what we want, whether or not it exists yet */
  std::vector<std::string>
      app_dirs_;                    /* "~~" directories seen under /data/app */
  std::vector<RuleSource> sources_; /* the places a config can be in */
  std::optional<std::chrono::steady_clock::time_point>
      pending_;     /* burst in progress */
  bool ce_ = false; /* sys.user.0.ce_available as last seen */
};

} // namespace uidfake
