// SPDX-License-Identifier: GPL-2.0
#include "watcher.hpp"

#include <dlfcn.h>
#include <poll.h>
#include <sys/inotify.h>
#include <sys/system_properties.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <ranges>

namespace uidfake {
namespace {

/*
 * Android's own "this user's credential-encrypted storage is open" flag, set
 * after the first unlock. /data/user/0 appears through a vold mount and inotify
 * cannot report a mount, so this is what turns the unlock into an immediate
 * event instead of a poll guess.
 */
[[nodiscard]] bool ce_available() {
  char value[PROP_VALUE_MAX] = {};
  return __system_property_get("sys.user.0.ce_available", value) > 0 &&
         value[0] == 't';
}

/*
 * There is no file descriptor to poll for a property, so before the unlock -
 * when there is nothing to watch and nothing readable anyway - block on the
 * property itself instead of waking up every second. Returns whether the
 * storage is open now.
 */
/*
 * The unlock is a key being added and a bind mount being made: inotify reports
 * neither. The platform's own waiting call is not part of the NDK's symbols, so
 * it and the serial accessor that closes the gap between looking at the flag
 * and waiting on it are resolved at run time. If a ROM lacks either, the flag
 * is polled instead and nothing else notices.
 */
using PropSerial = std::uint32_t (*)(const prop_info *);
using PropWait = bool (*)(const prop_info *, std::uint32_t, std::uint32_t *,
                          const timespec *);

constexpr long kUnlockPollMs = 250;

[[nodiscard]] bool wait_for_unlock() {
  if (ce_available())
    return true;

  const prop_info *info = __system_property_find("sys.user.0.ce_available");
  const auto serial_fn = reinterpret_cast<PropSerial>(
      dlsym(RTLD_DEFAULT, "__system_property_serial"));
  const auto wait_fn =
      reinterpret_cast<PropWait>(dlsym(RTLD_DEFAULT, "__system_property_wait"));

  if (info != nullptr && serial_fn != nullptr && wait_fn != nullptr) {
    std::uint32_t seen = serial_fn(info);
    while (!ce_available()) {
      std::uint32_t fresh = 0;
      timespec watchdog{.tv_sec = 30, .tv_nsec = 0};
      if (!wait_fn(info, seen, &fresh, &watchdog))
        continue;
      seen = fresh;
    }
    return true;
  }

  timespec slice{.tv_sec = 0, .tv_nsec = kUnlockPollMs * 1000 * 1000};
  while (!ce_available())
    ::nanosleep(&slice, nullptr);
  return true;
}

constexpr std::uint32_t kFileEvents =
    IN_MODIFY | IN_CLOSE_WRITE | IN_ATTRIB | IN_MOVE_SELF | IN_DELETE_SELF;
constexpr std::uint32_t kDirEvents = IN_CREATE | IN_MOVED_TO | IN_CLOSE_WRITE |
                                     IN_ATTRIB | IN_DELETE | IN_MOVED_FROM;

/*
 * Where installed code lives, watched at its first level. An install or an
 * update renames a "~~[random]" directory in here; nothing deeper is watched,
 * so dexopt writing into an existing package does not wake us up at all.
 */
constexpr std::string_view kAppRoot = "/data/app";
/* Only the rename in and out matters: creation, removal and both moves. */
constexpr std::uint32_t kAppDirEvents =
    IN_CREATE | IN_MOVED_TO | IN_MOVED_FROM | IN_DELETE;

} // namespace

bool Watcher::open(const std::filesystem::path &config) {
  inotify_.reset(::inotify_init1(IN_CLOEXEC | IN_NONBLOCK));
  if (!inotify_.valid()) {
    Log::warn("inotify_init1: {}", std::strerror(errno));
    return false;
  }

  debounce_.reset(
      ::timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK));
  resync_.reset(::timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK));
  if (!debounce_.valid() || !resync_.valid()) {
    Log::warn("timerfd_create: {}", std::strerror(errno));
    return false;
  }

  /*
   * Declare what we want and arm it best effort: config.json in particular may
   * not exist yet, and a failed watch used to mean the file stayed invisible
   * for the whole lifetime of the process (that is how changes went missing).
   */
  desired_ = {
      {.path = config, .mask = kFileEvents},
      {.path = config.parent_path(), .mask = kDirEvents},
      {.path = kAppRoot, .mask = kAppDirEvents, .app_root = true},
  };
  apply_watches();

  /* The directory watch is only there for an atomic replace of the config
   * itself; the name tells the two apart when events arrive. */
  config_name_ = config.filename().string();
  const auto dir = std::ranges::find_if(
      watches_, [&](const Watch &w) { return w.path == config.parent_path(); });
  config_dir_wd_ = dir == watches_.end() ? -1 : dir->wd;

  /* Nothing is armed here: a retry is asked for when something is missing. */
  if (!watches_complete())
    arm_retry();
  return true;
}

void Watcher::arm_retry() {
  if (!resync_.valid())
    return;
  itimerspec timer{};
  timer.it_value.tv_sec = kRetry.count();
  timer.it_interval.tv_sec = 0; /* one shot; the caller decides what is next */
  ::timerfd_settime(resync_.get(), 0, &timer, nullptr);
}

void Watcher::apply_watches() {
  for (const auto &want : desired_)
    add(want.path, want.mask);
}

bool Watcher::watches_complete() const {
  return std::ranges::all_of(desired_,
                             [](const Watch &w) { return !w.warned; });
}

void Watcher::add(const std::filesystem::path &path, std::uint32_t mask) {
  /* Remember which of the wanted watches are not armed yet: that is also what
   * tells the resync timer to come back sooner, since these paths only appear
   * once /data is unlocked. */
  const auto wanted = std::ranges::find_if(
      desired_, [&](const Watch &w) { return w.path == path; });
  const bool app_root = wanted != desired_.end() && wanted->app_root;

  const int wd = ::inotify_add_watch(inotify_.get(), path.c_str(), mask);
  if (wd < 0) {
    if (wanted != desired_.end() && !wanted->warned) {
      wanted->warned = true;
      Log::warn(
          "cannot watch {} yet: {} (retrying; /data may still be encrypted)",
          path.string(), std::strerror(errno));
    }
    return;
  }
  if (wanted != desired_.end() && wanted->warned) {
    wanted->warned = false;
    Log::info("watching {} now", path.string());
  }
  for (auto &watch : watches_) {
    if (watch.wd == wd) {
      watch = Watch{.wd = wd, .path = path, .mask = mask, .app_root = app_root};
      return;
    }
  }
  watches_.push_back(
      Watch{.wd = wd, .path = path, .mask = mask, .app_root = app_root});
}

void Watcher::arm_debounce() {
  const auto now = std::chrono::steady_clock::now();

  /* First event of a burst: wait out the quiet period. */
  if (!pending_) {
    pending_ = now;
    itimerspec timer{};
    timer.it_value.tv_nsec =
        std::chrono::duration_cast<std::chrono::nanoseconds>(kDebounce).count();
    ::timerfd_settime(debounce_.get(), 0, &timer, nullptr);
    return;
  }

  /* Changes keep arriving: sync anyway, no later than kDebounceMax after the
   * first one. */
  if (now - *pending_ >= kDebounceMax) {
    itimerspec timer{};
    timer.it_value.tv_nsec = 1;
    ::timerfd_settime(debounce_.get(), 0, &timer, nullptr);
  }
}

bool Watcher::handle_inotify_events() {
  std::array<char, kReadBuffer> buffer{};
  const ssize_t count = ::read(inotify_.get(), buffer.data(), buffer.size());
  if (count <= 0)
    return false;

  bool interesting = false;
  bool rearm = false;
  for (ssize_t offset = 0; offset < count;) {
    const auto *event =
        reinterpret_cast<const inotify_event *>(buffer.data() + offset);
    offset += static_cast<ssize_t>(sizeof(*event)) + event->len;

    if (event->mask & IN_Q_OVERFLOW) {
      Log::warn("inotify queue overflow, resyncing");
      interesting = true;
      rearm = true;
      continue;
    }
    if (event->mask & IN_IGNORED) {
      /* The inode went away (an atomic replace) or the watch was dropped:
       * re-arm. */
      interesting = true;
      rearm = true;
      continue;
    }
    /*
     * HMA keeps its own files next to config.json, and that directory is only
     * watched so a config written to a temporary file and renamed into place is
     * caught. Anything else in there is none of our business: without this,
     * every file HMA writes wakes the whole sync up.
     */
    if (event->len > 0 && event->wd == config_dir_wd_ &&
        config_name_ != event->name)
      continue;
    if (event->mask & (IN_CREATE | IN_MOVED_TO | IN_DELETE | IN_MOVED_FROM)) {
      /* A file we could not watch before may exist now, or vice versa. */
      rearm = true;
    }
    /* Only the /data/app watch reports installs; every other watch is a rule
     * source. Taking any watch for the install root is how a config change was
     * dropped here. */
    const auto watch = std::ranges::find_if(
        watches_, [&](const Watch &w) { return w.wd == event->wd; });
    if (watch != watches_.end() && watch->app_root) {
      /* An install directory appeared or went away; hand the name to the
       * caller, which reads that one directory and nothing else. */
      if (event->len > 0 && (event->mask & IN_ISDIR)) {
        std::string_view name{event->name};
        if (name.starts_with("~~"))
          app_dirs_.emplace_back(name);
      }
      continue;
    }
    interesting = true;
  }

  if (rearm)
    apply_watches();

  return interesting;
}

std::optional<Watcher::Tick> Watcher::wait() {
  for (;;) {
    std::array<pollfd, 3> fds{{
        {.fd = inotify_.get(), .events = POLLIN, .revents = 0},
        {.fd = debounce_.get(), .events = POLLIN, .revents = 0},
        {.fd = resync_.get(), .events = POLLIN, .revents = 0},
    }};

    /*
     * Before the unlock there is nothing to watch and nothing to read, so wait
     * on the property instead of waking up every second. ce_ has to be updated
     * here: returning without it made the caller come straight back and spin.
     */
    if (!ce_) {
      if (!wait_for_unlock())
        continue;
      ce_ = true;
      /* The mount is there now, so the watches that could not be created
       * before can be: without this one a change would go unnoticed until
       * something else happened. */
      apply_watches();
      Log::info("credential storage is open (device unlocked)");
      if (!watches_complete())
        arm_retry();
      return Tick{.kind = Tick::Kind::Resync, .dirs = {}};
    }

    /* After the unlock a one second tick doubles as the closure check. */
    const int ready = ::poll(fds.data(), fds.size(), 1000);
    if (ready < 0) {
      if (errno == EINTR)
        continue;
      Log::warn("poll: {}", std::strerror(errno));
      return std::nullopt;
    }
    if (ready == 0) {
      if (!ce_available()) {
        ce_ = false;
        Log::info("credential storage closed");
        return Tick{.kind = Tick::Kind::Resync, .dirs = {}};
      }
      continue;
    }
    if (fds[0].revents != 0) {
      const bool interesting = handle_inotify_events();
      if (!app_dirs_.empty()) {
        Tick tick{.kind = Tick::Kind::Packages, .dirs = std::move(app_dirs_)};
        app_dirs_.clear();
        return tick;
      }
      /* config.json changes go through the debounce: an editor writes it in
       * several steps and only the settled file is worth reading. */
      if (interesting)
        arm_debounce();
    }

    std::uint64_t expirations = 0;
    if (fds[1].revents != 0 &&
        ::read(debounce_.get(), &expirations, sizeof(expirations)) > 0) {
      pending_.reset();
      return Tick{.kind = Tick::Kind::Config, .dirs = {}};
    }
    if (fds[2].revents != 0 &&
        ::read(resync_.get(), &expirations, sizeof(expirations)) > 0) {
      /* A retry fired: try the watches again and let the caller re-evaluate.
       * It asks for the next retry if something is still pending. */
      apply_watches();
      if (!watches_complete())
        arm_retry();
      return Tick{.kind = Tick::Kind::Resync, .dirs = {}};
    }
  }
}

} // namespace uidfake
