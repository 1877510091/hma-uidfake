// SPDX-License-Identifier: GPL-2.0
#include "rules.hpp"

#include <algorithm>
#include <array>
#include <fstream>
#include <ranges>
#include <utility>

namespace uidfake {
namespace {

/* HMA's own list (xj.a in the app): the packages it always knows about. They
 * are not hidden from anybody, and nothing is hidden from them; when a caller
 * hides everything else they join the set, which is what keeps them visible
 * there. */
constexpr std::array kHmaKnownPackages{
    std::string_view{"android"},
    std::string_view{"com.android.shell"},
    std::string_view{"com.android.systemui"},
    std::string_view{"com.android.permissioncontroller"},
    std::string_view{"com.android.providers.downloads"},
    std::string_view{"com.android.providers.downloads.ui"},
    std::string_view{"com.android.providers.media"},
    std::string_view{"com.android.providers.media.module"},
    std::string_view{"com.android.providers.settings"},
    std::string_view{"com.google.android.webview"},
    std::string_view{"com.google.android.providers.media.module"},
};

/* Constants.packagesShouldNotHide in HMA-OSS. A different list from HMA's; a
 * caller or a target on it is never hidden. */
constexpr std::array kHmaOssReservedPackages{
    std::string_view{"android"},
    std::string_view{"android.media"},
    std::string_view{"android.uid.system"},
    std::string_view{"android.uid.shell"},
    std::string_view{"android.uid.systemui"},
    std::string_view{"com.android.permissioncontroller"},
    std::string_view{"com.android.providers.downloads"},
    std::string_view{"com.android.providers.downloads.ui"},
    std::string_view{"com.android.providers.media"},
    std::string_view{"com.android.providers.media.module"},
    std::string_view{"com.android.providers.settings"},
    std::string_view{"com.google.android.providers.media.module"},
    std::string_view{"com.google.android.permissioncontroller"},
};

} // namespace

std::optional<nlohmann::json>
Rules::read_json(const std::filesystem::path &path) {
  try {
    std::ifstream in(path);
    if (!in)
      return std::nullopt;
    nlohmann::json config;
    in >> config;
    return config;
  } catch (const std::exception &e) {
    Log::warn("cannot parse {}: {}", path.string(), e.what());
    return std::nullopt;
  }
}

Rules::Rules(Tool tool, nlohmann::json config, std::filesystem::path path)
    : config_(std::move(config)), path_(std::move(path)), tool_(tool) {
  if (const auto it = config_.find("scope");
      it != config_.end() && it->is_object())
    scope_ = &*it;
  if (const auto it = config_.find("templates");
      it != config_.end() && it->is_object())
    templates_ = &*it;
}

const nlohmann::json *Rules::caller_entry(std::string_view caller) const {
  if (scope_ == nullptr)
    return nullptr;
  const auto it = scope_->find(std::string{caller});
  return it == scope_->end() ? nullptr : &*it;
}

const nlohmann::json *Rules::template_entry(std::string_view name) const {
  if (templates_ == nullptr)
    return nullptr;
  const auto it = templates_->find(std::string{name});
  return it == templates_->end() ? nullptr : &*it;
}

const nlohmann::json *Rules::find_array(const nlohmann::json &entry,
                                        std::string_view key) {
  const auto it = entry.find(key);
  if (it == entry.end() || !it->is_array())
    return nullptr;
  return &*it;
}

bool Rules::in_list(const nlohmann::json &array, std::string_view name) {
  return std::ranges::any_of(array, [&](const nlohmann::json &item) {
    return item.is_string() && item.get_ref<const std::string &>() == name;
  });
}

void Rules::log_summary(std::size_t callers, const Pairs &pairs) const {
  Log::info("{} ({}): {} caller(s), {} pair(s)", path_.string(),
            tool_name(tool_), callers, pairs.size());
}

std::unique_ptr<HmaRules> HmaRules::load(const std::filesystem::path &path) {
  auto config = read_json(path);
  if (!config)
    return nullptr;
  return std::make_unique<HmaRules>(std::move(*config), path);
}

/* HMA: the extra list plus the appList of every template the caller applies.
 * See defpackage/m10.java in the app. */
bool HmaRules::on_list(const nlohmann::json &entry,
                       std::string_view target) const {
  if (const auto *extra = find_array(entry, "extraAppList");
      extra != nullptr && in_list(*extra, target))
    return true;

  const auto *applied = find_array(entry, "applyTemplates");
  if (applied == nullptr)
    return false;
  for (const auto &name : *applied) {
    if (!name.is_string())
      continue;
    const auto *tpl = template_entry(name.get_ref<const std::string &>());
    if (tpl == nullptr)
      continue;
    const auto *list = find_array(*tpl, "appList");
    if (list != nullptr && in_list(*list, target))
      return true;
  }
  return false;
}

bool HmaRules::hides_target(const nlohmann::json &entry,
                            std::string_view target,
                            bool target_is_system) const {
  /* The caller's own list never hides a package HMA always knows about; in
   * whitelist mode those join the set instead, which keeps them visible. */
  const bool whitelist = entry.value("useWhitelist", false);
  const bool known = std::ranges::contains(kHmaKnownPackages, target);
  if (!whitelist && known)
    return false;
  /* System apps stay visible in whitelist mode when that is switched on. */
  if (whitelist && entry.value("excludeSystemApps", false) && target_is_system)
    return false;

  const bool on_the_list = on_list(entry, target) || (whitelist && known);
  return whitelist ? !on_the_list : on_the_list;
}

bool HmaRules::hides(std::string_view caller, std::string_view target,
                     bool target_is_system, const Presets &) const {
  if (std::ranges::contains(kHmaKnownPackages, caller))
    return false;
  const auto *entry = caller_entry(caller);
  if (entry == nullptr)
    return false;
  return hides_target(*entry, target, target_is_system);
}

Pairs HmaRules::expand(const PackageDb &packages, const Presets &) const {
  Pairs pairs;
  std::size_t callers = 0;

  if (scope_ != nullptr)
    for (const auto &[caller, entry] : scope_->items()) {
      append_pairs(
          pairs, packages, caller,
          [&](std::string_view target, std::uint32_t, bool target_is_system) {
            return hides_target(entry, target, target_is_system);
          });
      ++callers;
    }

  log_summary(callers, pairs);
  return pairs;
}

HmaOssRules::HmaOssRules(nlohmann::json config, std::filesystem::path path)
    : Rules(Tool::HmaOss, std::move(config), std::move(path)) {
  const auto *ignored = find_array(config_, "ignoredPackagesForPresets");
  if (ignored == nullptr)
    return;
  for (const auto &item : *ignored)
    if (item.is_string())
      presets_skip_.insert(item.get_ref<const std::string &>());
}

std::unique_ptr<HmaOssRules>
HmaOssRules::load(const std::filesystem::path &path) {
  auto config = read_json(path);
  if (!config)
    return nullptr;
  return std::make_unique<HmaOssRules>(std::move(*config), path);
}

bool HmaOssRules::presets_skip(std::string_view target) const {
  return presets_skip_.contains(target);
}

/* HMA-OSS: HMAService.shouldHide, in its order. */
bool HmaOssRules::hides_target(const nlohmann::json &entry,
                               std::string_view target, bool target_is_system,
                               const Presets &presets) const {
  const bool whitelist = entry.value("useWhitelist", false);
  if (const auto *extra = find_array(entry, "extraAppList");
      extra != nullptr && in_list(*extra, target))
    return !whitelist;
  if (const auto *opposite = find_array(entry, "extraOppositeAppList");
      opposite != nullptr && in_list(*opposite, target))
    return whitelist;

  if (const auto *applied = find_array(entry, "applyTemplates");
      applied != nullptr) {
    for (const auto &name : *applied) {
      if (!name.is_string())
        continue;
      const auto *tpl = template_entry(name.get_ref<const std::string &>());
      if (tpl == nullptr)
        continue;
      const auto *list = find_array(*tpl, "appList");
      if (list != nullptr && in_list(*list, target))
        return !whitelist;
    }
  }

  if (!presets_skip(target)) {
    if (const auto *applied = find_array(entry, "applyPresets");
        applied != nullptr) {
      for (const auto &name : *applied) {
        if (!name.is_string())
          continue;
        const auto preset =
            presets.find(std::string{name.get_ref<const std::string &>()});
        if (preset != presets.end() && preset->second.contains(target))
          return !whitelist;
      }
    }
  }

  if (whitelist && entry.value("excludeSystemApps", false) && target_is_system)
    return false;
  return whitelist;
}

bool HmaOssRules::hides(std::string_view caller, std::string_view target,
                        bool target_is_system, const Presets &presets) const {
  if (std::ranges::contains(kHmaOssReservedPackages, caller) ||
      std::ranges::contains(kHmaOssReservedPackages, target))
    return false;
  const auto *entry = caller_entry(caller);
  if (entry == nullptr)
    return false;
  return hides_target(*entry, target, target_is_system, presets);
}

Pairs HmaOssRules::expand(const PackageDb &packages,
                          const Presets &presets) const {
  Pairs pairs;
  std::size_t callers = 0;

  if (scope_ != nullptr)
    for (const auto &[caller, entry] : scope_->items()) {
      append_pairs(
          pairs, packages, caller,
          [&](std::string_view target, std::uint32_t, bool target_is_system) {
            return hides_target(entry, target, target_is_system, presets);
          });
      ++callers;
    }

  log_summary(callers, pairs);
  return pairs;
}

} // namespace uidfake
