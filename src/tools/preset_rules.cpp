// SPDX-License-Identifier: GPL-2.0
/*
 * preset_rules.cpp - the scanned half of HMA-OSS's presets.
 *
 * BasePreset judges an installed app with canBeAddedIntoPreset(), and the app
 * writes only the result of that to its cache. The rules themselves are here,
 * read off the preset classes: the names that need the APK are checked by
 * looking for the entry names in the file (an APK's central directory is
 * plain text), the rest by the package name.
 */

#include <filesystem>
#include <fstream>
#include <ranges>
#include <string>
#include <vector>

#include "packages.hpp"
#include "rules.hpp"

namespace uidfake {
namespace {

/* HMA-OSS never adds a package on its own reserved list to a preset. */
constexpr std::array kReserved{
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
    std::string_view{"com.miui.securitycenter"},
};

[[nodiscard]] bool
starts_with_any(std::string_view value,
                std::initializer_list<std::string_view> set) {
  return std::ranges::any_of(
      set, [&](std::string_view one) { return value.starts_with(one); });
}

[[nodiscard]] bool ends_with_any(std::string_view value,
                                 std::initializer_list<std::string_view> set) {
  return std::ranges::any_of(
      set, [&](std::string_view one) { return value.ends_with(one); });
}

[[nodiscard]] bool contains_any(std::string_view value,
                                std::initializer_list<std::string_view> set) {
  return std::ranges::any_of(set, [&](std::string_view one) {
    return value.find(one) != std::string_view::npos;
  });
}

/* An APK keeps its entry names in the central directory as plain bytes, so a
 * search is enough to answer "does this file carry that entry" without
 * unpacking anything. */
/* An APK keeps its entry names in the central directory at the end of the file,
 * plain and uncompressed, so reading the tail answers "does this file carry
 * that entry" without unpacking anything. */
[[nodiscard]] bool file_has_entry(const std::filesystem::path &apk,
                                  std::string_view entry) {
  constexpr std::uintmax_t kTail = 1u << 20;
  std::error_code ignored;
  const auto size = std::filesystem::file_size(apk, ignored);
  if (ignored || size == 0)
    return false;
  const auto from = size > kTail ? size - kTail : 0;
  std::ifstream in{apk, std::ios::binary};
  if (!in)
    return false;
  in.seekg((std::streamoff)from);
  std::vector<char> data((std::size_t)(size - from));
  in.read(data.data(), (std::streamsize)data.size());
  const auto got = (std::size_t)in.gcount();
  return std::string_view{data.data(), got}.find(entry) !=
         std::string_view::npos;
}

/* Every split of an app can carry entries, so all the APKs in its code
 * directory are looked at, the way HMA-OSS does. */
[[nodiscard]] bool
apk_has_any(const PackageDb &packages, std::string_view name,
            std::initializer_list<std::string_view> entries) {
  const auto dir = packages.code_dir_of(name);
  if (!dir)
    return false;
  std::error_code ignored;
  for (const auto &item : std::filesystem::directory_iterator{*dir, ignored}) {
    if (ignored)
      break;
    if (item.path().extension() != ".apk")
      continue;
    for (const auto &entry : entries)
      if (file_has_entry(item.path(), entry))
        return true;
  }
  return false;
}

constexpr std::array kRootLibs{
    std::string_view{"libkernelsu.so"},
    std::string_view{"libapd.so"},
    std::string_view{"libmagisk.so"},
    std::string_view{"libmagiskboot.so"},
    std::string_view{"libmmrl-file-manager.so"},
    std::string_view{"libmmrl-kernelsu.so"},
    std::string_view{"libzakoboot.so"},
};

/* The library names live inside the APK as lib/<arch>/<name>: both ABIs HMA-OSS
 * looks at are tried. */
/* The library names live inside the APK as lib/<arch>/<name>: both ABIs HMA-OSS
 * looks at are tried. */
[[nodiscard]] bool apk_has_lib(const PackageDb &packages, std::string_view name,
                               const auto &libs) {
  for (const auto &lib : libs) {
    const std::string arm64 = std::string{"lib/arm64-v8a/"} + std::string{lib};
    const std::string arm32 =
        std::string{"lib/armeabi-v7a/"} + std::string{lib};
    if (apk_has_any(packages, name, {arm64}) ||
        apk_has_any(packages, name, {arm32}))
      return true;
  }
  return false;
}

} // namespace

Presets load_preset_cache(const std::filesystem::path &config_file,
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

  // items() is a proxy into its JSON owner. Keep that owner alive for the loop,
  // including with NDK r27's compiler, which does not extend its lifetime here.
  const auto cache_entries = json.value("cache", nlohmann::json::object());
  for (const auto &[name, list] : cache_entries.items()) {
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

Presets scan_presets(const PackageDb &packages,
                     const std::set<std::string, std::less<>> &wanted) {
  Presets presets;
  /* Only the presets the caller asked for pay for an apk read: the string rules
   * are free, opening a file is not. */
  const bool want_root = wanted.contains("root_apps");
  const bool want_sus = wanted.contains("sus_apps");
  const bool want_xposed = wanted.contains("xposed");

  for (const auto &[name, info] : packages.by_name()) {
    (void)info;
    if (std::ranges::contains(kReserved, name))
      continue;
    const bool detector =
        starts_with_any(name, {"me.garfieldhan."}) ||
        contains_any(name, {"chunqiu", "chuqniu"}) ||
        ends_with_any(name, {".duckdetector", ".keyattestation"});
    if (detector)
      presets["detector_apps"].insert(std::string{name});

    if (!detector) {
      /* root_apps */
      if (starts_with_any(name, {"dev.ukanth.ufirewall", "xzr.", "moe.xzr.",
                                 "org.lsposed", "com.drdisagree.iconify"}) ||
          starts_with_any(name,
                          {"com.dergoogler.mmrl", "com.xayah.databackup",
                           "com.smartpack.", "org.fdroid.fdroid.privileged"}) ||
          ends_with_any(name, {".viper4android", ".viperfx", ".magisk"}) ||
          contains_any(name, {".busybox", ".apatch."}) ||
          name.ends_with(".apatch") ||
          (want_root && apk_has_lib(packages, name, kRootLibs)) ||
          apk_has_any(packages, name,
                      {"assets/gamma_profiles.json", "assets/main.jar"}))
        presets["root_apps"].insert(std::string{name});
    }

    /* sus_apps */
    if (starts_with_any(name, {"com.offsec.", "com.termux", "com.realvnc.",
                               "nextapp.fx", "com.ghisler.", "ru.zdevs.",
                               "com.mixplorer", "bin.mt.", "com.x0.strai.",
                               "com.microsoft.rdc.", "com.teamviewer."}) ||
        (want_sus && apk_has_any(packages, name,
                                 {"assets/APKEditor.pk8", "assets/testkey.pk8",
                                  "assets/key/testkey.pk8"})))
      presets["sus_apps"].insert(std::string{name});

    /* xposed */
    if (want_xposed &&
        apk_has_any(packages, name,
                    {"assets/xposed_init", "META-INF/xposed/module.prop"}))
      presets["xposed"].insert(std::string{name});

    /* shizuku_dhizuku */
    if (name.starts_with("moe.shizuku."))
      presets["shizuku_dhizuku"].insert(std::string{name});

    /* custom_rom */
    if (starts_with_any(name, {"lineageos.",
                               "org.lineageos.",
                               "com.caf.",
                               "org.calyxos.",
                               "co.aospa.",
                               "org.omnirom.",
                               "org.protonaosp.",
                               "org.evolution.",
                               "org.evolutionx.",
                               "com.android.system.",
                               "com.accents.",
                               "com.alpha.",
                               "com.android.systemui.",
                               "com.android.theme.",
                               "com.bootleggers.",
                               "com.custom.overlay.",
                               "com.gnonymous.gvisualmod.",
                               "com.libremobileos.",
                               "com.nikgapps.",
                               "com.potato.",
                               "eu.xiaomi."}) ||
        ends_with_any(name, {".evolution", ".evolutionx", ".overlay.fog"}))
      presets["custom_rom"].insert(std::string{name});
  }
  return presets;
}

} // namespace uidfake
