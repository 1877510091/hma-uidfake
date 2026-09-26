// SPDX-License-Identifier: GPL-2.0
#pragma once

#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>

namespace uidfake {

/* What the package manager knows about one package, as persisted in its own
 * database. */
struct PackageInfo {
  std::uint32_t uid = 0;          /* the app id, as packages.xml stores it */
  std::filesystem::path code_dir; /* where its code lives */
  bool system = false;            /* ApplicationInfo.FLAG_SYSTEM */
};

/*
 * The package manager's view, read from /data/system/packages.xml.
 *
 * That file is Android Binary XML since Android 12 and it is the only source
 * this program uses: it carries the name, the app id, the code directory and
 * the system flag of every package. The other two candidates were dropped on
 * purpose - "pm list packages -f -U" needs a JVM per lookup, and packages.list
 * carries no code path at all, so its use meant walking /data/app, which is
 * exactly the behaviour hiding tools are recognised by.
 */
class PackageDb {
public:
  [[nodiscard]] static std::optional<PackageDb>
  load(const std::filesystem::path &xml_path);

  [[nodiscard]] std::optional<std::uint32_t>
  uid_of(std::string_view name) const;
  [[nodiscard]] bool is_system(std::string_view name) const;
  [[nodiscard]] std::optional<std::filesystem::path>
  code_dir_of(std::string_view name) const;

  [[nodiscard]] const std::map<std::string, PackageInfo, std::less<>> &
  by_name() const noexcept {
    return by_name_;
  }

private:
  std::map<std::string, PackageInfo, std::less<>> by_name_;
};

} // namespace uidfake
