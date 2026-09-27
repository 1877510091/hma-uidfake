// SPDX-License-Identifier: GPL-2.0
#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace uidfake {

inline constexpr std::string_view kPackagesXml = "/data/system/packages.xml";

/* Which of the two apps a config belongs to. It is a property of where the file
 * is kept, and it decides which class reads it. */
enum class Tool { Hma, HmaOss };

[[nodiscard]] std::string_view tool_name(Tool tool);

class RuleSource {
public:
  /* What to watch for one source. A directory watch accepts only entries with
   * one of `names`; a file watch sees events without one. */
  struct Watch {
    enum class Kind { Directory, File };

    std::filesystem::path path;
    Kind kind = Kind::Directory;
    std::vector<std::string> names;
  };

  /* The places both tools use, in the order they are looked for. */
  [[nodiscard]] static std::vector<RuleSource> known();

  /* The first of `sources` that has a config. By value, so it cannot point into
   * a list that has gone away. */
  [[nodiscard]] static std::optional<RuleSource>
  active(const std::vector<RuleSource> &sources);

  RuleSource(std::filesystem::path pattern, Tool tool)
      : pattern_(std::move(pattern)), tool_(tool) {}

  [[nodiscard]] Tool tool() const { return tool_; }
  [[nodiscard]] const std::filesystem::path &pattern() const {
    return pattern_;
  }

  /* The config to read, if it is there. */
  [[nodiscard]] std::optional<std::filesystem::path> config() const;

  /* Its file and that file's directory while the file exists -- never a second
   * config -- and the place it would appear in while it does not. */
  [[nodiscard]] std::vector<Watch> watches() const;

private:
  std::filesystem::path pattern_;
  Tool tool_;
};

/* The cache HMA-OSS expands its presets into, beside its config. */
inline constexpr std::string_view kPresetCacheNew = "preset_cache_v2.json";
inline constexpr std::string_view kPresetCacheOld = "preset_cache.json";

/* True for a directory entry name matching a leaf with one optional '*'. */
[[nodiscard]] bool leaf_matches(std::string_view name,
                                std::string_view pattern);

} // namespace uidfake
