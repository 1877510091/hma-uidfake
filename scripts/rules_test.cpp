// SPDX-License-Identifier: GPL-2.0
// Host test for both rule formats: what each one does with the same package list,
// driven with configs instead of a device.
#include "rules.hpp"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

using uidfake::Presets;
using uidfake::HmaOssRules;
using uidfake::HmaRules;

namespace
{

int failures = 0;

void check(bool got, bool want, const char *what)
{
	if (got == want)
		return;
	std::fprintf(stderr, "rules: FAILED (%s: got %d, want %d)\n", what, got,
		     want);
	++failures;
}

void check_name(std::string_view got, std::string_view want, const char *what)
{
	if (got == want)
		return;
	std::fprintf(stderr, "rules: FAILED (%s: got %.*s, want %.*s)\n", what,
		     static_cast<int>(got.size()), got.data(),
		     static_cast<int>(want.size()), want.data());
	++failures;
}

std::filesystem::path write_config(const char *name, const char *text)
{
	const std::filesystem::path path =
		std::filesystem::path{ "build" } / name;
	std::filesystem::create_directories(path.parent_path());
	std::ofstream out{ path };
	out << text;
	return path;
}

/* HMA 13: no opposite list, no presets, and a built-in list of its own. */
constexpr auto kHmaConfig = R"({
  "configVersion": 13,
  "aggressiveFilter": false,
  "templates": {"t": {"appList": ["com.example.tpl"], "isWhitelist": false}},
  "scope": {
    "com.example.caller": {
      "applyTemplates": ["t"],
      "excludeSystemApps": true,
      "extraAppList": ["com.example.extra", "com.android.shell"],
      "useWhitelist": false,
      "aggressiveFilter": false
    },
    "com.example.whitelist": {
      "applyTemplates": [],
      "excludeSystemApps": true,
      "extraAppList": ["com.example.extra"],
      "useWhitelist": true,
      "aggressiveFilter": false
    }
  }
})";

/* HMA-OSS: the opposite list, presets, and the packages presets must ignore. */
constexpr auto kHmaOssConfig = R"({
  "configVersion": 4,
  "ignoredPackagesForPresets": ["com.example.ignored"],
  "templates": {"t": {"appList": ["com.example.tpl"], "isWhitelist": false}},
  "scope": {
    "com.example.caller": {
      "useWhitelist": false,
      "excludeSystemApps": true,
      "applyTemplates": ["t"],
      "applyPresets": ["risky"],
      "extraAppList": ["com.example.extra"],
      "extraOppositeAppList": ["com.example.opposite"]
    },
    "com.example.whitelist": {
      "useWhitelist": true,
      "excludeSystemApps": true,
      "applyTemplates": [],
      "applyPresets": [],
      "extraAppList": ["com.example.extra"],
      "extraOppositeAppList": ["com.example.opposite"]
    }
  }
})";

/* Read the real cache loader, rather than supplying only hand-built sets. */
void test_preset_cache()
{
	const auto config =
		write_config("preset_cache_test/config.json", kHmaOssConfig);
	const auto cache_dir = config.parent_path();
	const auto old_cache = cache_dir / uidfake::kPresetCacheOld;
	const auto new_cache = cache_dir / uidfake::kPresetCacheNew;
	std::filesystem::remove(old_cache);
	std::filesystem::remove(new_cache);
	uidfake::PresetFacts facts;
	check(uidfake::load_preset_cache(config, facts).empty(), true,
	      "cache: missing files");
	write_config("preset_cache_test/preset_cache.json",
		     "{\"cache\":{\"legacy\":[\"com.example.legacy\"]}}");
	auto presets = uidfake::load_preset_cache(config, facts);
	check(presets.contains("legacy"), true,
	      "cache: legacy filename fallback");
	write_config(
		"preset_cache_test/preset_cache_v2.json",
		"{\"cache\":{"
		"\"risky\":[\"com.example.preset\",\"com.example.ignored\","
		"\"com.example.preset\",7,null],"
		"\"empty\":[],\"not_a_list\":false},"
		"\"riskyPackageCache\":[\"com.example.gms\",9,null]}");
	presets = uidfake::load_preset_cache(config, facts);
	check(presets.size() == 2, true, "cache: keep array entries only");
	check(!presets.contains("legacy"), true, "cache: prefer v2 filename");
	check(presets.contains("risky") && presets.at("risky").size() == 2 &&
		      presets.at("risky").contains("com.example.preset"),
	      true,
	      "cache: retain membership, ignore nonstrings and duplicates");
	check(presets.contains("empty") && presets.at("empty").empty(), true,
	      "cache: an empty preset is present, not missing");
	check(facts.gms_connected.size() == 1 &&
		      facts.gms_connected.contains("com.example.gms"),
	      true, "cache: GMS-connected membership");
	const auto rules = HmaOssRules::load(config);
	check(rules && rules->hides("com.example.caller", "com.example.preset",
				    false, presets),
	      true, "cache: cached membership reaches the rule decision");
	check(rules && rules->hides("com.example.caller", "com.example.ignored",
				    false, presets),
	      false, "cache: ignored packages remain visible");
	write_config("preset_cache_test/preset_cache_v2.json", "{}");
	facts = {};
	check(uidfake::load_preset_cache(config, facts).empty(), true,
	      "cache: absent keys");
	write_config("preset_cache_test/preset_cache_v2.json", "{invalid");
	check(uidfake::load_preset_cache(config, facts).empty(), true,
	      "cache: malformed JSON");
	std::filesystem::remove(new_cache);
	std::filesystem::remove(old_cache);
	std::filesystem::remove(config);
	std::filesystem::remove(cache_dir);
}

} // namespace

int main()
{
	test_preset_cache();
	const auto hma_path = write_config("rules_hma.json", kHmaConfig);
	const auto oss_path = write_config("rules_oss.json", kHmaOssConfig);

	const auto hma = HmaRules::load(hma_path);
	const auto oss = HmaOssRules::load(oss_path);
	if (!hma || !oss) {
		std::fprintf(stderr, "rules: FAILED (config did not load)\n");
		return 1;
	}
	check_name(uidfake::tool_name(hma->tool()), "hma",
		   "HMA's place means HMA's format");
	check_name(uidfake::tool_name(oss->tool()), "hma-oss",
		   "HMA-OSS's place means HMA-OSS's format");
	check(hma->uses_presets(), false, "HMA has no presets");
	check(oss->uses_presets(), true, "HMA-OSS has presets");

	Presets presets;
	presets["risky"].insert("com.example.preset");
	presets["risky"].insert("com.example.ignored");

	const auto hma_hides = [&](const char *caller, const char *target,
				   bool system = false) {
		return hma->hides(caller, target, system, presets);
	};
	const auto oss_hides = [&](const char *caller, const char *target,
				   bool system = false) {
		return oss->hides(caller, target, system, presets);
	};

	/* HMA: the hidden set, its built-in list, and whitelist mode. */
	check(hma_hides("com.example.other", "com.example.extra"), false,
	      "hma: unknown caller");
	check(hma_hides("com.example.caller", "com.example.extra"), true,
	      "hma: the extra list");
	check(hma_hides("com.example.caller", "com.example.tpl"), true,
	      "hma: an applied template");
	check(hma_hides("com.example.caller", "com.example.other"), false,
	      "hma: unlisted");
	check(hma_hides("com.example.caller", "com.android.shell"), false,
	      "hma: a listed built-in is still visible");
	check(hma_hides("com.example.whitelist", "com.example.other"), true,
	      "hma: whitelist mode hides the unlisted");
	check(hma_hides("com.example.whitelist", "com.example.extra"), false,
	      "hma: whitelist mode keeps the listed visible");
	check(hma_hides("com.example.whitelist", "com.android.shell"), false,
	      "hma: the built-ins stay visible in whitelist mode");
	check(hma_hides("com.example.whitelist", "com.example.other", true),
	      false, "hma: excludeSystemApps in whitelist mode");
	check(hma_hides("com.example.caller", "com.example.preset"), false,
	      "hma: presets do not exist");
	check(hma_hides("com.android.shell", "com.example.extra"), false,
	      "hma: a built-in caller hides nothing");

	/* HMA-OSS: the decision chain. */
	check(oss_hides("com.example.caller", "com.example.extra"), true,
	      "oss: the extra list");
	check(oss_hides("com.example.caller", "com.example.opposite"), false,
	      "oss: the opposite list in normal mode");
	check(oss_hides("com.example.whitelist", "com.example.extra"), false,
	      "oss: the extra list in whitelist mode");
	check(oss_hides("com.example.whitelist", "com.example.opposite"), true,
	      "oss: the opposite list in whitelist mode");
	check(oss_hides("com.example.caller", "com.example.tpl"), true,
	      "oss: an applied template");
	check(oss_hides("com.example.caller", "com.example.other"), false,
	      "oss: unlisted in normal mode");
	check(oss_hides("com.example.whitelist", "com.example.other"), true,
	      "oss: unlisted in whitelist mode");
	check(oss_hides("com.example.caller", "com.example.preset"), true,
	      "oss: an applied preset");
	check(oss_hides("com.example.caller", "com.example.ignored"), false,
	      "oss: ignoredPackagesForPresets");
	check(oss_hides("com.example.whitelist", "com.example.other", true),
	      false, "oss: excludeSystemApps in whitelist mode");
	check(oss_hides("com.example.caller", "com.google.android.gms"), false,
	      "oss: gms is never hidden");
	check(oss_hides("com.example.caller", "com.android.shell"), false,
	      "oss: the built-in list is HMA's, not HMA-OSS's");
	/* A caller never hides itself, and the reserved list wins over the whitelist
	 * mode that would otherwise hide everything unlisted. */
	check(oss_hides("com.example.whitelist", "com.example.whitelist"),
	      false, "oss: a caller never hides itself");
	check(oss_hides("com.example.whitelist", "com.miui.securitycenter"),
	      false, "oss: the reserved list wins in whitelist mode");

	std::filesystem::remove(hma_path);
	std::filesystem::remove(oss_path);
	if (failures != 0) {
		std::fprintf(stderr, "rules: %d failure(s)\n", failures);
		return 1;
	}
	std::printf("rules: PASS\n");
	return 0;
}
