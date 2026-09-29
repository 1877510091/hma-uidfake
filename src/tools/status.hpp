// SPDX-License-Identifier: GPL-2.0
#pragma once

#include <optional>
#include <string_view>

namespace uidfake {

/*
 * What the module says about itself where a user will see it: the description
 * line of module.prop, which is what the KernelSU and Magisk module lists show.
 * The text goes in front of the description that is already there, in brackets,
 * so the module goes on saying what it is while saying how it is doing.
 *
 * Nothing happens when there is no module.prop beside the running binary: the
 * tool is also built and run on a build host.
 */
void report_status(std::string_view text);

/*
 * The running kernel's config, as far as this tool needs it. GKI kernels ship
 * /proc/config.gz (CONFIG_IKCONFIG_PROC), and the module reports the geometry
 * it was built for, so the two can be compared where a user will see the
 * answer. Empty when the config is not readable, which is the only case that
 * says nothing.
 */
struct DeviceGeometry {
  std::optional<unsigned int> va_bits;
  std::optional<unsigned int> page_shift;
};

[[nodiscard]] DeviceGeometry read_device_config();

} // namespace uidfake
