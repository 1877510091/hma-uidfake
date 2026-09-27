// SPDX-License-Identifier: GPL-2.0
// A host shim: policy.c takes xchg() from the kernel's atomic headers to publish
// a snapshot, and the host test compiles that file as it is.
#pragma once

#define xchg(ptr, value) __atomic_exchange_n((ptr), (value), __ATOMIC_SEQ_CST)
