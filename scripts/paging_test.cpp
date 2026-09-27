// SPDX-License-Identifier: GPL-2.0
// Host test for the paging side of a policy upload: the CRC the kernel checks the
// staged bytes with has to be the same value here, and a page has to fit one
// netlink message.
#include "paging.hpp"

#include <cstdio>
#include <cstdlib>

using uidfake::Pair;

namespace
{

void must(bool ok, const char *what)
{
	if (ok)
		return;
	std::fprintf(stderr, "paging: FAILED (%s)\n", what);
	std::exit(1);
}

} // namespace

int main()
{
	/* 1,2 then 3,4 as four little-endian u32: the value an independent CRC32 gives
   * for those bytes, which is what src/netlink.c computes too. */
	const Pair pairs[] = { { .caller = 1, .target = 2 },
			       { .caller = 3, .target = 4 } };
	must(uidfake::crc32(pairs) == 0xaf05d4ef, "crc32 of two pairs");
	must(uidfake::crc32({}) == 0, "crc32 of nothing");

	/* A page carries 8 bytes of header plus the pairs, and the kernel takes at
   * most 32 KiB in one message (MAX_BLOB_BYTES in src/netlink.c). */
	must(8 + uidfake::kPagePairs * 8 <= 32768, "a page fits one message");

	std::printf("paging: PASS\n");
	return 0;
}
