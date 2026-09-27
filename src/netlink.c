// SPDX-License-Identifier: GPL-2.0
/*
 * netlink.c - policy injection channel from privileged userspace into the
 * kernel. Little endian, matches src/tools/netlink.cpp.
 *
 *   KAUX_CMD_SET_BEGIN   blob = u32 total_pairs, u32 total_words, u32 crc32
 *   KAUX_CMD_SET_PAGE    blob = u32 seq, u32 npairs, then npairs * (caller,
 *                        target); caller 0 means any caller
 *   KAUX_CMD_SET_COMMIT  no payload: the staged policy is checked against the
 *                        total and the CRC and applied in one step
 *   KAUX_CMD_PING        no payload, ACK only
 *   KAUX_CMD_APK         blob = u32 n, then n * (st_dev, ino_lo, ino_hi, uid)
 */

#include "uidfake.h"
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/version.h> /* LINUX_VERSION_CODE for the resv_start_op guard */
#include <linux/crc32.h>
#include <linux/string.h>
#include <net/genetlink.h>

#define KAUX_FAMILY_NAME "kaux"
#define KAUX_FAMILY_VERSION 2

enum { KAUX_ATTR_UNSPEC, KAUX_ATTR_BLOB, __KAUX_ATTR_MAX };
#define KAUX_ATTR_MAX (__KAUX_ATTR_MAX - 1)

enum {
	KAUX_CMD_UNSPEC,
	KAUX_CMD_SET_BEGIN, /* u32 total_pairs, u32 total_words, u32 crc32 */
	KAUX_CMD_SET_PAGE, /* u32 seq, u32 npairs, then the pairs */
	KAUX_CMD_SET_COMMIT, /* nothing: checks what was staged, then applies it */
	KAUX_CMD_PING,
	KAUX_CMD_APK,
	__KAUX_CMD_MAX
};
#define KAUX_CMD_MAX (__KAUX_CMD_MAX - 1)

#define MAX_BLOB_BYTES 32768

/* A policy larger than one message arrives in pages and is held here until its
 * last page and its CRC have been seen: the live policy is replaced in one step,
 * or not at all. */
static DEFINE_MUTEX(g_staged_lock);
static u32 *g_staged;
static u32 g_staged_total;
static u32 g_staged_pairs;
static u32 g_staged_crc;

/* The helper gets the same value from zlib: crc32_le(~0, ..) ^ ~0 is zlib's
 * crc32(0, ..). Both are byte-wise, so the endianness of either side is not part
 * of the agreement. */
static u32 kaux_crc32(const u32 *words, u32 nwords)
{
	return crc32_le(~0u, (const u8 *)words,
			(size_t)nwords * sizeof(*words)) ^
	       ~0u;
}

/*
 * The command ids moved when the staged upload was added, and a helper of the
 * other version would read a ping as a set: the family version is checked, not
 * assumed.
 */
static int kaux_version(struct genl_info *info)
{
	return info->genlhdr->version == KAUX_FAMILY_VERSION ? 0 :
							       -EPROTONOSUPPORT;
}

static int kaux_blob(struct genl_info *info, const u32 **p, u32 *len)
{
	if (kaux_version(info))
		return -EPROTONOSUPPORT;
	if (!info->attrs[KAUX_ATTR_BLOB])
		return -EINVAL;
	*p = nla_data(info->attrs[KAUX_ATTR_BLOB]);
	*len = nla_len(info->attrs[KAUX_ATTR_BLOB]);
	if (*len < 4 || (*len & 3) || *len > MAX_BLOB_BYTES)
		return -EINVAL;
	return 0;
}

/* blob: u32 total_pairs, u32 total_words, u32 crc32 */
static int kaux_set_begin(struct sk_buff *skb, struct genl_info *info)
{
	const u32 *p;
	u32 len;
	int rc = 0;

	mutex_lock(&g_staged_lock);

	if (kaux_blob(info, &p, &len) || len < 12) {
		rc = -EINVAL;
		goto out;
	}
	if (p[0] > POLICY_MAX_PAIRS || p[1] != 2 * p[0]) {
		rc = -EINVAL;
		goto out;
	}

	g_staged_total = p[0];
	g_staged_pairs = 0;
	g_staged_crc = p[2];

out:
	mutex_unlock(&g_staged_lock);
	return rc;
}

/* blob: u32 seq, u32 npairs, then npairs * (caller, target) */
static int kaux_set_page(struct sk_buff *skb, struct genl_info *info)
{
	const u32 *p;
	u32 len, npairs;
	int rc = 0;

	mutex_lock(&g_staged_lock);

	if (kaux_blob(info, &p, &len) || len < 8) {
		rc = -EINVAL;
		goto out;
	}
	npairs = p[1];
	if (len < 8 + 8 * (unsigned long long)npairs) {
		rc = -EINVAL;
		goto out;
	}
	if (g_staged_total == 0 || p[0] != g_staged_pairs ||
	    npairs > g_staged_total - g_staged_pairs) {
		rc = -EINVAL;
		goto out;
	}

	memcpy(g_staged + 2 * (size_t)g_staged_pairs, p + 2,
	       (size_t)npairs * 8);
	g_staged_pairs += npairs;

out:
	mutex_unlock(&g_staged_lock);
	return rc;
}

static int kaux_set_commit(struct sk_buff *skb, struct genl_info *info)
{
	int rc = 0;

	if (kaux_version(info))
		return -EPROTONOSUPPORT;

	mutex_lock(&g_staged_lock);
	if (g_staged_total == 0 || g_staged_pairs != g_staged_total) {
		rc = -EINVAL;
		goto out;
	}
	if (kaux_crc32(g_staged, 2 * g_staged_pairs) != g_staged_crc) {
		pr_err("uidfake: policy crc mismatch, keeping previous one\n");
		rc = -EINVAL;
		goto out;
	}

	pr_info("uidfake: netlink policy: %u pair(s) in pages\n",
		g_staged_pairs);
	policy_apply(g_staged, g_staged_pairs);
	g_staged_total = 0;
	g_staged_pairs = 0;

out:
	mutex_unlock(&g_staged_lock);
	return rc;
}

/*
 * The apk inodes of the apps that have rules: u32 n, then n * (dev, ino_lo,
 * ino_hi, uid). Read in userspace, where package names live; the kernel only
 * compares the numbers.
 */
static int kaux_apk(struct sk_buff *skb, struct genl_info *info)
{
	const u32 *p;
	u32 len, n;

	if (!info->attrs[KAUX_ATTR_BLOB])
		return -EINVAL;
	p = nla_data(info->attrs[KAUX_ATTR_BLOB]);
	len = nla_len(info->attrs[KAUX_ATTR_BLOB]);
	if (len < 4 || (len & 3) || len > MAX_BLOB_BYTES)
		return -EINVAL;
	n = p[0];
	if ((unsigned long long)len < 4ull + 16ull * (unsigned long long)n)
		return -EINVAL;
	pr_info("uidfake: netlink caller code dirs: %u entr(ies)\n", n);
	return uidfake_apk_apply(p + 1, n);
}

static int kaux_ping(struct sk_buff *skb, struct genl_info *info)
{
	if (kaux_version(info))
		return -EPROTONOSUPPORT;

	/* A command id that lands here instead of where it belongs would otherwise
   * look like a success, because a ping is answered with an ACK like anything
   * else. */
	pr_info("uidfake: netlink ping\n");
	return 0;
}

/*
 *
 * The helper builds this from /proc: an app and the isolated processes it
 * spawns share one category layout is baked in here, the map is simply what the
 * helper measured.
 */

static const struct genl_ops kaux_ops[] = {
	{ .cmd = KAUX_CMD_PING, .flags = GENL_ADMIN_PERM, .doit = kaux_ping },
	{ .cmd = KAUX_CMD_APK, .flags = GENL_ADMIN_PERM, .doit = kaux_apk },
	{ .cmd = KAUX_CMD_SET_BEGIN,
	  .flags = GENL_ADMIN_PERM,
	  .doit = kaux_set_begin },
	{ .cmd = KAUX_CMD_SET_PAGE,
	  .flags = GENL_ADMIN_PERM,
	  .doit = kaux_set_page },
	{ .cmd = KAUX_CMD_SET_COMMIT,
	  .flags = GENL_ADMIN_PERM,
	  .doit = kaux_set_commit },
};

static const struct genl_multicast_group kaux_mcgrps[] = {
	{ .name = "events" }
};

static struct genl_family kaux_family = {
	.name = KAUX_FAMILY_NAME,
	.version = KAUX_FAMILY_VERSION,
	.maxattr = KAUX_ATTR_MAX,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	.resv_start_op = KAUX_CMD_MAX + 1,
#endif
	.module = THIS_MODULE,
	.ops = kaux_ops,
	.n_ops = ARRAY_SIZE(kaux_ops),
	.mcgrps = kaux_mcgrps,
	.n_mcgrps = ARRAY_SIZE(kaux_mcgrps),
};

int netlink_init(void)
{
	int rc;

	g_staged = kcalloc(2 * (size_t)POLICY_MAX_PAIRS, sizeof(*g_staged),
			   GFP_KERNEL);
	if (!g_staged)
		return -ENOMEM;
	rc = genl_register_family(&kaux_family);

	pr_info("uidfake: netlink family '%s' register rc=%d\n",
		KAUX_FAMILY_NAME, rc);
	return rc;
}

void netlink_exit(void)
{
	genl_unregister_family(&kaux_family);
	kfree(g_staged);
	g_staged = NULL;
}
