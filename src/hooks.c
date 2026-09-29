// SPDX-License-Identifier: GPL-2.0
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/ioprio.h>
#include <linux/kernel.h>
#include <linux/version.h>

#include <linux/module.h>
#include <linux/resource.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/uidgid.h>
#include <linux/user.h>

#include "uidfake.h"
#include "kaux.h"

/*
 * What the module tells userspace about itself (include/kaux.h). The tool reads
 * it and puts it in the module description, which is where KernelSU and Magisk
 * show a module's state -- so a hook that was not taken is something a user can
 * see without a dmesg.
 */
static struct kaux_status g_status = {
	.magic = KAUX_STATUS_MAGIC,
	.version = KAUX_FAMILY_VERSION,
	/* what this build assumes; the tool checks it against the running kernel */
	.va_bits = CONFIG_ARM64_VA_BITS,
	.page_shift = PAGE_SHIFT,
};

void uidfake_status_get(struct kaux_status *out)
{
	*out = g_status;
	/* The reader checks these before it believes anything else, so they are set
	 * here and not left to whoever filled the rest in. */
	out->magic = KAUX_STATUS_MAGIC;
	out->size = sizeof(*out);
	out->version = KAUX_FAMILY_VERSION;
}

void uidfake_status_set_hooks(unsigned int native, unsigned int compat)
{
	g_status.native = native;
	g_status.compat = compat;
	if (native == g_status.native_expected)
		g_status.flags |= KAUX_F_NATIVE;
	if (compat == g_status.compat_expected)
		g_status.flags |= KAUX_F_COMPAT;
}

void uidfake_status_set_lsm(int state, int error, const char *target)
{
	g_status.lsm_state = state;
	g_status.lsm_error = error;
	if (state == KAUX_LSM_TAKEN)
		g_status.flags |= KAUX_F_SETUID;
	if (target)
		strscpy(g_status.lsm_target, target,
			sizeof(g_status.lsm_target));
}

void uidfake_status_set_apks(unsigned int inodes, unsigned int expected,
			     unsigned int failed)
{
	g_status.apk_inodes = inodes;
	g_status.apk_offered = expected;
	g_status.apk_failed = failed;
	/*
	 * An inode that could not be put in place is worth keeping: the next apply
	 * that goes well would otherwise report no failures at all, and a hook that
	 * is missing on one file is not something a later success undoes.
	 */
	g_status.apk_failed_total += failed;
	g_status.apk_updates++;
	if (failed == 0)
		g_status.flags |= KAUX_F_APKS;
}

void uidfake_status_note(int error)
{
	g_status.last_error = error;
}

/* The window is closed from the query path too (see uidfake_close_pending). */
void uidfake_tag_close(void);

/* one translation unit with the policy: its query is on the hot path and the
 * compiler can then inline it into the syscall wrappers instead of paying a
 * call for every query */
#include "policy.c"

#define ARG_UID 0 /* find_user(kuid_t uid): uid in x0 */
#define ARG_WHO \
	1 /* getpriority/setpriority/ioprio_get/ioprio_set: (which, who, ...) */

/* syscall_fn_t is not declared for every KMI the module builds against */
typedef long (*uidfake_syscall_t)(const struct pt_regs *);

/*
 * nr is where the entry is expected to be, and is replaced by where it really is
 * once the slot has been found. A table is searched for the wrapper that is
 * supposed to be in it -- the same thing KernelSU does to find a free slot for
 * its dispatcher -- so the number itself is a shortcut and not the thing that
 * decides what gets patched. On a kernel whose numbering, 32-bit ABI or vendor
 * syscalls differ from the tree this module was built against, the constant
 * would point at the wrong entry and the patch that followed would be a hook on
 * someone else's syscall; looking the wrapper up instead cannot do that, and an
 * entry that cannot be found is simply not hooked.
 */
struct hook_entry {
	unsigned int nr;
	uidfake_syscall_t ours;
	uidfake_syscall_t orig;
	const char *sym;
	/*
	 * The table entry of the other (64-bit) table this one has to hold the same
	 * function as, or -1 to resolve sym instead. The 32-bit ABI calls the same
	 * implementations for the syscalls this module cares about -- unistd32.h maps
	 * getpriority to sys_getpriority and so on -- but through its own table, so
	 * the value to look for is the address the 64-bit table held, not a name and
	 * not a number. Names are what this replaced: the numbers this module used to
	 * carry (141 for getpriority) were not even the 32-bit ones (96), and on a
	 * device where the 32-bit table has no such entry at all there is nothing to
	 * find and nothing is hooked.
	 */
	int native;
	/*
	 * The other way a 32-bit table names the same syscall: some kernels wrap
	 * compat syscalls in __arm64_compat_sys_<name> and put that in the table,
	 * where others put the 64-bit implementation itself. Both are accepted --
	 * the value found in the table is what decides, and the device decides which
	 * of the two its kernel has.
	 */
	const char *sym32;
};

/*
 * Only data is patched, never an instruction: the syscall table entries are
 * indirect calls, so there is no branch range to worry about (a module region
 * is farther from the image than a bl can reach), no BTI landing pad and no PAC
 * prologue. A wrapper never touches the task's pt_regs either -- it copies it,
 * substitutes the uid in the copy and runs the real wrapper with that, so
 * find_user() fails exactly like for a uid that does not exist while
 * /proc/<tid>/syscall, ptrace and the syscall-exit stop keep seeing the
 * original argument.
 *
 * This is the mechanism KernelSU uses. Fallback: if the table cannot be
 * resolved or patched, the verified sys_call_table patch is the only hook.
 */

asmlinkage long uidfake_getpriority(const struct pt_regs *regs);
asmlinkage long uidfake_setpriority(const struct pt_regs *regs);
asmlinkage long uidfake_ioprio_get(const struct pt_regs *regs);
asmlinkage long uidfake_ioprio_set(const struct pt_regs *regs);

static struct hook_entry g_hook[] = {
	{ __NR_getpriority, uidfake_getpriority, NULL,
	  "__arm64_sys_getpriority", -1, NULL },
	{ __NR_setpriority, uidfake_setpriority, NULL,
	  "__arm64_sys_setpriority", -1, NULL },
	{ __NR_ioprio_get, uidfake_ioprio_get, NULL, "__arm64_sys_ioprio_get",
	  -1, NULL },
	{ __NR_ioprio_set, uidfake_ioprio_set, NULL, "__arm64_sys_ioprio_set",
	  -1, NULL },
};

/*
 * AArch32 binaries go through compat_sys_call_table with the ARM (EABI)
 * numbers. They are stable ABI constants: getpriority/setpriority are 141/140
 * in both tables, ioprio is not (314/315 here against 31/30 in the 64-bit
 * generic table).
 */
#ifdef CONFIG_COMPAT
/* The 32-bit (EABI) numbers of the same four: a hint for the first comparison,
 * the value found in the table is what decides. */
#define NR32_GETPRIORITY 96
#define NR32_SETPRIORITY 97
#define NR32_IOPRIO_SET 314
#define NR32_IOPRIO_GET 315

asmlinkage long uidfake32_getpriority(const struct pt_regs *regs);
asmlinkage long uidfake32_setpriority(const struct pt_regs *regs);
asmlinkage long uidfake32_ioprio_get(const struct pt_regs *regs);
asmlinkage long uidfake32_ioprio_set(const struct pt_regs *regs);

static struct hook_entry g_chook[] = {
	{ NR32_GETPRIORITY, uidfake32_getpriority, NULL, NULL, 0,
	  "__arm64_compat_sys_getpriority" },
	{ NR32_SETPRIORITY, uidfake32_setpriority, NULL, NULL, 1,
	  "__arm64_compat_sys_setpriority" },
	{ NR32_IOPRIO_GET, uidfake32_ioprio_get, NULL, NULL, 2,
	  "__arm64_compat_sys_ioprio_get" },
	{ NR32_IOPRIO_SET, uidfake32_ioprio_set, NULL, NULL, 3,
	  "__arm64_compat_sys_ioprio_set" },
};

#endif

/*
 * Substitute the uid argument when the policy hides it, then run the real
 * wrapper.
 *
 * Only the argument registers are copied: the generated __arm64_sys_* wrappers
 * read exactly regs[0..2] (which/who/prio) and never pass the pt_regs on, so
 * the rest of the copy is never touched. The copy is unconditional and the
 * substituted value is selected with csel, so a hidden uid and a uid that does
 * not exist execute the same instruction stream -- only the register value
 * differs. The task's own pt_regs is never modified, so /proc/<tid>/syscall,
 * ptrace and the syscall-exit stop keep seeing the original argument.
 */
/*
 * The ten syscalls hooked here take three arguments at most, and the generated
 * __arm64_sys_* wrappers read exactly those argument registers -- so the
 * substituted call is handed a three register object instead of a whole
 * pt_regs. The full struct made the compiler zero 312 bytes on every hooked
 * call (a memset call, not three stores), and it pushed the frame over the size
 * that turns the stack canary on. The copy stays unconditional, so a hidden uid
 * and a uid that does not exist still execute the same instruction stream.
 */
struct uidfake_args {
	u64 regs[3];
};

/*
 * The original syscall is reached through a pointer this module stored, and a
 * pre-kCFI kernel checks such calls against the callee's jump table; the functions
 * that make them are marked __nocfi, as KernelSU's dispatcher is.
 */
static asmlinkage long __nocfi uid_hook(const struct pt_regs *regs,
					unsigned int which_user,
					uidfake_syscall_t orig)
{
	struct uidfake_args args;
	u32 repl;

	args.regs[0] = regs->regs[0];
	args.regs[1] = regs->regs[1];
	args.regs[2] = regs->regs[2];
	if ((u32)regs->regs[0] != which_user)
		return orig(regs);

	repl = policy_query((u32)regs->regs[ARG_WHO]);
	args.regs[ARG_WHO] = repl ? (u64)repl : regs->regs[ARG_WHO];
	return orig((const struct pt_regs *)&args);
}

asmlinkage long uidfake_getpriority(const struct pt_regs *regs)
{
	return uid_hook(regs, PRIO_USER, g_hook[0].orig);
}

asmlinkage long uidfake_setpriority(const struct pt_regs *regs)
{
	return uid_hook(regs, PRIO_USER, g_hook[1].orig);
}

asmlinkage long uidfake_ioprio_get(const struct pt_regs *regs)
{
	return uid_hook(regs, IOPRIO_WHO_USER, g_hook[2].orig);
}

asmlinkage long uidfake_ioprio_set(const struct pt_regs *regs)
{
	return uid_hook(regs, IOPRIO_WHO_USER, g_hook[3].orig);
}

#ifdef CONFIG_COMPAT
asmlinkage long uidfake32_getpriority(const struct pt_regs *regs)
{
	return uid_hook(regs, PRIO_USER, g_chook[0].orig);
}

asmlinkage long uidfake32_setpriority(const struct pt_regs *regs)
{
	return uid_hook(regs, PRIO_USER, g_chook[1].orig);
}

asmlinkage long uidfake32_ioprio_get(const struct pt_regs *regs)
{
	return uid_hook(regs, IOPRIO_WHO_USER, g_chook[2].orig);
}

asmlinkage long uidfake32_ioprio_set(const struct pt_regs *regs)
{
	return uid_hook(regs, IOPRIO_WHO_USER, g_chook[3].orig);
}
#endif

/* ---- table patching ---- */

static uidfake_syscall_t *main_table;
#ifdef CONFIG_COMPAT
static uidfake_syscall_t *compat_table;
#endif

/*
 * The slot that holds the wrapper this entry is for, or NULL. The number is
 * tried first, and the table is searched for the wrapper when that does not
 * match it. Both spellings are accepted, because a pre-kCFI kernel puts the
 * jump-table address of a function in its table.
 */
#define UF_TABLE_SCAN \
	512 /* the largest arm64 table, 64-bit or 32-bit, is ~450 */

static uidfake_syscall_t *find_slot(uidfake_syscall_t *table,
				    struct hook_entry *e)
{
	/* uidfake_lookup() gives the spelling a table holds -- the jump-table entry
	 * before 6.1 and the plain symbol from there on, which is the rule KernelSU
	 * resolves a functable hook with; the other spelling is accepted too. */
	/*
	 * Every way the same syscall can be named in a table: the 64-bit
	 * implementation, the entry's own symbol in both spellings, and the compat
	 * wrapper under both of its names in both spellings. KernelSU and its forks
	 * do not cover 32-bit callers at all -- they return early for a compat task
	 * and never touch compat_sys_call_table -- so there is no method to follow
	 * here; what is left is to accept everything a kernel might have put there
	 * and patch the one that is actually in the table.
	 */
	unsigned long want[8];
	unsigned int nwant = 0, i;
	bool found = false;

	if (e->native >= 0 && g_hook[e->native].orig) {
		/* the implementation the 64-bit table had for this syscall: what some
		 * kernels put in the 32-bit table as well */
		want[nwant++] = (unsigned long)g_hook[e->native].orig;
	}
	if (e->sym) {
		want[nwant++] = uidfake_lookup(e->sym);
		want[nwant++] = uidfake_lookup_raw(e->sym);
	}
	if (e->sym32) {
		/* or the compat wrapper of its own, on kernels that have one: the
		 * jump-table spelling first, the plain symbol after it. Some trees name
		 * it compat_sys_<name> rather than __arm64_compat_sys_<name>, so that
		 * spelling is added as well when the name carries the prefix. */
		const char *pfx = strstr(e->sym32, "__arm64_");
		const char *alt = pfx ? pfx + strlen("__arm64_") : NULL;

		want[nwant++] = uidfake_lookup(e->sym32);
		want[nwant++] = uidfake_lookup_raw(e->sym32);
		if (alt) {
			want[nwant++] = uidfake_lookup(alt);
			want[nwant++] = uidfake_lookup_raw(alt);
		}
	}
	for (i = 0; i < nwant; i++)
		if (want[i])
			found = true;
	if (!found)
		return NULL;

	/* the number is only the first guess, and only when it agrees */
	if (e->nr < UF_TABLE_SCAN) {
		for (i = 0; i < nwant; i++) {
			if (want[i] &&
			    table[e->nr] == (uidfake_syscall_t)want[i])
				return &table[e->nr];
		}
	}

	for (i = 0; i < UF_TABLE_SCAN; i++) {
		unsigned int k;

		for (k = 0; k < nwant; k++) {
			if (want[k] && table[i] == (uidfake_syscall_t)want[k]) {
				e->nr = i;
				return &table[i];
			}
		}
	}
	return NULL;
}

static unsigned int patch_entries(uidfake_syscall_t *table,
				  struct hook_entry *e, unsigned int n,
				  bool required)
{
	unsigned int i, done = 0;

	for (i = 0; i < n; i++) {
		uidfake_syscall_t *slot = find_slot(table, &e[i]);
		uidfake_syscall_t orig;

		if (!slot) {
			pr_warn("uidfake: no slot held for %s; not hooked\n",
				e[i].sym ? e[i].sym : "a 32-bit entry");
			e[i].orig = NULL;
			if (required) {
				uidfake_status_note(-ENOENT);
				return done;
			}
			continue;
		}
		done++;
		orig = slot[0];
		if (uidfake_patch_text(slot, &e[i].ours,
				       sizeof(uidfake_syscall_t), true) ||
		    slot[0] != e[i].ours) {
			pr_warn("uidfake: patching syscall %u failed\n",
				e[i].nr);
			e[i].orig = NULL;
			uidfake_status_note(-EIO);
			return required ? i : done - 1;
		}
		e[i].orig = orig;
	}
	return done;
}

static void unpatch_entries(uidfake_syscall_t *table, struct hook_entry *e,
			    unsigned int n)
{
	unsigned int i;

	if (!table)
		return;
	for (i = 0; i < n; i++) {
		/*
		 * Only when the entry is still this module's, and only the value that
		 * was there when it was taken. Another patcher may have replaced it
		 * since -- its hook is the live one then, and undoing it here would
		 * silently remove work that is not ours; and what was saved may be an
		 * address inside a module that has already gone, which is a call to
		 * nothing once it is written back.
		 */
		if (!e[i].orig) {
			continue;
		} else if (table[e[i].nr] != e[i].ours) {
			pr_warn("uidfake: syscall %u is no longer ours; leaving it alone\n",
				e[i].nr);
		} else {
			uidfake_patch_text(&table[e[i].nr],
					   (const void *)&e[i].orig,
					   sizeof(uidfake_syscall_t), true);
		}
		e[i].orig = NULL;
	}
}

static int patch_tables(void)
{
	unsigned long table = uidfake_lookup("sys_call_table");
	unsigned int n;

	if (!table)
		return -ENOENT;
	/* Real addresses go behind the debug key: dmesg is readable on plenty of devices. */
	if (UF_DEBUG_ON())
		pr_info("uidfake: sys_call_table=%px locator check: find_user=%px linked=%px\n",
			(void *)table, (void *)uidfake_lookup("find_user"),
			(void *)find_user);

	g_status.native_expected = ARRAY_SIZE(g_hook);
#ifdef CONFIG_COMPAT
	g_status.compat_expected = ARRAY_SIZE(g_chook);
#endif

	main_table = (uidfake_syscall_t *)table;
	n = patch_entries(main_table, g_hook, ARRAY_SIZE(g_hook), true);
	if (n != ARRAY_SIZE(g_hook)) {
		unpatch_entries(main_table, g_hook, n);
		return -EIO;
	}
	pr_info("uidfake: %u uid syscall(s) hooked in sys_call_table\n", n);
	uidfake_status_set_hooks(n, 0);
	/*
   * Off by default: the probe exercises the sid->context call, and if the call
   * shape were ever
   */

#ifdef CONFIG_COMPAT
	table = uidfake_lookup("compat_sys_call_table");
	if (table) {
		compat_table = (uidfake_syscall_t *)table;
		n = patch_entries(compat_table, g_chook, ARRAY_SIZE(g_chook),
				  false);
		if (n != ARRAY_SIZE(g_chook))
			pr_warn("uidfake: %u of %u 32-bit entr(ies) hooked; the rest are not in this kernel's 32-bit table\n",
				n, (unsigned)ARRAY_SIZE(g_chook));
		pr_info("uidfake: %u uid syscall(s) hooked in compat_sys_call_table\n",
			n);
		uidfake_status_set_hooks(g_status.native, n);
	}
#endif
	return 0;
}

int hooks_install(void)
{
	if (uidfake_patch_init())
		return 0;

	/*
	 * Where the kernel hands both creds over at the commit, that hook is what the
	 * id setters used to be. Taken before the tables are patched, so a hook that
	 * cannot be taken is known before anything else is installed.
	 */
	/*
	 * The change of identity is watched where the kernel commits it, and there is
	 * no second mechanism behind this one: a kernel where the hook cannot be taken
	 * gets a module that hides callers but never learns about new ones, and says
	 * so loudly, instead of quietly hooking the syscalls the id setters use.
	 */
	{
		const int lsm = uidfake_lsm_install();

		if (lsm)
			pr_err("uidfake: setuid hook not taken (%d); identity changes are NOT watched\n",
			       lsm);
		else
			pr_info("uidfake: id changes are watched at the commit\n");
	}

	if (!patch_tables()) {
		/*
     * The vendor hook covers every open path, not just openat, and keeps
     * sys_call_table down to the uid syscalls.
     */
		uidfake_tag_prime(); /* give the processes that already run their tag */
		return 1;
	}

	pr_warn("uidfake: could not hook sys_call_table, no hook installed\n");
	return 0;
}

void hooks_remove(void)
{
	/* The apk inodes are ours whatever the table did: put them back first. */
	uidfake_apk_remove();

	/* nothing was patched means nothing to tear down: there is no fallback */
	if (!main_table)
		return;

	unpatch_entries(main_table, g_hook, ARRAY_SIZE(g_hook));
#ifdef CONFIG_COMPAT
	unpatch_entries(compat_table, g_chook, ARRAY_SIZE(g_chook));
	compat_table = NULL;
#endif
	main_table = NULL;

	/* the identity changes stay covered until the last moment */
	uidfake_lsm_remove();
}
