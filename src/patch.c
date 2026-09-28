// SPDX-License-Identifier: GPL-2.0
/*
 * patch.c - write a few bytes into read-only kernel or module text.
 *
 * Kernel text is mapped read-only and the helpers that would normally make it
 * writable (set_memory_rw, text_poke) are not exported to modules. Instead the
 * physical page is translated through init_mm and mapped again writable with
 * vmap(); the instruction cache is cleaned afterwards and the synchronous path
 * stops all other CPUs, because one of them can be executing the very
 * instruction being replaced.
 *
 * The technique is the one every out-of-tree patcher on arm64 ends up using;
 * this is an independent implementation.
 */
#include <asm/cacheflush.h>
#include <asm/pgtable.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/stop_machine.h>
#include <linux/vmalloc.h>

#include "uidfake.h"

static int probe_noop(struct kprobe *p, struct pt_regs *r)
{
	return 0;
}

/*
 * Symbol lookup, the way KernelSU does it on arm64: resolve a name through
 * kallsyms, accept the CFI jump-table variant of it as well (that is what a call
 * site reaches on a CFI kernel), and fall back to walking the whole kallsyms
 * table when kallsyms_lookup_name() cannot be had. Nothing here reads an offset
 * out of a function body.
 *
 * kallsyms_lookup_name() and kallsyms_on_each_symbol() are not exported to
 * modules, so their own addresses come from a probe registered on them -- kprobe
 * resolves .symbol_name through kallsyms internally -- unregistered immediately,
 * so nothing stays behind.
 */
static unsigned long lookup_exported(const char *symbol)
{
	struct kprobe kp = { .symbol_name = symbol, .pre_handler = probe_noop };
	unsigned long addr;

	if (register_kprobe(&kp))
		return 0;
	addr = (unsigned long)kp.addr;
	unregister_kprobe(&kp);
	return addr;
}

static unsigned long lookup_name(const char *name)
{
	unsigned long (*fn)(const char *) =
		(void *)lookup_exported("kallsyms_lookup_name");

	return fn ? fn(name) : 0;
}

struct find_ctx {
	const char *name;
	unsigned long addr;
	unsigned long next; /* the following symbol: where the body ends */
};

/*
 * The walk has to see every symbol: the one after a match is the end of it, so it
 * cannot stop at the match itself.
 */
static int find_symbol_cb(void *data, const char *name, unsigned long addr)
{
	struct find_ctx *ctx = data;

	if (ctx->addr && addr > ctx->addr && (!ctx->next || addr < ctx->next))
		ctx->next = addr;
	if (!ctx->addr && name && strcmp(name, ctx->name) == 0)
		ctx->addr = addr;
	return 0;
}

/* For kernels before 6.6 the callback carries the module a symbol came from: a
 * module may shadow a name, so those are skipped. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
static int find_symbol_cb_mod(void *data, const char *name, struct module *mod,
			      unsigned long addr)
{
	if (mod)
		return 0;
	return find_symbol_cb(data, name, addr);
}
#endif

static void find_symbol(const char *name, struct find_ctx *ctx)
{
	int (*walk)(void *, int (*)(void *, const char *, unsigned long),
		    void *) =
		(void *)lookup_exported("kallsyms_on_each_symbol");

	ctx->name = name;
	ctx->addr = 0;
	ctx->next = 0;
	if (!walk)
		return;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	walk(ctx, find_symbol_cb, NULL);
#else
	/*
	 * The older signature takes the callback with the module argument, so it is
	 * called through a small shim with the same shape.
	 */
	{
		int (*old)(void *,
			   int (*)(void *, const char *, struct module *,
				   unsigned long),
			   void *) = (void *)walk;

		old(ctx, find_symbol_cb_mod, NULL);
	}
#endif
}

unsigned long uidfake_lookup(const char *name)
{
	unsigned long addr = lookup_name(name);
	char dotted[KSYM_NAME_LEN + 16];

	if (addr)
		return addr;

	/* The CFI variant: selinux_setprocattr becomes selinux_setprocattr..cfi_jt. */
	if (!strchr(name, '.') && snprintf(dotted, sizeof(dotted), "%s..cfi_jt",
					   name) < (int)sizeof(dotted)) {
		addr = lookup_name(dotted);
		if (addr)
			return addr;
	}

	{
		struct find_ctx ctx;

		find_symbol(name, &ctx);
		return ctx.addr;
	}
}

unsigned long uidfake_lookup_end(const char *name)
{
	struct find_ctx ctx;

	find_symbol(name, &ctx);
	return ctx.next;
}

/*
 * Symbols the patcher needs at run time. init_mm is not exported,
 * kimage_voffset/kallsyms are not either, so all of them go through the same
 * transient-probe resolver.
 */
static struct mm_struct *patch_mm;

/* [_stext, _end): the only range this module is willing to write into. */
static unsigned long g_text_start;
static unsigned long g_text_end;
static unsigned long *g_kimage_voffset;
static bool g_walk_warned;
static unsigned long *g_memstart_addr;

int uidfake_patch_init(void)
{
	/* The kernel's own extent: every patch target has to be inside it, or the
	 * write would land somewhere it has no business being. */
	g_text_start = uidfake_lookup("_stext");
	g_text_end = uidfake_lookup("_end");

	patch_mm = (struct mm_struct *)uidfake_lookup("init_mm");
	g_kimage_voffset = (unsigned long *)uidfake_lookup("kimage_voffset");
	g_memstart_addr = (unsigned long *)uidfake_lookup("memstart_addr");
	if (UF_DEBUG_ON())
		pr_info("uidfake: init_mm=%px kimage_voffset=%px memstart_addr=%px\n",
			patch_mm, (void *)g_kimage_voffset,
			(void *)g_memstart_addr);
	return patch_mm ? 0 : -ENOENT;
}
struct patch_req {
	void *addr;
	const void *src;
	size_t len;
};

/*
 * The 4 KB page backing a kernel address, plus the offset inside it. Kernel
 * .rodata (where sys_call_table lives) is often mapped as a 2 MB block, and the
 * image as 1 GB blocks, so block mappings have to be resolved to the page
 * inside them instead of being rejected.
 */
static struct page *kernel_page(unsigned long addr, unsigned long *off)
{
	pgd_t *pgd = pgd_offset(patch_mm, addr);
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	phys_addr_t phys;

	if (pgd_none(*pgd) || pgd_bad(*pgd))
		return NULL;
	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		return NULL;
	pud = pud_offset(p4d, addr);
	if (pud_none(*pud) || pud_bad(*pud))
		return NULL;
	*off = offset_in_page(addr);
	if (pud_leaf(*pud)) {
		phys = (phys_addr_t)(pud_val(*pud) & ~(PUD_SIZE - 1)) +
		       (addr & (PUD_SIZE - 1));
		return pfn_to_page(phys >> PAGE_SHIFT);
	}
	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd) || pmd_bad(*pmd))
		return NULL;
	if (pmd_leaf(*pmd)) {
		phys = (phys_addr_t)(pmd_val(*pmd) & ~(PMD_SIZE - 1)) +
		       (addr & (PMD_SIZE - 1));
		return pfn_to_page(phys >> PAGE_SHIFT);
	}
	pte = pte_offset_kernel(pmd, addr);
	if (pte_none(*pte))
		return NULL;
	return pte_page(*pte);
}
/*
 * Cache maintenance inlined by hand: __builtin___clear_cache() lowers to a call
 * to
 * __clear_cache(), which the kernel does not export (the module would fail to
 * load with "Unknown symbol __clear_cache").
 */
static unsigned long cache_dline(void)
{
	unsigned long ctr;

	asm volatile("mrs %0, ctr_el0" : "=r"(ctr));
	return 4UL << ((ctr >> 16) & 0xf);
}

static unsigned long cache_iline(void)
{
	unsigned long ctr;

	asm volatile("mrs %0, ctr_el0" : "=r"(ctr));
	return 4UL << (ctr & 0xf);
}

static void cache_clean_inval(void *addr, size_t len)
{
	unsigned long start = (unsigned long)addr;
	unsigned long end = start + len;
	unsigned long dline = cache_dline();
	unsigned long iline = cache_iline();
	unsigned long p;

	for (p = start & ~(dline - 1); p < end; p += dline)
		asm volatile("dc cvau, %0" ::"r"(p) : "memory");
	dsb(ish);
	for (p = start & ~(iline - 1); p < end; p += iline)
		asm volatile("ic ivau, %0" ::"r"(p) : "memory");
	dsb(ish);
	isb();
}

/*
 * Physical address of a kernel image address without walking page tables: with
 * KASLR the image is offset by kimage_voffset, so pa = va - kimage_voffset.
 * Used when the walk cannot resolve the address, for instance because struct
 * mm_struct differs from the tree this module was built against.
 */
static phys_addr_t image_phys(unsigned long addr)
{
	phys_addr_t base, end, pa;
	unsigned long voff;

	if (g_kimage_voffset)
		voff = *g_kimage_voffset;
	else if (g_memstart_addr)
		voff = (unsigned long)(KIMAGE_VADDR - *g_memstart_addr);
	else
		return 0;

	pa = (phys_addr_t)(addr - voff);
	/*
	 * The offset has to put the target inside the image's own physical extent.
	 * When it does not -- a vendor kernel whose kimage_voffset this module did
	 * not read correctly, or an mm_struct that is not the tree's -- the write
	 * would land on an unrelated page, so it is refused instead.
	 */
	if (!g_text_start || !g_text_end)
		return 0;
	base = (phys_addr_t)(g_text_start - voff);
	end = (phys_addr_t)(g_text_end - voff);
	if (pa < base || pa >= end)
		return 0;
	return pa;
}

static struct page *page_for(unsigned long addr, unsigned long *off)
{
	struct page *page = kernel_page(addr, off);
	phys_addr_t phys;

	if (page)
		return page;
	phys = image_phys(addr);
	if (!phys)
		return NULL;
	if (!g_walk_warned) {
		g_walk_warned = true;
		pr_info("uidfake: page table walk unusable (vendor mm_struct); using kimage_voffset\n");
	}
	return pfn_to_page(phys >> PAGE_SHIFT);
}

static int patch_do(void *arg)
{
	struct patch_req *r = arg;
	unsigned long off;
	struct page *page = page_for((unsigned long)r->addr, &off);
	void *alias;

	if (!page) {
		pr_warn("uidfake: no page for %p\n", r->addr);
		return -EFAULT;
	}
	alias = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	if (!alias) {
		pr_warn("uidfake: vmap of %p failed\n", r->addr);
		return -ENOMEM;
	}
	memcpy(alias + off, r->src, r->len);
	/* the line is physically tagged, so cleaning through the alias covers the
   * target too */
	vunmap(alias);
	return 0;
}

int uidfake_patch_text(void *dst, const void *src, size_t len, bool sync)
{
	struct patch_req req = { .addr = dst, .src = src, .len = len };
	int ret;

	if (!len || (unsigned long)dst & 3 || len & 3)
		return -EINVAL;
	/* Refuse anything outside the kernel image before a single byte is written:
	 * a wrong physical address used to be caught only by reading the target
	 * back, which is too late -- the stray write has already happened. */
	if (!g_text_start || !g_text_end || (unsigned long)dst < g_text_start ||
	    (unsigned long)dst + len > g_text_end) {
		pr_warn("uidfake: refusing to patch %px: outside the kernel image\n",
			dst);
		return -EPERM;
	}
	if (offset_in_page((unsigned long)dst) + len > PAGE_SIZE)
		return -EINVAL;

	ret = sync ? stop_machine(patch_do, &req, NULL) : patch_do(&req);
	if (ret)
		return ret;

	/* make the new instructions visible to every CPU */
	cache_clean_inval(dst, len);
	return 0;
}
