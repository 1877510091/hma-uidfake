# Design

## Queries

The four syscalls a uid scanner uses have their entries in `sys_call_table` (and the AArch32 numbers
in `compat_sys_call_table`) redirected, not the syscalls themselves: the hook substitutes the uid
argument and calls the original, which takes its own "no such uid" branch. The caller side comes
from the birth tag rather than from the current uid -- one table load and a `csel` -- so changing
uid cannot move a process into another set of rules. `/proc` and ptrace see the argument as the
caller wrote it, and there is nothing to restore.

## Naming an isolated child

An isolated process gets its uid at birth and nothing else says which app it came from:

1. **Birth.** When zygote hands an app uid to a fresh process, or `app_zygote` hands an isolated uid
to one, the app id goes into bits 40..55 of `thread_info.flags` (zero = untagged), and an isolated
child also gets a pending bit above that field, so the hot path tests both with one AND. The tag is
never rewritten or cleared, and `fork()` copies it.
2. **The first code file it opens.** While the pending bit is set, the vendor hook looks at
consecutive opens until one lands on a filesystem an app's code lives on -- the framework's own
startup reads properties, `/proc`, `/dev` and `/system`, none of which counts. From
`file->f_path.dentry` it walks up at most four dentries comparing inodes against the registered
caller code dirs; a hit names the whole thread group after that app, whichever file inside the
directory was opened (apk, vdex, odex, library). A miss ends the wait for good.
3. **Before the module loads.** `uidfake_tag_prime()` derives the same tag for every running task
from its uid and the SELinux sid of its creds, the pair the zygote path writes. Without it a manual
`rmmod`/`insmod` would lose the identity of every running app. That pair is also what the
`setuid`-family hooks write, which is why they are hooked: `setuid()` cannot choose its rules.

## Diagnostics

Diagnostics sit behind a static key (jump label): with the key off the branch is a NOP.

```
insmod hma_uidfake.ko debug=1        # for 60 seconds, then off again
```

Only the two lines that report a real event are ungated (`iso birth uid ... marked`, `iso uid ...
belongs to app ...`). The rest -- the devs treated as code, a directory an open reached with no rule
for it, an untagged caller -- is what the parameter is for.

## Invariants

- Never take the `find_user()` hit path: it walks every process at ~1000x the cost of a miss, which
  timing shows. The argument is rewritten instead and the kernel takes its own miss branch.
- The replacement uid hashes into the same bucket as the target (`__uidhashfn(uid) = ((uid >> 7) +
  uid) & 127`), or the chain length would differ from a genuinely absent uid.
- The lookup does constant work: one hash of the target with the kernel's own uid hash (read back
  from `find_user()` when a policy is applied) gives the bucket line and the starting slot; the line
  index is that formula or its mirrored twin, whichever keeps the address independent of the
  contents; the probe count is fixed when the policy is laid out (1, 2, 4 or 8) and each reads its
  slot and the mask words of all eight; indices are masked, never branched on; `cmp`+`csel` picks
  the bit and the replacement. A query touches a function of `(caller, target)` alone --
  `scripts/lookup_model.py` states that function.
- Never touch the syscall's `pt_regs`: the probe sits on `find_user()`, the first place a uid is a
  plain argument register. (arm64 has no in-register syscall entry to hook: no `__do_sys_`/
  `__se_sys_` symbol.)
- The kernel only compares numbers; whatever needs a path, a package name or JSON happens in
  `sync-tool`, and what arrives is checked for shape and size.
- A rejected update changes nothing: a policy that does not fit, a caller that is not an app uid, a
  group larger than the tables -- each is logged and the previous policy stays in force, because
  half a policy is the state that leaks.

## Trust

- The netlink family is `GENL_ADMIN_PERM`: only root can push a policy, both blobs are
  length-checked before they are parsed, and nothing is copied back out.
- HMA's `config.json` decides who is hidden and belongs to HMA's uid; `sync-tool` reads nothing an
  app can write.
- The tag lives in bits 40..55 of `thread_info.flags`, which nothing else uses on these kernels, and
  is only read-modify-written with those bits masked out.
- The ten hooked syscalls take at most three arguments, which is what the register object they
  receive covers.
- Normal runs print no addresses; the two init lines that do are behind the debug key.
- The timing a hidden uid still costs is measured, not assumed away: `src/tools/uidbench.c` samples
  the hidden, absent and unhooked cases in one round and reports paired deltas.

## Protocol

Little endian, same layout as `src/tools/netlink.cpp`. The family version is 2, and the kernel
rejects a request that does not carry it, so a helper and a module of different versions cannot read
each other's command ids.

```
KAUX_CMD_SET_BEGIN  (1)  blob: u32 total_pairs, u32 total_words, u32 crc32
KAUX_CMD_SET_PAGE   (2)  blob: u32 seq, u32 npairs, then npairs * (caller, target)
KAUX_CMD_SET_COMMIT (3)  no payload: total and CRC are checked, then applied
KAUX_CMD_PING       (4)  no payload, ACK only
KAUX_CMD_APK        (5)  blob: u32 n, then n * (st_dev, ino_lo, ino_hi, uid)
```

Family `kaux`, all commands `GENL_ADMIN_PERM`; a blob over 32 KiB is rejected before it is parsed.
A policy goes up in pages and only becomes live when the commit matches what was announced, so a
half-uploaded policy never takes effect.

| limit | value |
|---|---|
| `(caller, target)` pairs | 4096 |
| callers | 4096 |
| code dirs (`UF_APK_MAX`) | 1024 |
| dentries walked per open (`UF_DIR_DEPTH`) | 4 |
| netlink blob (`MAX_BLOB_BYTES`) | 32 KiB |
