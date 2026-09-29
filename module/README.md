# HMA UID Fake

Makes a hidden uid look like it does not exist:

```
getpriority(PRIO_USER, uid)       -> -ESRCH
ioprio_get(IOPRIO_WHO_USER, uid)  -> -EINVAL
setpriority / ioprio_set          -> same
```

The rules come from the app a process was born from, so an isolated child or anything that called
`setuid()` cannot choose which of them apply. The repository README has the rest.

`customize.sh` picks the `ko/` entry matching `uname -r`, renames it to `ko/hma_uidfake.ko` and
removes the rest. With nothing for your kernel it leaves the closest build as
`ko/hma_uidfake.ko.try`, prints why another KMI's build will not load (vermagic, and the structures
this module reads), and points at `docs/build.md`. `post-fs-data.sh` loads the module as early as it
can and `service.sh` retries; both use the bundled `lkmloader` and log its exit code to
`state/sync.log` (`lkmloader ... debug=1` names things in dmesg for 60 seconds).
