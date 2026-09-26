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
removes the rest. `post-fs-data.sh` loads it with `/data/adb/ksud insmod`, `service.sh` starts
`sync-tool`. Logs: the module's `state/sync.log`, and dmesg for the kernel (`insmod ... debug=1`
names things for 60 seconds).
