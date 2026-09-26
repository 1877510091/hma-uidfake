# HMA UID Fake

KernelSU module that makes the uid of an app hidden by HMA answer as if it did not exist:

```
getpriority(PRIO_USER, uid)       -> -ESRCH
ioprio_get(IOPRIO_WHO_USER, uid)  -> -EINVAL
setpriority / ioprio_set          -> same
```

Which rules apply follows the app a process was born from, not the uid it holds when it calls, so an
isolated child or anything that called `setuid()` answers the same way.

Install the release zip with KernelSU. Design and build: [docs](docs/).

GPL-2.0, see [LICENSE](LICENSE).
