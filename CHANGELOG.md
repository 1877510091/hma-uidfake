# Changelog

## 0.2.2

- A rule applies in every user. The rules are per package, but every user has its own uids
  (uid = the uid at user 0 + user * 100000) and only the user 0 uids reached the kernel, so an app in
  a work profile queried its own user's uid and matched nothing. The helper reads
  /data/system/users and writes every pair once per user, each with the replacement its own bucket
  needs.

- The policy is published without a lock: the spinlock that was taken with interrupts off around it
  guarded a single pointer assignment, which is an atomic exchange by itself.
- The staged upload takes one, on the other hand: three commands write the same buffer and nothing
  serialised them. A second sender could only produce a policy whose CRC does not check out -- refused
  rather than half applied -- but a mutex keeps them from fighting over it.


- The presets a config applies follow the app line for line. The rules its own code computes
  (`canBeAddedIntoPreset`) were only partly copied here, so a package the app hides could be one this
  side did not count -- a uid hidden in userspace and still answered by the kernel. `sus_apps` by
  `com.termux` and the apk editor assets, `root_apps` by the viper, busybox, magisk and apatch names,
  the kernel manager libraries and the old `ACCESS_SUPERUSER` permission, `accessibility_apps` by its
  permission and never for a system app, `shizuku` by the provider it declares, `xposed` by the entry
  it carries or by being the app itself, `custom_rom` by the full overlay prefix list. A binary
  manifest keeps its strings in UTF-16, so one search looks for both forms: two checks that looked
  for bytes could never have matched on a device.
- Permissions are read from `/data/system/packages.xml` (`<perms>`) as well, and either source is
  enough.
- A regression test holds 25 cases, each naming the line of the app it stands for, and runs with the
  host tests in both rounds (plain and under ASan).

## 0.2.1

- A policy is uploaded in pages and only becomes live when its last page and its CRC check out, so a
  config with thousands of pairs is applied as one piece instead of being refused as too large.
- The netlink command ids moved with that, and the family version is 2: a helper and a module of
  different versions refuse each other instead of reading each other's commands.

## 0.2.0

- HMA and HMA-OSS each have their own config format and their own rules: the source that exists
  decides which one is in use, and each file is read by the parser written for it.
- HMA-OSS works as well as HMA: its config is read from
  /data/misc/hide_my_applist_*/config.json, and the preset cache it writes beside it says what each
  preset contains, so presets (which only the app can work out on the device) are applied too.
- The rule decision is the one HMA-OSS makes: the extra list, the opposite list, the applied
  templates, the applied presets, then whitelist mode. Rules from both tools are applied together.

## 0.1.3

- Config changes are noticed again. An event on a watched directory was taken for an install event
  and dropped, so a changed config was only picked up by the periodic pass -- and that pass is gone.

## 0.1.2

- The policy and the caller code table are sent to the kernel only when they changed, and only
  events for config.json itself count as a config change: an idle module no longer re-sends the
  same tables every few seconds.
- The sync runs on events, not on a timer. Watches that could not be created before the unlock are
  applied when it happens, and a push that did not land asks for one retry.
- The update record the module manager shows is text instead of the release page.

## 0.1.1

- The helper reads /data/system/packages.xml itself instead of asking "pm list packages -f -U"
  and walking /data/app, and installs arrive as inotify events on the first level of /data/app.
- The system flag comes from what that file records instead of MIUI's partition marker, so an
  updated preinstalled app stays a system app.

## 0.1.0

- First release. The module answers the app id (uid) of the packages HMA hides with the id of a
  real, unrelated, installed app, and the kernel refuses an id that a hidden package would be the
  only owner of.
