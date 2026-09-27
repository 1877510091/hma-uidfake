# Changelog

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
