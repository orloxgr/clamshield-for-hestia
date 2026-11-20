# Changelog

## 1.2.4

- Add 12px bottom spacing below the dashboard panel grid.

## 1.2.3

- Give every ClamShield card 12px padding on all four sides.

## 1.2.2

- Match the Varnish and other addon entries in the shared Plugins menu by using
  plain list/link elements, without notification classes that change font weight.

## 1.2.1

- Make expandable sections throughout the panel recognizable as native Hestia
  buttons, with a caret indicating their closed/open state. Retain native
  details/summary keyboard behavior and theme appearance, including nested tools.

## 1.2.0

- Make Install/Update rules a single queued download, validation and activation
  operation. Retain the previous active rules on validation failure.
- Automatically display queue/download/check/activation progress and resume it
  when reopening the rules view. Never report a staged candidate as installed.
- Put build, manual activation, task history, trials and source/rule controls in
  a collapsed advanced section; the normal view needs only a profile and Install.
- Bind install status and progress to the administrator's native account identity;
  refresh active-rule indicators without requiring a manual page refresh.

## 1.1.1

- Present dashboard account totals in one activity panel with four rows,
  native icons and right-aligned values, retaining navigation links and live
  scan-count updates. Keep Hestia theme colors and control appearance.

## 1.1.0

- Organize the panel around ten persistent primary sections, with focused
  secondary navigation and direct Manage links using native Hestia controls.
- Open a dashboard with live engine/rule metadata, recorded provider download
  times, scanner readiness, account counts and actual SpamAssassin state.
- Separate website schedules/monitoring from on-demand scanning; retain scan
  progress, WordPress integrity, findings, repair and automatic-action tools.
- Replace three Forge stage buttons with a profile dropdown and Install/Update
  action; place validated candidates, activation and task status together.
- Show pending recent SpamAssassin configuration tasks and their outcomes.
- Preserve tenant authorization, lazy-loaded mail/history controls and scan
  polling when navigating nested views. No Hestia vendor/theme files change.

## 1.0.2

- Show timestamped installer stages, native command activity and ten-second
  heartbeats during slow work or lock waits, without adding operation deadlines.
- Default to a readable, optionally colored final summary with actual PHP/timer
  counts, scanner startup choice, next setup steps and elapsed time.
- Keep successful native output out of the summary while preserving captured
  failure diagnostics, traceback, last stage and nonzero exit status.
- Add `--json` for automation, keeping a single result on stdout and progress
  on stderr. Existing panel/worker/maintenance output is unchanged.
- Keep migration forks free of reporting threads and preserve caller-owned alarms.

## 1.0.1

- Publish the complete application with clone/pull followed by the same installer
  command for new installations and updates.
- Automatically install missing Ubuntu dependencies. Skip APT when all required
  packages are installed, preserving existing engine packages on ordinary updates.
- Retain the existing `--install-packages` option for compatibility.
- Add package-bootstrap regression tests and public operator documentation.

## 1.0.0

- Website and email protection with Ubuntu ClamAV/YARA and independent policies.
- Official, SecuriteInfo, SaneSecurity and local signature management; staged
  validation, provenance and rollback.
- YARA Forge profiles, managed hosting sources, local rules and candidate trials.
- Scheduling, changed-file monitoring, full rechecks, live progress and cancellation.
- Quarantine/restore, targeted cleanup, verified reference/backup repair and undo.
- WordPress integrity, tenant delegation, notifications and retained history.
- Native Exim integration, mail quarantine/release, domain/mailbox inheritance
  and SpamAssassin score/RBL/URIBL/zone controls.
- Additive installation/update/removal and durable interruption recovery.
- Correct incomplete encrypted/limited-file coverage and full account dashboard totals.
- Verify Hestia1.10.7→1.10.8 upgrade paths without patching vendor panel files.
