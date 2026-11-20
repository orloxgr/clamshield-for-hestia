# Changelog

## 1.13.2

- Accept WordPress.org's multiple official checksum variants for individual files
  during integrity checks and verified recovery/replacement downloads.
- Separate file differences from components not compared in integrity reports.
  Explain unsupported single-file plugins without internal mapping terminology.
- Distinguish missing release references, rate limits and connectivity failures.

## 1.13.1

- Keep cancelled automatic website rechecks paused across signature/rule updates,
  including retained cancellation decisions and already queued automatic jobs.
- Show the paused website in Scheduled Scanner with an explicit Resume automatic
  rechecks control, governed by the account's schedule permission. Manual scans,
  calendar schedules and changed-file monitoring retain their saved behavior.

## 1.13.0

- Split personal preferences into ClamShield notifications and HestiaCP
  notifications, with independent category selections for each channel.
- Clearing Review notifications also removes matching Bell copies for the
  signed-in native account, preserving other recipients and unrelated notices.
- Attempt native notification deletion once. Failed or interrupted attempts
  stop without automatic retries and expose the error in Review and preferences.

## 1.12.3

- Rename the read-only SpamAssassin catalog action to Show installed rule scores
  and DNS restrictions to distinguish displaying data from applying settings.

## 1.12.2

- Show provider state, activation status, update timing and automatic-update
  preferences only in Updates, with a provider list and individual update actions.
- Keep credentials and database selection in Settings with separate partial Save
  requests; saving either form preserves the other form and its saved settings.
- Refresh displayed saved timing, enabled state and database counts after Save.

## 1.12.1

- Show Saving, saved and retryable error feedback next to Save provider settings,
  prevent duplicate submissions and bound confirmation waits to 30 seconds.
- Link saved database choices directly to their update action without reloading
  or starting an update, and distinguish later unsaved edits from saved settings.

## 1.12.0

- Separate website and email database selections and loaded ClamAV directories,
  with shared downloads, profile validation and atomic activation/rollback.
- Add explicit Recommended defaults for malware scanning and email protection;
  exclude PUA and High risk from presets and show published false-positive risk.
- Apply presets only on new installations or when requested in the form; updates
  retain installed selections, credentials, provider switches and update intervals.

## 1.11.8

- Explain recovery as Analyze, Review proposed changes and Apply selected changes;
  rename cleanup options as proposals and hide empty previous-analysis history.
- Default recovery to fresh latest-stable WordPress.org release discovery, with
  explicit installed-version, per-component version and vendor ZIP alternatives.
- Show installed and pinned recovery versions together, retaining unverified
  references without silent fallback or partial component version application.
- Keep analysis/preview nonmutating and apply/undo bound to retained candidates.

## 1.11.7

- Rename the main On-Demand Scan tab to On-Demand Actions, keeping existing routes.
- Add Account/Website selectors and Check/Check all to WordPress integrity, with
  native account/server targeting, pending-check reuse and live per-site progress.
- Add separate Account/Website selectors to WordPress recovery; require an
  explicit website and discard stale target choices when changing accounts.

## 1.11.6

- Keep cancelled automatic full rechecks cancelled for the same active signature/
  rule generation, including initial-monitoring fallbacks and queued duplicates.
- Preserve independent manual scans, future schedules and changed-file monitoring.
- Add confirmed Clear non-active scans for administrators with native account/
  server scope, retaining active jobs, findings, recovery and cancellation evidence.
- Add 25/50/100-row scan pagination with matching counts and page indicators.

## 1.11.5

- Restrict rule building to supported source types and rebuild active unsupported
  selections from installed source bytes during install/update, without downloads.
- Exclude removed sources from pinned-generation matches and automatic actions;
  prevent activation or rollback to rulesets containing unsupported sources.
- Mark retained findings from removed sources as historical evidence.
- Label automatic signature-update scans as Recheck after signature updates and
  clarify the independent scheduled full-recheck choice.

## 1.11.4

- Explain queued scans with their global FIFO position, elapsed wait and observed
  blocker, including automatic scans after signature updates.
- Distinguish busy scans, held scanner locks, pending activation/recovery,
  stopped timers, failed workers and delayed unclaimed jobs without changing
  service state. Show the same queue reason in WordPress integrity checks.
- Keep other accounts' active website and scan source visible only to admins.

## 1.11.3

- Combine Global Email stored messages and decisions into one recipient list,
  with subject/sender, classification, decision and actual delivery status.
- Replace account summary tables with account/search/date/status/decision filters
  and full server pagination. Collapse repeated evaluations of the same message.
- Add Clear list and selected-record controls separately from confirmed deletion
  of quarantined email. Preserve uncertain deliveries and private recovery data.

## 1.11.2

- Merge Review Activity into History, retaining task statuses, filters, paging,
  selected/all controls and automatic action history in the same tab.
- Route queue/update/configuration links and former Activity bookmarks to
  History; one refresh updates its event and task lists.

## 1.11.1

- Add page checkboxes and scoped selected/all actions throughout Review, with
  explicit Clear findings, Remove exceptions and Delete quarantine files labels.
- Keep active work visible when clearing completed maintenance and action lists.
- Delete verified private quarantine copies with a resumable journal; batch
  quarantined-email deletion through the existing recipient custody checks.
- Label the existing confirmed-recipient email release action Deliver anyway.

## 1.11.0

- Add native search/date/account/type/status controls and server pagination to
  Review lists, including full Global email records beyond the former previews.
- Add confirmed scoped history/notification clearing and AJAX Mark all read.
  Preserve operational recovery evidence and notification deduplication records.
- Reuse escaped PHP row templates and retain all existing scoped row actions
  after paging. Keep initial Review previews small and validate nested templates.

## 1.10.8

- Route Manage quarantined email to Review / Email instead of the Quarantine tab.

## 1.10.7

- Give website ClamAV service controls priority over queued maintenance and new
  scans. Ordinary scans yield at a file boundary, retaining evidence and queuing
  a complete replacement scan. Bound the wait for the worker lock.
- Show queued, waiting-for-scan, starting and verifying states separately on
  Dashboard, including signature updates that delay a queued startup.

## 1.10.6

- Add Check now to website readiness, with direct links to the required scanner,
  signature, YARA or active-work controls. Persist real checks without refreshing
  old verification times when a scan/update is busy.

## 1.10.5

- Remove the Global preview-limit banner from the panel.

## 1.10.4

- Show unavailable website ClamAV clearly on Dashboard, with an administrator-only
  Enable button that follows startup and signature verification without reloading.
  Retain the saved Start choice through the existing owned service controls.

## 1.10.3

- Refresh PHP's realpath cache before loading the current panel release after
  reinstall/update. Report unavailable panel files before rendering the header.

## 1.10.2

- Fix reinstall after completed removal when the old code directory is absent.
  Preserve retained data and validate recorded controller ownership before
  starting installation; installed-state code checks remain enforced.
- Report every remaining ClamShield directory after uninstall, its contents and
  an exact manual deletion command. Add `uninstall.py --json` for scripts.

## 1.10.1

- Remove the PHP hosting / PHP Malware Finder integration, downloader, settings
  and update actions. Keep YARA Forge, additional web rules and custom sources.

## 1.10.0

- Separate configuration into Settings, update operations into Updates, and
  retained email, maintenance, notifications and action records into Review.
  Preserve old navigation links and scoped account controls.
- Add server-wide website YARA enable/disable, timeout and file-size settings.
  Bind saved policy to scan generations, report size-limit gaps and preserve
  independent repair validation. Apply additional PHP/web sources through one
  validated settings action rather than manual Build/Candidate/Activate steps.
- Move rule profiles, provider credentials and update schedules into Settings.
  Add Support Us with donation/provider links and concise source references;
  retain upstream notices with rule data without embedding license texts in UI.

## 1.9.2

- Remove Trial scans, comparison APIs/execution, the delegated trial permission
  and its notification category. Normal website scanning and YARA rule management
  remain available.
- Cancel queued/running legacy comparison jobs on upgrade and refuse late
  comparison work without scanning files. Preserve recorded historical evidence
  and read older permission/notification preferences without the retired options.

## 1.9.1

- Add a Get a key link beside the SecuriteInfo account-key label, opening the
  provider's registration page in a new tab.

## 1.9.0

- Add automatic YARA Forge rule updates with a configurable interval, last
  attempt/success and next permitted update under Updates → YARA rules.
  Default to daily checks of the installed profile; Forge publishes weekly.
- Enforce a conservative hourly minimum across manual, automatic and legacy
  updates, including profile changes, failures and interrupted downloads.
  Retain longer GitHub Retry-After/rate-limit deadlines across restarts.
- Revalidate queued automatic updates and pause them for pending source edits
  or disabled Forge sources. Only validated rules are activated; the engine
  remains the Ubuntu APT package.

## 1.8.0

- Show per-provider update intervals, minimums, last attempt/success and next
  permitted checks. Allow longer intervals with a backend-enforced hourly floor;
  SecuriteInfo permits one download per hour, while ClamAV/SaneSecurity retain a
  conservative hourly floor. Manual and automatic checks share the same gate.
- Preserve legacy provider selections/credentials and use configured intervals
  in the scheduler. Retain longer Freshclam cooldown deadlines without exposing
  credential-bearing diagnostics, including across retries or preference changes.
- Repair corrupted database-label separators and other affected panel messages.

## 1.7.2

- Group Results, Repairs and cleaning, Exceptions, Quarantine and History under
  the Review main tab. Preserve native active-tab styling, saved selections and
  old Results/Exceptions/Quarantine/History bookmarks.

## 1.7.1

- Align Dashboard Manage and View queue links to the right edge of their cards,
  keeping engine/provider values on the left and allowing long values to wrap.

## 1.7.0

- Add personal notification-type selections, type/read-state filters and AJAX
  Mark read without reloading the panel. Keep all recorded types accessible.
- Add opt-in Also notify me on Bell through native Hestia notification commands.
  A separate owned timer delivers new selected events, respects current native
  roles/account generations and recovers interrupted appends using stable links.
- Keep Bell disabled by default, avoid resending old events, and retain original
  ClamShield notifications and independent native read states.

## 1.6.5

- Align scan target and scan search controls along their bottom edge. Add a
  visible search label and 12px spacing between automatic-action selectors and
  save buttons, including when controls wrap onto another line.

## 1.6.4

- Present History events with readable operation names, website/scope context,
  coverage counts and update-interruption explanations instead of raw JSON.
  Keep original references and evidence in closed Technical details disclosures.

## 1.6.3

- Keep individual website accordions closed by default in Scheduled Scanner.

## 1.6.2

- Organize WordPress integrity into a website table with immediate queue feedback,
  live progress, last-check times, inline reports and visible retryable errors.
- Move the optional folder path into an explained disclosure; whole-website
  discovery remains the default. Preserve previous detailed integrity reports.
- Disable repeated starts during queued/running checks and atomically reuse the
  same pending integrity job for concurrent requests with the same account
  generation, website root and target. Fresh checks remain available on completion.

## 1.6.1

- Highlight both the active main tab and its active subtab with Hestia's
  --color-text-link-hover bottom border, following the selected native theme.

## 1.6.0

- Default native administrators to Global throughout the plugin. Aggregate live
  account generations, full dashboard totals and recent website records; retain
  actual account ownership for scans, findings, quarantine, repairs and recovery.
- Add inherited server/account defaults for scan schedules, website delegation
  and automatic actions, with reset-to-inheritance controls.
- Add central email defaults and all-account domain/activity summaries. Settings
  inherit server → account → domain → mailbox, including future accounts/domains.
  Validate inherited thresholds and reject stale server/account edits.
- Default customer email modification, exception, release and deletion permissions
  to denied. Preserve explicit administrator grants, allow global and account
  delegation, and keep all engine/service/activation controls administrator-only.
- Enforce server protection activation independently of domain/mailbox overrides;
  hosting users cannot disable it with a policy or a forged API request.

## 1.5.3

- Give installation and updates priority over background scans: close admission,
  pause owned timers and stop verified ClamShield controllers before acquiring
  the application lock, with bounded waits and escalation for stuck controllers.
- Keep interrupted scan findings, coverage and history. Queue ordinary scans
  again from the beginning; retain repair/recovery work for journaled recovery
  and review instead of replaying mutations automatically.

## 1.5.2

- Restore the required SpamAssassin validation helper in the public checkout and
  release archive, fixing first-time mail protection activation failures.
- Reject incomplete checkouts before installation and report a missing validator
  explicitly. Verify the distribution and actual Ubuntu SpamAssassin parser in tests.

## 1.5.1

- Add 12px spacing below cards and between controls, disclosures and content
  throughout the panel. Keep Hestia's native control appearance and use existing
  flex gaps without adding duplicate button margins inside control rows.

## 1.5.0

- Add WordPress recovery with queued Analyze → Review → Apply/Undo batches,
  cancellation, progress and scoped retained plans. Use verified release
  replacements and existing journaled quarantine/repair mechanisms.
- Add independent uploads policies for PHP/other server scripts and all
  JavaScript. Policy matches are labeled separately from malware detections;
  removed content is quarantined outside the public root.
- Support explicit target versions and account-supplied premium/vendor ZIPs,
  including private account-home paths. Retain package provenance and refuse
  ambiguous headers, invalid archives and flagged replacements.
- Inspect local native-account WordPress databases without executing site PHP;
  require exact reviewed edits, native database-user ownership, stable primary
  keys/schema, InnoDB row/content guards and post-write verification. Preserve
  serialized string lengths and valid JSON; retain exact originals for undo.
- Add review of configuration directives, recent file changes and scoped open
  process files. Keep coverage gaps visible and bound report/database resources.

## 1.4.0

- Add one Enable mail protection action for the server: prepare missing signature
  and YARA data, verify/start the owned native integration, then enable inherited
  mail policies. Existing domain/mailbox overrides and native filter precedence
  are preserved; future domains inherit the same default.
- Display queued preparation and verification automatically. Enabled requires a
  verified connection, an active lifecycle and enabled inherited defaults.
- Put technical integration/adapter controls, domain settings, quarantine,
  history and recovery inside a closed Advanced section. Disable uses the
  existing safe drain lifecycle and retains policies and quarantined email.

## 1.3.0

- Replace per-website scan inputs with account/website dropdowns, an all-websites
  account option and adjacent Scan/Scan all actions with explicit scope labels.
- Put optional relative-path scanning behind a disclosure for a single website;
  account/server scans never send a leftover single-site path.
- Load website choices through native account authorization and keep suspended
  websites unavailable. Failed account discovery cannot reuse earlier targets.
- Link queued scans to the correct account or server progress view; retain website
  root information in an expandable section and clarify the viewing account.

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
