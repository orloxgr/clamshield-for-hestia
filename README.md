# ClamShield for HestiaCP

Website malware scanning and email protection inside HestiaCP, using Ubuntu's
ClamAV and YARA packages. Version **1.3.0** · [GPL-2.0](LICENSE).

ClamShield adds its own application, services and supported integrations.
Existing Hestia panel files, scripts, templates and package units are not patched.
Administrator and hosting-user access use native Hestia authentication and its
own theme, with account isolation enforced by the privileged backend.

## Quick start

Requires **Ubuntu 26.04 with HestiaCP 1.10.x already installed**, Python3.12+
and Git. Run these commands over SSH as an administrator. Ubuntu APT supplies
the engines and dependencies; there is no separately compiled or bundled YARA.

1. **Get the code. Choose one command:**

   For a **new installation**, clone the repository:

   ```sh
   sudo git clone https://github.com/orloxgr/clamshield-for-hestia.git /usr/local/src/clamshield-for-hestia
   ```

   To **update an existing checkout**, pull instead:

   ```sh
   sudo git -C /usr/local/src/clamshield-for-hestia pull --ff-only
   ```

   Wait for Git to finish successfully before continuing.

2. **Install or apply the update.**

   Use the same command for a **new installation** and an **update**:

   ```sh
   sudo python3 /usr/local/src/clamshield-for-hestia/tools/install.py
   ```

   Missing Ubuntu dependencies are installed automatically. When they are
   already installed, this step does not run APT or request engine upgrades.
   Application updates retain existing resource limits, provider credentials,
   policies, schedules, history, quarantine and the website engine's Start/Stop
   choice. Pulling the code alone does not apply the update; run the installer too.

3. **Log into Hestia and open Plugins → ClamShield.**

   As administrator, select and update your **Updates → Signature providers**, install the required
   **Updates → YARA rules** with one click, then choose **Start website ClamAV** in
   **Settings → Resources**. Confirm readiness in the dashboard before starting a scan.
   Set the independent service limits to fit the server and selected data.

4. **Configure protection for websites and email.**

   Choose site schedules and changed-file monitoring under **Scheduled Scanner**.
   Review **Settings → Automatic actions** and **Settings → Website permissions** for tenant access.
   For native Exim/SpamAssassin email, configure scores and domain/mailbox
   policies, then explicitly enable **Mail integration** under **Email Shield → Email policies**.
   Saved mail policies are enforced only while that integration is connected.

This repository is public; cloning does not require GitHub credentials.
See the [administration guide](docs/administration.md) for daily operation,
resources, recovery, update and removal.

## Panel navigation

Dashboard | Email Shield | On-demand Scan | Scheduled Scanner | Results |
Exceptions | Quarantine | Updates | History | Settings

The main menu stays visible; secondary links organize each section. Dashboard
Manage links open the matching controls. Dashboard engine versions, rule counts,
build times and provider download times come from recorded server state, not
example values. Provider downloads and configured DNS checks do not by themselves
establish active scanning coverage or access to a public blocklist.

## Website protection

- Discover Hestia accounts, domains and actual document roots, including custom
  roots and account/site lifecycle changes.
- Scan a file, folder, website, account or all accounts; schedule scans, monitor
  new/changed files and recheck existing files after scanning-data updates.
- Follow live progress, cancel jobs and review checked/skipped/error coverage.
  Encryption, limits, unreadable files and unavailable engines remain incomplete.
- Review engine, rule/signature, source, severity, scanning generation and
  remediation status for each finding.
- Quarantine outside the web root; restore original metadata; preview and apply
  targeted cleaning or verified reference/backup repairs, recheck and undo.
- Discover WordPress and check core/plugin/theme integrity where trusted
  references are available, including changed, added and missing files.

## Signatures and YARA

- Official ClamAV data, SecuriteInfo free/paid subscription profiles,
  selected SaneSecurity feeds and administrator local signatures.
- Provider health, staged validation, authenticated feed verification where
  available, retained provenance and previous-data rollback.
- YARA Forge Core, Extended and Full; managed PHP/web hosting sources and local
  or additional sources, with license/version/dependency receipts.
- Candidate trials, performance reports, duplicate handling, source/rule
  toggles and advanced activation/rollback controls.

SecuriteInfo requires the administrator's own provider account/key and its
entitlements. Paid data and credentials are not distributed with this project.
Rules are checked with the installed Ubuntu YARA. Managed hosting heuristics
start in review mode: legitimate code can match. Evaluate candidates on suitable
clean and known-malicious samples before changing automatic-action eligibility.

## Email and antispam

- Separate malware, phishing and spam actions: SMTP rejection, scoring, Junk,
  tagging or quarantine according to policy.
- Per-domain defaults and selected mailbox overrides, scoped sender allow/block
  lists and exact-content false-positive exceptions.
- Searchable quarantine, controlled plain-text preview, queued release with
  native delivery confirmation and separately controlled deletion/retention.
- SpamAssassin threshold, installed rule scores, overrides, RBL/URIBL controls
  and DNS-zone restrictions; native mail flags and precedence remain visible.
- Account-scoped history, notifications, source acceptance and delivery recovery.

Email integration uses the installed native Exim and SpamAssassin stack. Only
the small ClamShield Exim adapter is compiled against the matching native SDK;
the engines remain Ubuntu packages. Pyzor/Razor2/DCC are disabled by default.

## Update

Run the commands separately. Download the current source first:

```sh
sudo git -C /usr/local/src/clamshield-for-hestia pull --ff-only
```

After Git finishes successfully, apply it:

```sh
sudo python3 /usr/local/src/clamshield-for-hestia/tools/install.py
```

Updates preserve saved settings and private data. An interrupted installation
can be resumed with the same installer. ClamShield publishes an owned immutable
release and maintains its own recovery state; it does not reapply vendor patches.
The additive integration was verified through native Hestia1.10.7→1.10.8 upgrades
in web/cache and active-mail configurations, including Varnish/Dragonfly coexistence.

### Installer output

The default output shows timestamped stages, the current native command, and a
readable final summary with version, operation, checked PHP templates, enabled
timers, scanner setup/retained choice, next steps and elapsed time. Slow steps
report their current activity every ten seconds, including waits for an existing
ClamShield operation. Reporting does not impose an execution deadline.

Successful native command output is kept out of the console summary. A failure
prints its captured diagnostics, traceback and last stage and returns a nonzero
exit status. Terminal success/failure headings use color when supported; redirected
logs and `NO_COLOR` stay plain. For scripts that need a JSON result:

```sh
sudo python3 /usr/local/src/clamshield-for-hestia/tools/install.py --json
```

JSON mode writes one final document to stdout; progress and diagnostics remain
on stderr. The normal panel, worker and maintenance JSON interfaces are unchanged.

## Removal

```sh
sudo python3 /opt/clamshield/tools/uninstall.py
```

Removal retains configuration, credentials, history, scanning data and private
custody for reinstall/recovery. It does not remove shared Ubuntu packages or
purge retained data. See [removal and interruption recovery](docs/administration.md#removal).

## Development

Run the Python tests on Linux with the Ubuntu engine/parser dependencies and
PHP CLI available. Root is needed for the kernel credential/descriptor tests:

```sh
sudo env PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Run the browser DOM tests:

```sh
cd tests/ui
npm ci
npm test
```

Build a source archive with `python3 tools/package.py`. The build verifies every
archived source byte and writes an adjacent manifest and SHA256 checksum. Provider data is
obtained on the server through its own validated update flow.

See the [changelog](CHANGELOG.md) for release changes.
