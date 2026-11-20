# Administration

## Installation and updates

Clone `https://github.com/orloxgr/clamshield-for-hestia.git` into
`/usr/local/src/clamshield-for-hestia` and run:

```sh
sudo python3 /usr/local/src/clamshield-for-hestia/tools/install.py
```

For later updates, run `sudo git -C /usr/local/src/clamshield-for-hestia pull --ff-only`
and wait for success before running the same installer again. Missing Ubuntu
packages are installed automatically; the old `--install-packages` option is
still accepted for compatibility. Existing dependencies do not trigger APT.
The installer retains configuration, credentials, database, rules/signatures,
quarantine and adapter caches. It publishes owned extension files and an
immutable application release without changing existing Hestia vendor files.

The verified platform is Ubuntu26.04 with Hestia1.10.x and APT ClamAV/YARA.
Email activation requires the existing native Exim/SpamAssassin stack. The
application does not provide a replacement control panel or mail server.

## Initial scanning data and resources

Open **Plugins → ClamShield** as administrator. In **Signature providers**, select
the official data and desired SaneSecurity/SecuriteInfo feeds. Enter the
provider credential in the password field; leaving it empty on a later save
retains the saved credential. Subscription entitlement is decided by the provider.
Updates validate candidates, authenticate feeds where supported and retain
previous data for rollback. Review the maintenance result and provider health.

In **YARA rules**, stage Core, Extended or Full and any managed/local sources.
Inspect the source/license/dependency receipts and run candidate trials before
activation. A source change builds a candidate; it does not immediately change
the active policy. Managed PHP/web sources default to review-only eligibility.
Rule data is compiled by Ubuntu's `yarac`, without building an engine.

**Resources** controls six independent owned services: website scanning, website
ClamAV, mail broker/YARA, mail ClamAV, mail SpamAssassin and maintenance.
CPU100% equals one core. Memory is a ceiling, not reserved RAM. I/O weight is
relative priority under contention. Fit the complete set of services and selected
data to the host; the larger scanning profiles need more capacity.

Use **Start website ClamAV** after valid data is active. Start verifies the loaded
generation and coverage before retaining the boot choice. An explicit Stop
survives application updates and reinstall; data activation does not silently
undo it. A saved Start is restored and verified after reinstall. Healthy code
updates verify the running scanner without restarting it.

## Websites and remediation

The administrator selects an account; each hosting user sees its own native
account generation. **Website permissions** delegates specific tenant actions.
The root bridge rechecks scope and authority for each operation, including
asynchronous work. Recreated accounts do not inherit the old account's access.

Use **Websites** for path/site/account scans, schedules and changed-file monitoring.
**Scans** shows queue, live progress and cancellation. Check coverage, not just
the absence of findings: unreadable, skipped, encrypted and limit-affected files
or an unavailable engine cannot establish a clean site. Independent YARA results
are retained when ClamAV fails, and vice versa.

**Findings** records engine/source/rule/signature, severity, file identity and
the scanning generation. Hosting heuristics, website spam matches and software
advisories require review. A match alone does not establish that an entire
site is compromised. Rule candidates should be evaluated against relevant clean
CMS/plugin/theme files and malware samples before activation.

**Quarantine** retains an original outside the public root. Restore preserves
the recorded metadata and refuses to overwrite changed destinations. A moved,
removed, suspended or recreated site/account can make historical operations
unavailable while preserving their evidence.

**WordPress** discovers installations and checks core/plugin/theme integrity
where reliable references exist. **Repairs** can prepare a nonmutating diff from
a verified reference or selected backup member. Review the preview before
applying it. Changes retain the original or its absence, recheck the published
file and support undo. Targeted cleaning handles its recognized definitions;
other infections remain reviewable or repairable from a verified clean source.
Quarantine, deletion, cleaning and replacement remain distinct actions.

**Automatic actions** supports account defaults and site policies, with explicit
eligibility, current content/generation checks, audit and interrupted-operation
recovery. Review these policies together with delegated tenant permissions.

## Email and SpamAssassin

In **Email**, domain policy provides mailbox defaults. Selecting a mailbox and
enabling a field override changes only that field. Other fields continue to
inherit later domain edits. **Use domain policy for this mailbox** removes its
overrides. Sender allowlists affect spam scoring; malware/phishing policies
remain independent. Exact-content exceptions have separate scope and permissions.

**SpamAssassin** provides its classification threshold, installed-rule catalog,
rule overrides, RBL/URIBL switches and DNS-zone restrictions. Domain spam/high-spam
thresholds act on the final score including signature weights. The catalog
shows installed base scores; the editor records applied overrides. Zone/list
access also depends on the server resolver and provider restrictions. A saved
toggle does not prove public-list access. Pyzor/Razor2/DCC are disabled by default.

The administrator explicitly enables **Mail integration** after selecting valid
data and policies. Native Hestia antivirus/antispam/reject flags and their
precedence are displayed. A saved ClamShield policy is not enforced while the
integration is disconnected. Activation validates the owned adapter and actual
scanners before attaching the supported native Exim hook.

Search quarantine and use plain-text preview before release/deletion. Release
queues the stored original for its recorded recipient and finishes only after
native delivery confirmation. Source/delivery uncertainty uses the recorded
recovery flow; do not independently resend the same original. Disabling drains
known work and retains custody. Re-enable and verify integration before release.

## Notifications, history and recovery

Review dashboard health, partial/failed scans, stale data, failed maintenance and
repeated detections. **History** retains policy, update, exception, remediation
and mail outcomes. A queued task is not an applied setting: wait for its terminal
result and refresh the relevant page.

Installer and component journals preserve interrupted operations. Repeat the
same root installer to resume an incomplete installation; use the matching UI
recovery controls for scanner/resource/mail transitions. Changed foreign files
require review. Do not remove journals or alter Hestia templates to bypass a refusal.

Required owned ClamAV coverage flags are migrated during installation/update.
Unrelated settings and file metadata are retained; running/stopped intent is
recorded before stop/write/restart. An already verified running configuration
does not require a restart. New scans remain gated if recovery is incomplete.

## Removal

```sh
sudo python3 /opt/clamshield/tools/uninstall.py
```

The uninstaller checks the exact owned inventory before stopping anything,
drains/detaches active mail and removes only recorded application integrations.
Shared packages, foreign extensions and protected private data remain.
Configuration, credentials, history, signatures/rules, custody and release code
are retained. There is no automatic purge option.

Repeat the same command after an interruption. If the active code pointer has
already been removed, use the original checkout:

```sh
sudo python3 /usr/local/src/clamshield-for-hestia/tools/uninstall.py
```

Alternatively invoke `tools/uninstall.py` inside the retained release recorded
in `/var/lib/clamshield/installation.json`. Reinstall restores the integrations
and exposes retained, correctly scoped custody and history.
