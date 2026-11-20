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

The root installer shows ten installation phases, timestamped commands and a
readable success/failure summary. While a step or operation lock is waiting,
it reports current activity every ten seconds without imposing a work deadline.
Use `--json` for a single final JSON document on stdout; progress/diagnostics
stay on stderr. Native child diagnostics and the last stage are retained on
failure. Console output does not assert that scanning data or email protection
is active merely because application installation succeeded: follow the next
setup steps in the summary and check readiness in Hestia.

## Panel structure

The persistent main menu contains Dashboard, Email Shield, On-demand Scan,
Scheduled Scanner, Review, Updates and Settings. **Review** groups Results,
Repairs and cleaning, Exceptions, Quarantine and History. Existing bookmarks
and saved selections continue to select their matching view.
Secondary links retain access to all website and server tools. Dashboard Manage
links select the matching secondary view. Tenants retain the same primary menu;
server-wide forms remain administrator-only and backend authorization is unchanged.

Native administrators open **Global** by default in **Viewing account**. Dashboard
totals and website lists cover all current native accounts; recent results,
quarantine, integrity/recovery plans and history retain their actual account
ownership. Mutations reauthorize that account in the root backend. Select an
account to filter all views or manage its overrides. Hosting users never receive
the Global option or cross-account access. Same-name replacement accounts do not
inherit the previous generation's records or explicit grants.

Global lists are bounded recent previews (up to 500 website records per list and
100 mail records per list); dashboard totals are independent of preview lengths.
Scans has its own server-wide search and pagination. Account views provide their
scoped history; account-specific history-retention controls appear there, while
server history controls remain available globally.

The dashboard distinguishes rule build times and successful provider downloads
from active scanner readiness. SpamAssassin displays service, mail integration,
process verification, score and configured DNS checks, plus pending tasks shown
in the recent maintenance list. These are runtime/configuration facts; no
automatic refinement or external reputation service is implied.

## Initial scanning data and resources

Open **Plugins → ClamShield** as administrator. In **Updates → Signature providers**, select
the official data and desired SaneSecurity/SecuriteInfo feeds. Enter the
provider credential in the password field; leaving it empty on a later save
retains the saved credential. Subscription entitlement is decided by the provider.
Updates validate candidates, authenticate feeds where supported and retain
previous data for rollback. Review the maintenance result and provider health.

In **Updates → YARA rules**, choose Core, Extended or Full in the dropdown and
click **Install rules** or **Update rules**. The same asynchronous task downloads,
validates and activates the selected rules. Progress refreshes automatically,
including after reopening the view. Success is shown only after activation;
a failed download, validation or source-revision check does not activate the
candidate. Existing active data remains available after failed validation.

**Advanced rule tools** retains staging, per-source/per-rule selections, receipts,
comparison trials, manual candidate activation and rollback. Those controls are
optional for normal Forge installation. Managed PHP/web hosting sources retain
their review-only defaults. Engine binaries still come from Ubuntu APT.
Rule data is compiled by Ubuntu's `yarac`, without building an engine.

**Settings → Resources** controls six independent owned services: website scanning, website
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

The administrator normally stays in **Global**; each hosting user sees its own
native account generation. **Settings → Website permissions** sets global
delegation defaults or explicit permissions for the selected account.
The root bridge rechecks scope and authority for each operation, including
asynchronous work. Recreated accounts do not inherit the old account's access.

In **On-demand Scan → Websites**, choose **Scan account** and then a website,
or **All websites in this account**, and press **Scan**. Administrators also have
**Scan all**, which queues active websites across all accounts on the server.
For a single site, **Scan a folder or file (optional)** accepts a path relative
to its document root; blank means the whole website. Account/server scans ignore
that path. Choosing an account/site alone does not start work. **View progress**
opens the selected account or the server-wide queue as appropriate.
**Scheduled Scanner** manages global scan defaults, account defaults and website
overrides for schedules and changed-file monitoring. Defaults apply to new sites
without copying a policy into every account. **Use account scan defaults** removes
a website override; **Use global scan defaults** removes an account override.
**Settings → Automatic actions** follows the same server/account/site hierarchy.
Administrator-configured automatic protection retains administrator authority
when user controls are restricted. Policy changes still fence queued actions.

**On-demand Scan → WordPress integrity** shows a website table with its last
check, current status, coverage counters and actions. **Discover and verify**
searches the whole website, including nested installations. **Folder (optional)**
contains the relative folder path and its explanation.
The row immediately shows submission, queue and running states; active checks
refresh while the page is visible and resume after reopening. Repeated clicks
or concurrent identical requests reuse the pending check. **Check again** becomes
available once it finishes. **View report** loads differences and unverified
entries inline; **Previous integrity reports** retains the detailed component
history. Failed or partial coverage remains explicit rather than implying a
clean website. File integrity checking does not modify site files.
**On-demand Scan → Scan progress** shows queue, live progress and cancellation. Check coverage, not just
the absence of findings: unreadable, skipped, encrypted and limit-affected files
or an unavailable engine cannot establish a clean site. Independent YARA results
are retained when ClamAV fails, and vice versa.

**Review → Results** records engine/source/rule/signature, severity, file identity and
the scanning generation. Hosting heuristics, website spam matches and software
advisories require review. A match alone does not establish that an entire
site is compromised. Rule candidates should be evaluated against relevant clean
CMS/plugin/theme files and malware samples before activation.

**Review → Quarantine** retains an original outside the public root. Restore preserves
the recorded metadata and refuses to overwrite changed destinations. A moved,
removed, suspended or recreated site/account can make historical operations
unavailable while preserving their evidence.

**On-demand Scan → WordPress integrity** discovers installations and checks core/plugin/theme integrity
where reliable references exist. **Review → Repairs and cleaning** can prepare a nonmutating diff from
a verified reference or selected backup member. Review the preview before
applying it. Changes retain the original or its absence, recheck the published
file and support undo. Targeted cleaning handles its recognized definitions;
other infections remain reviewable or repairable from a verified clean source.
Quarantine, deletion, cleaning and replacement remain distinct actions.

### WordPress recovery

**On-demand Scan → WordPress recovery** provides a nonmutating analysis followed
by a reviewed batch. Select a website and optional installation folder, choose
the uploads policies and press **Analyze WordPress**. Default PHP/server-script
cleanup and optional all-JavaScript cleanup are separate controls. Their matches
are recorded as selected cleanup policy, not proof of malware. Ordinary uploads
are retained; legitimate deny-only `.htaccess` files are not removed simply
because of their filename. Configuration directives and scanner findings have
separate review evidence.

Analysis discovers core/plugins/themes and compares installed files with
trusted references. Modified/missing files receive validated replacement
candidates; additional files in known component directories can be selected for
quarantine. Unrecognized root code and configuration changes remain reviewable.
Unavailable references, unsafe files, limits and scanner failures remain visible
as coverage gaps. Replacement preparation requires the ClamAV and YARA engines.

Without an explicit version selection, replacement uses the installed version.
**Versions and trusted vendor ZIPs** accepts a component's website-relative path,
an optional target version, and a premium/custom ZIP. Prefer a private account
path such as `~/tmp/example.zip`, where `~` means the selected hosting account's
home, not the administrator's. Other paths are website-relative. ZIP roots,
release headers, paths, expanded sizes and candidate content are checked.
Vendor authenticity remains the operator's responsibility and is stated in the
receipt. Core always uses an official release. Invalid/ambiguous component
metadata remains unverified. A typo in a component mapping is reported.

Review the selected actions and exact file/database changes before **Apply
reviewed recovery**. Changing the selection requires another preview. Pause
traffic, cron, deployment and other writers during recovery; this feature does
not stop shared PHP pools or unrelated account processes. The batch checks all
selected originals before applying and rechecks each actual mutation. It uses
per-file journals rather than an atomic switch of an entire application. A
concurrent change, cancellation or failure can therefore leave completed actions
retained alongside unapplied actions. **Resume reviewed recovery** inspects
recorded state; **Undo recovery** restores only unchanged destinations and does
not overwrite subsequent work. Some interrupted repairs require fresh analysis
after the existing recovery mechanism restores the original.

File originals and database before/after values are private retained evidence.
They are not removed by ordinary scan-history expiry or uninstall. Undo is
content guarded; do not manually remove private recovery artifacts while a plan
is needed. Successful file operations enqueue a full malware scan and WordPress
integrity recheck. Applied is not a declaration that every file/database is clean.
Updates may still require trusted application/database migration, functional
testing, credential/session rotation and remediation of the original entry point.

Database inspection uses Ubuntu `python3-pymysql`, installed by the root
installer. It parses literal `wp-config.php` settings without loading PHP and
requires the database and database user from the selected native Hestia account.
Computed configuration, external hosts or unavailable credentials are reported
as unavailable, never clean. Tables use the installation's prefix. String/script
matches and administrator capabilities are review candidates, not automatic
malware verdicts. Choose an exact find/replacement for each selected database
value; there is no blanket SQL search-and-delete.

Changes require a stable primary key/table definition and InnoDB. Tables with
triggers require manual review; the native user must have permission to inspect
triggers so that hidden database code is not treated as absent. Exact original
bytes, native configuration and row locks guard updates; trigger rewrites or
changed content are refused/rolled back. PHP serialized string lengths are
recalculated without instantiating PHP objects; serialized objects/references
require manual review. Valid JSON structure is preserved. Full row originals are
retained for exact undo; this does not replace a complete database backup.

Investigation shows up to 100 recent files and a bounded open-file/cwd process
snapshot scoped to the website. Timestamps and open descriptors are clues, not
proof of malicious writes. No processes are killed and no blanket chmod is
performed. Analysis is bounded to 200,000 filesystem entries, 50 installations,
500 components, 10,000 recovery actions, and bounded paginated report sizes.
Database inspection bounds each value to 1 MiB, candidate evidence to 16 MiB,
table count to 500, row/column checks to 100,000 and time to 120 seconds per
installation. Hitting a limit remains incomplete coverage.

**Settings → Automatic actions** supports account defaults and site policies, with explicit
eligibility, current content/generation checks, audit and interrupted-operation
recovery. Review these policies together with delegated tenant permissions.

## Email and SpamAssassin

In **Email Shield → Email policies**, an administrator clicks **Enable mail
protection** for the entire server, including accounts other than the viewing
account. The queued task prepares missing signature data and, when YARA is
enabled without installed rules, installs the Core profile. Existing data and
profile choices are retained. The owned mail lifecycle builds/verifies its
adapter, prepares initial SpamAssassin settings and probes the actual scanners
and connection. Only then are inherited server policies enabled. Progress is
automatic; a failed check remains visible and retryable instead of reporting
Enabled. No manual adapter preparation or refresh is needed for normal activation.

Unconfigured domains, including future domains, inherit enabled protection.
Explicit handling overrides, sender lists and exceptions remain intact.
Server activation takes precedence over old domain/mailbox activation toggles;
customers cannot disable the server protection. Native Hestia antivirus/antispam/
rejection flags retain their precedence. The toggle becomes **Disable mail
protection** only with a verified active connection and enabled server defaults.
Disabling drains/detaches the connection and retains policies and quarantined
email. Tenant users retain their delegated account controls; the global toggle
requires native administrator authority.

With **Global** selected, **Server-wide email defaults** controls handling actions,
spam thresholds, sender lists and default customer permissions for every existing
and future account. The central activity view shows all native accounts, mail
domain counts, stored recipient records and recent decisions, even when the
administrator's own account has no mail domains. **Manage account** opens that
account for message previews, release, recovery and complete decision history.

Selecting an account exposes **Account email defaults**, which overrides the
server defaults for all its current/future domains. The inheritance order is
server → account → domain → mailbox. Saving server/account defaults validates
existing live descendants' score thresholds and checks the loaded revision;
conflicting or stale changes do not silently replace newer settings.

Customer policy editing, exact-content exceptions, release and deletion are
**denied by default** until an administrator grants them globally or per account.
Existing explicit grants are retained on update. **Use global email defaults and
permissions** removes account defaults/grants; individual domain/mailbox overrides
remain. Services, engine installation and server activation are always restricted
to native administrators, regardless of customer policy permissions.

**Advanced email settings and account activity** is closed initially and contains
integration/adapter diagnostics, domain settings, quarantine, history and
recovery tools. Select an account above to use its account-specific controls.
Domains inherit account/server defaults; mailboxes inherit their domain. Selecting
a field override changes only that field; other fields follow later parent edits.
**Use domain policy for this mailbox** removes its
overrides. Sender allowlists affect spam scoring; malware/phishing policies
remain independent. Exact-content exceptions have separate scope and permissions.

**Email Shield → SpamAssassin** provides its classification threshold, installed-rule catalog,
rule overrides, RBL/URIBL switches and DNS-zone restrictions. Domain spam/high-spam
thresholds act on the final score including signature weights. The catalog
shows installed base scores; the editor records applied overrides. Zone/list
access also depends on the server resolver and provider restrictions. A saved
toggle does not prove public-list access. Pyzor/Razor2/DCC are disabled by default.

A saved ClamShield policy is not enforced while the integration is disconnected.
The advanced integration controls remain available for maintenance and diagnosis.
Foreign hook/library changes still require review; automatic activation does not
overwrite unowned configuration to force a successful result.

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

History shows readable event names, website/scope information and coverage
counts. **Technical details** starts closed and contains the original event,
actor, references and recorded fields for troubleshooting. The presentation does
not change stored audit evidence or turn partial scans into successful checks.

**Settings → Notifications** has personal preferences for the signed-in native
account, even while an administrator views a customer's account. Select the
notification types you want to see. For detections only, keep **Website malware
detections** checked and clear the other categories. This includes repeated
detections; WordPress integrity differences are a separate category. **Type**
and **Status** filter the list without a request. **All recorded types** still
shows retained events excluded from your selections. **Mark read** updates its
own row without reloading the panel and preserves the row on failure.

**Also notify me on Bell** is off by default. It sends future selected events to
your native Hestia Bell using the supported `v-add-user-notification` command;
no vendor panel file is patched. An opted-in native administrator receives
current-generation events across the server; tenants receive only their own.
Changing selections or enabling Bell starts from that change, avoiding an old
notification flood. ClamShield and Hestia keep independent read states.
The owned `clamshield-notifications.timer` normally checks every 15 seconds.
Its separate service uses the root runtime gate and stops for installation or
removal. Failed/uncertain sends wait at least 60 seconds, check the native list
for the same stable link before retrying, and expose a delivery warning in the
personal preferences. No engine or mail services are exposed to tenant controls.

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
