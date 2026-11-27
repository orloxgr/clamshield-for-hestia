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

The persistent main menu contains Dashboard, Email Shield, On-Demand Actions,
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
Scans has its own server-wide search, active-job filter and 25/50/100-row
pagination with matching totals and page numbers. Administrators can Clear
non-active scans after confirming the count for the selected account or server.
This clears completed, partial, failed and cancelled rows from that list, keeping
queued/running jobs and original findings, recovery and cancellation evidence.
Newly arriving records are excluded from the confirmed selection.
Account views provide their
scoped history; account-specific history-retention controls appear there, while
server history controls remain available globally.

The dashboard distinguishes rule build times and successful provider downloads
from active scanner readiness. SpamAssassin displays service, mail integration,
process verification, score and configured DNS checks, plus pending tasks shown
in the recent maintenance list. These are runtime/configuration facts; no
automatic refinement or external reputation service is implied.

## Initial scanning data and resources

Open **Plugins → ClamShield** as administrator. In **Settings → Signature providers**, select
the official data and desired SaneSecurity/SecuriteInfo feeds. Enter the
provider credential in the password field; leaving it empty on a later save
retains the saved credential. Subscription entitlement is decided by the provider.
Updates validate candidates, authenticate feeds where supported and retain
previous data for rollback. Review the maintenance result and provider health.

**Updates → Signature providers → Update schedule** lists each provider's interval in minutes, minimum, last
attempt, last success and next permitted check, with timestamps in UTC. The
default is 60 minutes; choose any whole-minute interval from 60 to 525600 and
choose **Save update schedule**. The Automatic provider updates switch controls background
checks. Manual updates use the same interval gate; cached validation/activation
does not download anything. Due now means eligible for the background worker,
not that a download has already completed. Disabled providers are labelled.

[SecuriteInfo explicitly permits one download per hour for its signatures](https://www.securiteinfo.com/clamav-antivirus/faq-clamav-unofficial-signatures_en.shtml).
ClamShield also enforces a conservative hourly floor for official ClamAV and
SaneSecurity. [ClamAV's guidance](https://docs.clamav.net/faq/faq-troubleshoot.html)
discusses DNS-based checks and CDN limits; [SaneSecurity's guidance](https://sanesecurity.com/usage/linux-scripts/)
prohibits excessive mirror requests without publishing a single numeric minimum.
The SaneSecurity floor is ClamShield's conservative policy, not a claimed
provider-published hourly restriction. Existing settings acquire the defaults
without changing selected databases, credentials, enablement or automatic mode.

When Freshclam reports a longer cooldown, ClamShield retains its parsed UTC
deadline and displays it. Increasing/decreasing an interval or restarting workers
cannot shorten that cooldown. Credential-bearing Freshclam output stays private;
only the validated deadline and safe error text are kept in public status.

In **Settings → YARA**, save the desired Core, Extended or Full profile. In
**Updates → YARA rules**, click **Install rules** or **Update rules**. The same asynchronous task downloads,
validates and activates the selected rules. Progress refreshes automatically,
including after reopening the view. Success is shown only after activation;
a failed download, validation or source-revision check does not activate the
candidate. Existing active data remains available after failed validation.

**Settings → YARA → Rule update preferences** controls the profile and automatic
interval. **Updates → YARA rules** shows last attempt/success and next permitted
update in UTC. Checks default to every 1440 minutes
(24 hours) and automatically validate and activate the selected Forge profile.
Install a profile once before background updates can start. Save any whole-minute
interval from 60 to 525600; unchecking the automatic option leaves manual updates
available when due. These are server-wide administrator settings in every account
view; hosting users cannot change them.

[YARA Forge publishes weekly releases](https://github.com/YARAHQ/yara-forge#readme).
Our hourly minimum is a conservative polling floor, not a claimed Forge quota.
Manual and automatic updates, profile changes and the legacy updater share one
durable gate. Failed or interrupted attempts also consume the interval. Longer
[GitHub Retry-After/rate-limit deadlines](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api)
take precedence, including after a restart or interval change. Success is recorded
after the entire requested operation finishes: activation for the normal flow,
validated staging for an advanced Forge update.

Automatic updates use the saved profile, skip disabled Forge sources and pause
while source/rule edits differ from the active configuration.
Queued work rechecks settings and native administrator authority before running.
Changing a profile preference applies on the next update. Additional sources
are selected in Settings and validated before application.

**Settings → YARA** has a real administrator-only website scanning toggle,
per-file timeout (1–3600 seconds) and YARA file-size ceiling (1–50 MiB, within the
existing website snapshot ceiling). Saved choices are applied by maintenance
between website jobs and included in the scan generation. Disabled YARA is
omitted from manual/scheduled/changed-file website scans; enabled YARA errors or
size-limit gaps make coverage incomplete. File repair/recovery retain their
independent validation contract, and email YARA remains separate.

**Additional website rules** selects the extra web
hosting heuristics. Save downloads missing sources, validates with Ubuntu YARA
and applies the result in one task. New sources default to manual review;
automatic-policy eligibility requires an explicit choice plus the website action
policy. Failed validation preserves active rules and restores the saved source
selection when no concurrent editor has replaced it. Repeated unchanged saves
reuse the active selection. Custom source/rule saves also validate and apply;
manual Build/Candidate/Activate controls are no longer part of the interface.
Updates → YARA rules also offers update actions for enabled web and custom remote sources;
these validate and apply in one task, while preserving manual-review choices.

The engine still comes from Ubuntu APT; `yarac` compiles rule data only.

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

In **On-Demand Actions → Websites**, choose **Scan account** and then a website,
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

**On-Demand Actions → WordPress** combines installed-version integrity checking
and recovery. Select Account and Website, then **Analyze website**. Analysis reads
files without changing the website. It compares core/plugins/themes with their
installed releases, performs scanner and selected cleanup-policy checks, and
shows coverage gaps separately. Prior analyses remain available in the same view.
The standalone Integrity tab is removed; former links open the unified workflow.
**On-Demand Actions → Scan progress** shows queue, live progress and cancellation. Check coverage, not just
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

Integrity reports separate modified, missing and additional files from components
that were **Not compared**. Inspected entries include discovered directories and
files; checked files count actual comparisons. A missing reference is a coverage
gap, not a malware detection or proof of altered code. Single-file plugins do not
yet support automatic official comparison and need an original plugin copy.
Custom components/child themes may need the publisher's original package or your
own trusted baseline. Missing WordPress.org releases are distinguished from
connection failures and rate limits when a fresh check retrieves the reference.
Official checksum lists can contain several valid variants; each listed digest
is accepted, while unlisted content remains a difference. This also applies to
independently verified recovery downloads. Old reports retain their recorded
coverage; run a fresh check to reassess previously unreadable references.

**On-Demand Actions → WordPress** discovers installations and checks core/plugin/theme integrity
where reliable references exist. **Review → Repairs and cleaning** can prepare a nonmutating diff from
a verified reference or selected backup member. Review the preview before
applying it. Changes retain the original or its absence, recheck the published
file and support undo. Targeted cleaning handles its recognized definitions;
other infections remain reviewable or repairable from a verified clean source.
Quarantine, deletion, cleaning and replacement remain distinct actions.

### WordPress recovery

**On-Demand Actions → WordPress** uses separate Account and Website
selectors. Choose an account and a specific active website before analysis;
there is no server-wide repair action. Loading/changing accounts clears stale
website and folder choices. It provides a nonmutating analysis followed
by a reviewed batch. Select a website and optional installation folder, choose
the cleanup actions to propose and press **Analyze website**. Analysis and review
do not change website files or its database; only **Apply selected changes**
executes the reviewed mutations. Default PHP/server-script
cleanup and optional all-JavaScript cleanup are separate controls. Their matches
are recorded as selected cleanup policy, not proof of malware. The cleanup policy
matches script extensions, not PHP-looking bytes inside images or other media.
An `index.php` containing only the standard "Silence is golden" placeholder is
excluded from cleanup suggestions. All these files still receive ClamAV/YARA
scans. Retained uploads-policy rows point back to WordPress analysis, rather than
suggesting replacement from a backup. Earlier media/placeholder cleanup proposals
are rejected during preview/apply preflight; run a new analysis to replace them.
Ordinary uploads are retained; legitimate deny-only `.htaccess` files are not removed simply
because of their filename. Configuration directives and scanner findings have
separate review evidence.

Analysis discovers core/plugins/themes and compares installed files with
trusted references. Modified/missing files receive validated replacement
candidates; additional files in known component directories can be selected for
quarantine. Unrecognized root code and configuration changes remain reviewable.
Unavailable references, unsafe files, limits and scanner failures remain visible
as coverage gaps. Replacement preparation requires the ClamAV and YARA engines.

Recovery defaults to **Same as installed**, when its reference is available.
Analysis always compares installed versions, even when a different recovery
version is requested. After analysis, choose **Latest stable from WordPress.org**
and **Prepare selected recovery version** to create a fresh read-only analysis
with separately labelled **Version updates**. Upgrades do not count as installed
file modifications or missing files. Exact release metadata, references and
candidate bytes are pinned; preview/apply do not resolve a newer release.
Unavailable targets never silently fall back to another version. A vendor ZIP
with a different version cannot verify the installed component's integrity.
**Specific versions and vendor ZIPs (optional)** accepts a component's website-relative path,
an optional target version, and a premium/custom ZIP. Prefer a private account
path such as `~/tmp/example.zip`, where `~` means the selected hosting account's
home, not the administrator's. Other paths are website-relative. ZIP roots,
release headers, paths, expanded sizes and candidate content are checked.
Without an explicit version override, a vendor ZIP supplies its own header version.
Vendor authenticity remains the operator's responsibility and is stated in the
receipt. Core always uses an official release. Invalid/ambiguous component
metadata remains unverified. A typo in a component mapping is reported.

The screen follows **1. Analyze website → 2. Findings and recovery actions →
3. Apply selected changes**. A new analysis opens automatically. Empty history
is hidden; retained runs appear under **Previous analyses and recoveries**.
The analysis result records proposed changes and is not a prerequisite to start.
Review the selected actions and exact file/database changes before **Apply
selected changes**. Version changes require all replacement files of each chosen
component; a partial file selection is rejected before review or application.
Changing the selection requires another preview. Pause
traffic, cron, deployment and other writers during recovery; this feature does
not stop shared PHP pools or unrelated account processes. The batch checks all
selected originals before applying and rechecks each actual mutation. It uses
per-file journals rather than an atomic switch of an entire application. A
concurrent change, cancellation or failure can therefore leave completed actions
retained alongside unapplied actions. **Resume selected changes** inspects
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
customers cannot disable the server protection. Native baseline antivirus/spam
rejection is retained for unmanaged recipients; managed verdicts follow their
selected policy through the owned integrations described below. The toggle
becomes **Disable mail protection** with a verified active connection and enabled
server defaults; activation also verifies native rejection delegation.
Disabling drains/detaches the connection and retains policies and quarantined
email. Tenant users retain their delegated account controls; the global toggle
requires native administrator authority.

With **Global** selected, **Server-wide email defaults** controls handling actions,
spam thresholds, sender lists and default customer permissions for every existing
and future account. The central activity view shows all native accounts, mail
domain counts, stored recipient records and recent decisions, even when the
administrator's own account has no mail domains. **Manage account** opens that
account for message previews, release, recovery and complete decision history.

Scanner unavailability, exhausted scan capacity and incomplete reports do not
defer mail merely because ClamShield could not finish a check. The original
Exim envelope remains in the native queue; the check is recorded as incomplete,
never clean. An unavailable policy broker, a timeout or an invalid bridge reply
also preserves native delivery. Native queue acceptance is not proof of final
mailbox delivery.

Verified findings follow the recipient's selected policy, including **Tag and
deliver** for malware. The owned native antivirus gateway delegates these
decisions to the envelope-authenticated policy hook instead of rejecting malware
before the selected policy can run. Unmanaged native-antivirus recipients retain
baseline rejection. Tagged delivery prefixes the subject with `*** MALWARE ***`,
`*** PHISHING ***`, `*** SPAM ***` or `*** BLOCKED SENDER ***` as appropriate.
MIME body and attachment bytes are preserved.

Native handoff receipts distinguish a successful custody transfer from fallback
delivery. If a broker capture was prepared but its reply was lost, an exact
native fallback marker plus Exim's source receipt aborts the unused private
capture. Silence or missing evidence never authorizes a second submission.

The owned Exim service drop-in uses an optional hook include in a temporary
systemd runtime directory. Each native start begins without that include. A
bounded startup check publishes it only when the native executable, adapter,
source and owned configuration match the verified binding. Missing addon code,
failed checks or a timeout leave the hook absent; they do not prevent native
Exim startup or load an incompatible adapter. Integration diagnostics report the
missing hook and maintenance can refresh it after compatibility is restored.

Enabling mail protection delegates native domain spam rejection to the late
recipient policy through Hestia's supported reject-spam commands. A private
receipt records the original flag, account generation and domain generation
before each change. Unmanaged sibling recipients retain the original native
threshold and strict comparison. If Hestia's early scan skipped the message,
the broker queries the verified native spamd service; an unavailable result
remains incomplete and preserves delivery. Native scores do not get added to
the ClamShield policy score.

After an update, the owned maintenance controller applies this integration once
for servers with mail protection already enabled. An interrupted or failed
attempt is retained for review rather than automatically repeated.

An owned add-mail-domain extension applies this delegation to newly created
managed domains. An extension belonging to another application is preserved
and reported as a conflict. Disable/uninstall restores only unchanged owned
flags through the native API and removes only the unchanged owned extension.
Recreated accounts/domains and subsequent administrator changes are preserved.
A failed or uncertain native change is retained for review, never blindly
retried. SMTP recipient/routing restrictions and mailbox/storage failures remain
separate native delivery paths that need their own checks.

When native SpamAssassin ran before the hook, history also retains its Exim
score separately from the ClamShield score and contribution report. This value
comes from the authenticated native API variable `spam_score_int` (in tenths),
never from message headers. An absent native result stays absent. The bridge
continues accepting the prior request format, which has no native score field.
The separate score does not itself disable native rejection or change a saved
handling policy.

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

DNS query observations come from verified message scans. Provider-blocked replies
and resolver error replies appear separately; neither adds administrative spam
points. Resolver errors are observed passively from SpamAssassin 4.x's existing
per-message packets. No extra queries are sent. Unsupported packet-cache layouts,
missing answers and normal NXDOMAIN answers remain unknown. The displayed time
is the last observation, not a live availability check. Individual mail decisions
retain their own observations and the applied configuration revision.

The mail integration also excludes Spamhaus's documented access-error replies
(`127.255.255.252`, `.254` and `.255`) from supported native IP DNSBL entries,
using Hestia's `v-add-sys-mail-dnsbl` / `v-delete-sys-mail-dnsbl` commands. This
prevents these errors rejecting mail before the ClamShield hook; real listing
responses remain enabled. Original choices are recorded privately and restored
on disable/removal, preserving later administrator changes. Failed or uncertain
native API calls require review and are never retried automatically. The mail
integration status shows the protection count or a review notice. This change
does not delegate native MIME filename checks or genuine DNSBL listings to the
recipient's ClamShield policy; those earlier native filters remain separate.

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
notification types you want to see under **ClamShield notifications**. For detections only, keep **Website malware
detections** checked and clear the other categories. This includes repeated
detections; WordPress integrity differences are a separate category. **Type**
and **Status** filter the list without a request. **All recorded types** still
shows retained events excluded from your selections. **Review → Notifications → Mark read** updates its
own row without reloading the panel and preserves the row on failure.

**HestiaCP notifications** has its own category selection, independent of the
ClamShield list filter. **Enable HestiaCP notifications** is off by default.
It sends future events selected in that section to
your native Hestia Bell using the supported `v-add-user-notification` command;
no vendor panel file is patched. An opted-in native administrator receives
current-generation events across the server; tenants receive only their own.
Changing HestiaCP selections or enabling Bell starts from that change, avoiding an old
notification flood. ClamShield and Hestia keep independent read states.
The owned `clamshield-notifications.timer` normally checks every 15 seconds.
Its separate service uses the root runtime gate and stops for installation or
removal. Failed/uncertain sends wait at least 60 seconds, check the native list
for the same stable link before retrying, and expose a delivery warning in the
personal preferences.

Clearing notifications in Review also requests deletion of matching Bell copies
for the signed-in native account, including when Bell delivery is disabled.
Only exact ClamShield content is matched; unrelated Hestia notices and other
recipients' copies remain. Native deletion gets one attempt. A failed or
interrupted attempt stops permanently and exposes the error in Review and
notification preferences; it is never automatically retried. Reading remains
separate. No engine or mail services are exposed to tenant controls.

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

Native ClamAV restoration is checked before its service is interrupted. A
configuration conflict leaves the running scanner in place. If removal fails
after stopping it, the controller attempts to resume the native scanner and,
while still needed, its owned socket gateway. The recovery journal and later
administrator edits remain available for review.

Successful removal prints every remaining ClamShield directory, its contents
and a separate `sudo rm -rf -- ...` command for manual deletion. The list includes
service settings, the state directory (policies, credentials, history, website
and email quarantine, recovery originals and local rules), signatures/cache,
mail adapters, SpamAssassin state, code snapshots, the source checkout and any
remaining runtime, panel-plugin and ClamShield unit-override directories. Only
paths that still exist are listed. Shared
Ubuntu packages and Hestia directories are not cleanup targets. `--json` includes
the same `retained_directories` list and `delete_command` fields.

Deleting the state directory removes all retained originals and undo data.
After completed removal, reinstall also works if the old code snapshots were
deleted while data was kept. A retained source checkout uses `git pull --ff-only`
followed by the installer; it does not need to be cloned again.

Repeat the same command after an interruption. If the active code pointer has
already been removed, use the original checkout:

```sh
sudo python3 /usr/local/src/clamshield-for-hestia/tools/uninstall.py
```

Alternatively invoke `tools/uninstall.py` inside the retained release recorded
in `/var/lib/clamshield/installation.json`. Reinstall restores the integrations
and exposes retained, correctly scoped custody and history.

## Where controls and records live

Settings contains YARA, signature-provider credentials/selections, email
policies and delegated permissions, SpamAssassin, automatic actions, personal
notification choices, retention, resources, website permissions and Support Us.
Updates contains update/install operations, last successful checks and recovery
of previous rule data. Email Shield keeps the one-button server protection flow.

Review contains website results, repairs, exceptions, quarantine, stored email
and delivery decisions, event history, maintenance/action activity and notification
records. Global **Review → Email** combines stored messages and decisions into
one row per message and recipient. It shows the subject/sender, classification,
policy decision and actual delivery status; a decision without delivery evidence
is never labelled delivered. Repeated evaluations use the latest matching native
message, content hash and account generation.

Use the account filter instead of an account summary table. Search, date,
classification, decision and delivery-status filters run before pagination;
choose 25, 50 or 100 rows. Clear list / Clear selected records remove completed
entries from this view while retaining operational evidence. Quarantined and
unresolved messages remain visible. Delete quarantined email / Delete selected
quarantined email are separate confirmed actions which delete only eligible
verified private copies. Confirmations state their full account scope, including
records hidden by filters. Deliver anyway requires a reason and queues only the
stored recipient; delivery remains unconfirmed until its original proof arrives.

Select an account above for its authorized previews, recovery and full decision
history. Quarantine and Exceptions contain their website and email sections
together. Domain/mailbox selectors stay scoped.

Old bookmarks for moved leaf pages redirect to their current group. Source
notices remain with downloaded data and historical evidence. The panel uses
short source references, including technical views; full third-party licenses
are not embedded in the interface. Settings → Support Us provides the supplied
PayPal, SaneSecurity and SecuriteInfo links plus upstream acknowledgements.


### Scan queue waiting reasons

Website scans share one worker across the server, including manual, WordPress
integrity and changed-file monitoring scans. Queued rows show their
position in that shared FIFO queue and elapsed wait. A scan already in progress
continues to completion; reading queue status does not interrupt or restart it.

The live status identifies a busy scan, held scanner lock, pending signature or
resource activation/recovery, website ClamAV service control, stopped/missing
worker timer, failed worker or an unclaimed delayed job. An administrator can see
the blocking scan's account, website and source even when viewing a different
account; hosting users receive only a generic shared-worker explanation. Queue
position is independent of search, account filters and pagination.

A Type=oneshot worker service normally remains activating (start) while it runs
a scan. This state alone does not indicate a startup hang. The status probe checks
the actual worker lock and recorded jobs as well as bounded read-only systemd
properties; a leftover lock filename alone is not considered busy. Pending
activation links open Review / History for administrators. Unknown service or
lock state is reported explicitly rather than presented as normal waiting.


### Signature updates and scanning

Scans use the active signatures and rules without downloading them first.
Provider/YARA automatic updates follow their saved schedules; installing updated
scanning data does not queue a scan. Full scans run manually or on an explicit
calendar schedule. Monitoring scans new/changed files when enabled.

The former post-update full scan option has been removed. Saved values are
ignored, new requests cannot create those jobs, queued old jobs are cancelled
before claim, and interrupted old jobs are not restarted by installation.
Historical records remain visible as Retired automatic scan until cleared.

Cancelling the initial scan for explicitly enabled changed-file monitoring
pauses that baseline. Scheduled Scanner offers Resume initial monitoring;
manual/calendar scans and monitoring with existing observations are independent.

Only Forge, community web hosting, local and remote source types are supported.
Install/update rebuilds a mixed active ruleset from its supported installed source
bytes when necessary; this step does not fetch rule data. A selection containing
only unsupported sources returns to the normal Install rules state. Unsupported
rulesets cannot be reactivated or restored by rollback. Already pinned older
rulesets cannot publish matches from removed sources; a ruleset without any
supported sources reports missing coverage instead of a successful clean scan.
Retained findings show an explicit historical-source label, keep their original
evidence and are excluded from automatic remediation. Clear selected findings
or Clear all findings can remove those entries from the Review list.

WordPress.org release discovery follows the official [WordPress.org API](https://codex.wordpress.org/WordPress.org_API), [plugin information API](https://developer.wordpress.org/reference/functions/plugins_api/) and [core version check](https://developer.wordpress.org/reference/functions/wp_version_check/).


WordPress recovery actions support server pagination (25/50/100 rows), Previous
and Next, search, action, type and state filters. Large previews may shorten a
page to respect response limits. Selection persists across pages. **Select all**
selects all eligible matching actions across pages; blocked actions remain
unselectable, and **Clear selection** clears the full selection. Nothing is
selected automatically. **Preview selected changes** validates and stages the
selected replacements and exact diffs without changing the website. Apply stays
separate and is invalidated by changed selection or recovery-version choices.
Earlier analyses that compared recovery releases need a fresh installed-version
analysis before preview/apply; retained applied recoveries remain undoable.
