# Changelog

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
