<?php // Managed by clamshield; native Hestia controls and theme.
$notification_labels = [
    'scan.malware_found'=>'Malware detected', 'scan.repeated_detection'=>'Detected again',
    'scan.failed'=>'Scan failed', 'scan.partial'=>'Incomplete scan',
    'scan.update_interrupted'=>'Scan stopped for ClamShield update',
    'wordpress.integrity_issues'=>'WordPress integrity issues',
    'health.problem'=>'Service or scanning-data problem', 'health.recovered'=>'Service or scanning data recovered',
    'maintenance.completed'=>'Update or maintenance completed', 'maintenance.failed'=>'Update or maintenance failed',
    'maintenance.recovered'=>'Interrupted maintenance recovered', 'installation.recovered'=>'Installation recovered',
    'rules.trial_finished'=>'Rule comparison finished', 'mail.refreshed'=>'Mail integration refreshed',
    'mail.refresh_failed'=>'Mail integration refresh failed', 'mail.expiry_blocked'=>'Email expiry needs attention',
    'mail.native_fallback'=>'Incomplete email check: native delivery fallback',
    'automatic.cancelled'=>'Automatic action cancelled', 'automatic.cleaned'=>'Automatic cleaning completed',
    'automatic.needs_review'=>'Automatic action needs review', 'automatic.quarantined'=>'Automatically quarantined',
    'automatic.failed'=>'Automatic action failed',
    'cleanup.failed'=>'Cleaning failed', 'cleanup.undone'=>'Cleaning undone', 'cleanup.verified'=>'Cleaning verified',
    'cleanup.recheck_failed'=>'Cleaning recheck failed', 'cleanup.recovery_required'=>'Cleaning recovery required',
    'repair.failed'=>'Repair failed', 'repair.undone'=>'Repair undone', 'repair.verified'=>'Repair verified',
    'repair.recheck_failed'=>'Repair recheck failed', 'repair.recovery_required'=>'Repair recovery required',
];
$notification_subjects = [
    'clamav'=>'Website ClamAV', 'yara'=>'YARA engine', 'yara-rules'=>'YARA rules',
    'website-coverage'=>'Website scanning coverage', 'clamav-database-age'=>'ClamAV database age',
    'hestia-inventory'=>'Hestia account and website inventory',
    'provider-official'=>'Official ClamAV signatures', 'provider-securiteinfo'=>'SecuriteInfo signatures',
    'provider-sanesecurity'=>'SaneSecurity signatures',
    'signatures-update'=>'Signature update', 'signatures-ingest-native'=>'Native signature import', 'signatures-activate'=>'Signature activation',
    'signatures-rollback'=>'Signature rollback', 'rules-web-hosting'=>'Web hosting rule update',
    'rules-update'=>'YARA Forge update',
    'rules-build'=>'Build rule selection', 'rules-fetch'=>'Rule source update',
    'rules-activate'=>'Rule activation', 'rules-rollback'=>'Rule rollback',
    'resources-save'=>'Resource limits', 'resources'=>'Resource limits',
    'website-engine-start'=>'Start website ClamAV', 'website-engine-stop'=>'Stop website ClamAV',
    'website-engine'=>'Website ClamAV', 'spamassassin-save'=>'SpamAssassin settings',
    'spamassassin'=>'SpamAssassin', 'mail-integration'=>'Mail integration',
];
$notification_states = ['healthy'=>'Ready', 'unavailable'=>'Unavailable', 'stale'=>'Out of date',
    'missing'=>'Missing', 'error'=>'Error', 'unknown'=>'Not verified', 'stopped'=>'Stopped'];
$notification_counts = ['scanned'=>'Scanned files', 'infected'=>'Files with detections',
    'detections'=>'Detections', 'skipped'=>'Skipped files', 'errors'=>'Errors',
    'modified'=>'Modified files', 'missing'=>'Missing files', 'additional'=>'Additional files',
    'candidate_matches'=>'Candidate matches', 'baseline_matches'=>'Active-rule matches'];
?>
