<?php // Managed by clamshield; presentation only, original audit evidence is retained.
$cs_history_words=static function(string $value): string {
    $value=ucfirst(str_replace(['.','_','-'],' ',$value));
    return str_ireplace(['wordpress','spamassassin','yara','clamav','securiteinfo'],['WordPress','SpamAssassin','YARA','ClamAV','SecuriteInfo'],$value);
};
$cs_history_actions=[
    'signatures-update'=>'Update antivirus signatures','rules-update'=>'Update YARA rules',
    'rules-install'=>'Install YARA rules','rules-forge'=>'Update YARA Forge rules',
    'rules-build'=>'Validate YARA rules','rules-activate'=>'Activate YARA rules',
    'spamassassin-save'=>'Apply SpamAssassin settings','mail-adapter-build'=>'Prepare email integration',
    'mail-integration-enable'=>'Enable email protection','mail-integration-disable'=>'Disable email protection',
    'mail-integration-refresh'=>'Refresh email protection',
    'mail-protection-enable'=>'Enable email protection','mail-protection-disable'=>'Disable email protection',
    'resources-save'=>'Apply scanner resource settings',
    'website-engine-start'=>'Start website scanner','website-engine-stop'=>'Stop website scanner',
    'scan.queued'=>'Scan queued','scan.completed'=>'Scan completed','scan.partial'=>'Scan incomplete',
    'scan.failed'=>'Scan failed','scan.cancelled'=>'Scan cancelled','scan.cancel_requested'=>'Scan cancellation requested',
    'installation.scan_interrupted'=>'Scan stopped for update',
    'maintenance.queued'=>'Maintenance queued','maintenance.completed'=>'Maintenance completed','maintenance.failed'=>'Maintenance failed',
    'policy.saved'=>'Website scan schedule saved','policy.reset'=>'Website scan schedule reset',
    'policy.defaults_saved'=>'Default scan schedule saved','providers.saved'=>'Signature provider settings saved',
    'website.permissions_saved'=>'Website permissions saved','automatic.policy_saved'=>'Automatic protection settings saved',
    'mail.server_settings_saved'=>'Global email settings saved','mail.account_defaults_saved'=>'Account email defaults saved',
    'mail.account_defaults_reset'=>'Account email defaults reset','mail.permissions_saved'=>'Email permissions saved',
    'mail.policy_saved'=>'Email policy saved','mail.policy_reset'=>'Email policy reset',
    'mail.release_queued'=>'Email release queued','mail.deleted'=>'Quarantined email deleted',
    'history.retention_saved'=>'History retention saved','history.retention_reset'=>'History retention reset',
    'history.server_saved'=>'Server history retention saved','history.server_reset'=>'Server history retention reset',
    'history.permission_saved'=>'History permissions saved','history.pruned'=>'Account history cleaned up',
    'history.server_pruned'=>'Server history cleaned up',
];
$cs_history_action=static fn($action)=>$cs_history_actions[$action]??$cs_history_words((string)$action);
$cs_history_labels=['domain'=>'Website','target'=>'Folder','path'=>'File','action'=>'Operation','operation'=>'Operation',
    'queued_action'=>'Operation','frequency'=>'Schedule','time'=>'Time','timezone'=>'Timezone','watch'=>'Monitor changed files',
    'rescan_updates'=>'Recheck after rule updates','scan_days'=>'Scan details retained (days)',
    'mail_days'=>'Email details retained (days)','event_days'=>'Events retained (days)',
    'maintenance_days'=>'Maintenance details retained (days)','allowed'=>'Permission granted','error'=>'Problem',
    'scanned'=>'Files checked','seen'=>'Entries inspected','infected'=>'Files with detections','detections'=>'Detections',
    'installations'=>'WordPress installations','modified'=>'Modified files','missing'=>'Missing files',
    'additional'=>'Additional files','unverified'=>'Unverified components','errors'=>'Errors','skipped'=>'Skipped entries'];
$cs_history_technical_key=static fn($key)=>preg_match('/(^id$|_id$|identity|generation|revision|sha256|hash|digest|fingerprint|^replaces$|^replacement_job$|^finding$|^attempt$|^native$)/i',(string)$key);
$cs_history_clean=static fn($value)=>preg_replace('/(?<![a-z0-9])[a-f0-9]{32,}(?![a-z0-9])/i','[technical reference]',(string)$value);
$cs_history_value=static fn($value)=>is_bool($value)?($value?'Yes':'No'):($value===null?'Not recorded':(string)$value);
$cs_history_jobs=[];
foreach($data['jobs'] as $job)$cs_history_jobs[($job['owner']??$data['context']['owner'])."\0".($job['identity']??'')."\0".$job['id']]=$job;
$cs_history_summary=static function(array $event) use ($cs_history_jobs,$cs_history_action,$cs_history_labels,$cs_history_words,$cs_history_technical_key,$cs_history_clean,$cs_history_value): array {
    $detail=$event['detail'];$lines=[];$action=$event['action'];
    $job=$cs_history_jobs[($event['owner']??'')."\0".($event['identity']??'')."\0".($event['subject']??'')]??null;
    $domain=$detail['domain']??$job['domain']??null;
    if(is_string($domain)&&$domain!=='')$lines[]='Website: '.$domain;
    $subject=(string)($event['subject']??'');
    if(!$domain&&!$job&&$subject!==''&&!preg_match('/[a-f0-9]{32,}/i',$subject))$lines[]='Applies to: '.(['server'=>'Whole server','account'=>'Hosting account','rules'=>'YARA rules'][$subject]??$subject);
    if(array_key_exists('target',$detail)||$job){$target=$detail['target']??$job['target']??'';$lines[]='Scope: '.($target===''?'Whole website':$cs_history_clean($target));}
    if($action==='installation.scan_interrupted'){
        $lines[]='Stopped to install a ClamShield update. Previous scan coverage is incomplete.';
        if(!empty($detail['replacement_job']))$lines[]='A new full scan was queued automatically.';
    }elseif(!empty($detail['replaces']))$lines[]='Full replacement scan queued after the ClamShield update.';
    $walk=static function($values,string $prefix='',int $depth=0) use (&$walk,&$lines,$action,$cs_history_action,$cs_history_labels,$cs_history_words,$cs_history_technical_key,$cs_history_clean,$cs_history_value): void {
        if($depth>6||count($lines)>=12)return;
        foreach($values as $key=>$value){
            if(count($lines)>=12)break;
            if($cs_history_technical_key($key)||in_array($key,['domain','target','bytes'],true)||$value===null||$value==='')continue;
            if($key==='error'&&$action==='installation.scan_interrupted')continue;
            if(is_array($value)){$walk($value,$key==='counters'?'':$prefix.$cs_history_words((string)$key).' / ',$depth+1);continue;}
            if($prefix===''&&in_array($key,['seen','scanned','infected','detections','installations','modified','missing','additional','unverified','errors','skipped'],true)&&$value==0&&$key!=='scanned')continue;
            $label=$cs_history_labels[$key]??$cs_history_words((string)$key);
            $text=in_array($key,['action','operation','queued_action'],true)?$cs_history_action((string)$value):$cs_history_value($value);
            $lines[]=$prefix.$label.': '.$cs_history_clean($text);
        }
    };
    $walk($detail);
    return $lines?:['No additional details recorded.'];
};
$cs_history_technical=static function($value,string $prefix='',int $depth=0) use (&$cs_history_technical,$cs_history_words,$cs_history_value): string {
    if(!is_array($value))return $prefix.': '.$cs_history_value($value)."\n";
    if(!$value)return $prefix.': None'."\n";
    if($depth>12)return $prefix.': Further nested evidence retained in the audit record'."\n";
    $text='';foreach($value as $key=>$item)$text.=$cs_history_technical($item,($prefix!==''?$prefix.' / ':'').$cs_history_words((string)$key),$depth+1);
    return $text;
};
$cs_history_actors=['clamshield-installer'=>'ClamShield installer','clamshield-maintenance'=>'Background maintenance',
    'clamshield-mail'=>'Email protection','clamshield-history'=>'History cleanup','clamshield-retention'=>'Email retention'];
?>
<div class="scroll"><table id="cs-history-events"><colgroup><col style="width:16%"><col style="width:18%"><col style="width:22%"><col style="width:44%"></colgroup><thead><tr><th>Time</th><th><?=$cs_global?'Account / actor':'Actor'?></th><th>Event</th><th>Details</th></tr></thead><tbody>
<?php foreach($data['history'] as $event): ?>
<tr><td><?= $escape(gmdate('Y-m-d H:i:s',(int)$event['created'])) ?> UTC</td><td><?php if($cs_global): ?><strong><?=$escape(($event['owner']??'@admin')==='@admin'?'Server':$event['owner'])?></strong><br><?php endif ?><?=$escape($cs_history_actors[$event['actor']]??$event['actor'])?></td>
<td><?=$escape($cs_history_action($event['action']))?></td><td><div class="cs-history-summary"><?php foreach($cs_history_summary($event) as $line): ?><div><?=$escape($line)?></div><?php endforeach ?></div>
<details><summary class="button cs-disclosure"><i class="fas fa-caret-right cs-disclosure-icon" aria-hidden="true"></i>Technical details</summary><pre style="white-space:pre-wrap"><?=$escape('Event: '.$event['action']."\n".'Actor: '.$event['actor']."\n".'Reference: '.($event['subject']??'Not recorded')."\n".$cs_history_technical($event['detail']))?></pre></details></td></tr>
<?php endforeach;if(!$data['history']): ?><tr><td colspan="4">No events recorded in this view.</td></tr><?php endif ?>
</tbody></table></div>
