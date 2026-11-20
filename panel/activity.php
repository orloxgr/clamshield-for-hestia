<?php // Managed by clamshield
$cs_operations=['rules-install'=>'Update YARA rules','rules-update'=>'Update YARA source','rules-options-save'=>'Apply website rule settings','yara-settings-save'=>'Apply YARA scanning settings','rules-build'=>'Prepare rule selection','rules-activate'=>'Apply rule selection','rules-rollback'=>'Restore previous rules','rules-fetch'=>'Update custom rules','rules-web-hosting'=>'Update web rules','signatures-update'=>'Update signatures','signatures-activate'=>'Apply cached signatures','signatures-rollback'=>'Restore signatures','spamassassin-save'=>'Apply SpamAssassin settings','resources-save'=>'Apply resource limits','website-engine-start'=>'Start website ClamAV','website-engine-stop'=>'Stop website ClamAV'];
?>
<section data-page="activity" hidden><h2>Activity and maintenance</h2>
<h3 id="cs-sa-tasks" tabindex="-1">Updates and configuration</h3><button class="button" type="button" id="cs-sa-refresh-tasks">Refresh activity</button>
<div class="scroll"><table><thead><tr><th>Requested (UTC)</th><th>Operation</th><th>Status</th><th>Result</th></tr></thead><tbody>
<?php foreach($data['maintenance']??[] as $task): ?><tr><td><?=$escape(gmdate('Y-m-d H:i:s',(int)$task['created']))?></td><td><?=$escape($cs_operations[$task['action']]??ucfirst(str_replace('-',' ',$task['action'])))?></td><td><?=$escape(ucfirst($task['status']))?></td><td><?=$escape($task['error']??($task['status']==='completed'?'Completed successfully':($task['status']==='queued'?'Waiting to start':'In progress')))?></td></tr><?php endforeach ?>
</tbody></table></div>
<?php require __DIR__.'/automatic_history.php'; ?>
</section>
