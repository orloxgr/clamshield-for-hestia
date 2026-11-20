<?php foreach($data['history'] as $event): ?>
<tr><td><?= $escape(gmdate('Y-m-d H:i:s',(int)$event['created'])) ?> UTC</td><td><?php if($cs_global): ?><strong><?=$escape(($event['owner']??'@admin')==='@admin'?'Server':$event['owner'])?></strong><br><?php endif ?><?=$escape($cs_history_actors[$event['actor']]??$event['actor'])?></td>
<td><?=$escape($cs_history_action($event['action']))?></td><td><div class="cs-history-summary"><?php foreach($cs_history_summary($event) as $line): ?><div><?=$escape($line)?></div><?php endforeach ?></div>
<details><summary class="button cs-disclosure"><i class="fas fa-caret-right cs-disclosure-icon" aria-hidden="true"></i>Technical details</summary><pre style="white-space:pre-wrap"><?=$escape('Event: '.$event['action']."\n".'Actor: '.$event['actor']."\n".'Reference: '.($event['subject']??'Not recorded')."\n".$cs_history_technical($event['detail']))?></pre></details></td></tr>
<?php endforeach;if(!$data['history']): ?><tr><td colspan="4">No events recorded in this view.</td></tr><?php endif ?>

