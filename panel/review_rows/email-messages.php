<?php foreach($data['email-messages'] as $mail_record): ?><tr data-owner="<?=$escape($mail_record['owner'])?>">
<td><?=$escape(gmdate('Y-m-d H:i:s',(int)$mail_record['created']))?> UTC</td>
<td><?=$escape($mail_record['owner']==='@admin'?'Server':$mail_record['owner'])?><br><?=$escape($mail_record['recipient'])?></td>
<td><?=$escape($mail_record['subject']??'Subject not retained')?><br><?=$escape($mail_record['sender'])?></td>
<td><?=$escape(['native-mime'=>'Native attachment policy','native-dnsbl'=>'Native IP-list policy','native-malware'=>'Native antivirus','native-spam'=>'Native antispam'][$mail_record['classification']??'']??ucfirst(str_replace('_',' ',$mail_record['classification']??'Not recorded')))?>
<br><?=$escape(['reject'=>'SMTP rejection','defer'=>'Temporary failure','junk'=>'Junk','tag'=>'Tag and deliver','deliver'=>'Deliver','quarantine'=>'Quarantine','native-fallback'=>'Native delivery continued'][$mail_record['action']]??ucfirst(str_replace('_',' ',$mail_record['action'])))?>
<?php if(!empty($mail_record['transport_note'])): ?><p><?=$escape($mail_record['transport_note'])?></p><?php endif ?></td>
<td><?=$escape(['native_failed'=>'Native delivery failed','delivery_uncertain'=>'Delivery unconfirmed','source_unconfirmed'=>'Source acceptance unconfirmed','not_retained'=>'No retained copy','release_queued'=>'Delivery queued','check_unavailable'=>'Check unavailable'][$mail_record['status']]??ucfirst(str_replace('_',' ',$mail_record['status'])))?>
<?php if(!empty($mail_record['error'])): ?><p><?=$escape($mail_record['error'])?></p><?php endif ?></td>
<td><?php if(!empty($mail_record['decision_id'])): ?>
<button class="button cs-mail-decision-show" type="button" data-decision="<?=$escape($mail_record['decision_id'])?>"<?php if(!empty($mail_record['native_reference'])): ?> data-native-reference="<?=$escape($mail_record['native_reference'])?>"<?php endif ?>>Show decision details</button><pre class="cs-mail-decision-output" hidden role="status" aria-live="polite"></pre>
<?php elseif(!empty($mail_record['native_reference'])&&$data['context']['admin']): ?>
<button class="button cs-mail-decision-show" type="button" data-native-reference="<?=$escape($mail_record['native_reference'])?>">Show check details</button><pre class="cs-mail-decision-output" hidden role="status" aria-live="polite"></pre>
<?php endif ?><?php if($data['context']['admin']&&!empty($mail_record['can_deliver'])): ?>
<form class="cs-review-email-deliver" data-delivery="<?=$escape($mail_record['delivery_id'])?>"><label>Delivery reason <input class="form-control" name="note" required maxlength="1000" placeholder="Reason for delivering this email"></label><button class="button" type="submit">Deliver anyway</button><p class="cs-review-email-status" role="status" aria-live="polite"></p></form>
<?php endif ?></td></tr><?php endforeach ?>
