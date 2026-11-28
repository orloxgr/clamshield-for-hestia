<?php foreach($data['notifications'] as $notification):
    $detail = is_array($notification['detail']??null) ? $notification['detail'] : [];
    $parts = [];
    foreach(['message','error'] as $field) if(is_string($detail[$field]??null) && $detail[$field]!=='') $parts[]=$detail[$field];
    if($notification['event']==='mail.native_fallback'){
        foreach(['first_observed'=>'First recorded fallback','last_observed'=>'Last recorded fallback'] as $field=>$label)
            if(is_numeric($detail[$field]??null))$parts[]=$label.': '.gmdate('Y-m-d H:i:s',(int)$detail[$field]).' UTC';
        if(is_numeric($detail['observed_fallbacks']??null))$parts[]='Recorded fallback events: '.(int)$detail['observed_fallbacks'];
    }
    if(is_string($detail['state']??null)) $parts[]='State: '.($notification_states[$detail['state']]??$detail['state']);
    foreach(['path'=>'File', 'signature'=>'Detection', 'previous_detections'=>'Earlier detections'] as $field=>$label)
        if(isset($detail[$field]) && is_scalar($detail[$field])) $parts[]=$label.': '.$detail[$field];
    if(is_array($detail['counters']??null)) foreach($notification_counts as $field=>$label)
        if(isset($detail['counters'][$field]) && is_numeric($detail['counters'][$field]) && ($field==='scanned'||$detail['counters'][$field]>0)) $parts[]=$label.': '.number_format((int)$detail['counters'][$field]);
    $subject=(string)$notification['subject'];
    // Translate only known server components/operations; website and file
    // subjects retain their exact names even if they resemble an operation.
    if(in_array(explode('.',(string)$notification['event'],2)[0],['health','maintenance','installation'],true))
        $subject=$notification_subjects[$subject]??$subject;
    if($notification['event']==='mail.native_fallback')$subject='Native email delivery';
    $title=$notification_labels[$notification['event']]??ucfirst(str_replace(['.','_'],' ',(string)$notification['event']));
?>
<tr data-owner="<?=$escape($notification['owner']??$data['context']['owner'])?>" data-notification="<?=$escape($notification['id'])?>" data-event="<?=$escape($notification['event'])?>" data-read="<?=$notification['read_at']?'true':'false'?>"><td><?php if($cs_global): ?><?=$escape(($notification['owner']??'@admin')==='@admin'?'Server':$notification['owner'])?><br><?php endif ?><?=$escape(gmdate('Y-m-d H:i:s',(int)$notification['created']))?></td>
<td><?=$escape($title)?></td><td><?=$escape($subject)?>
<?php foreach($parts as $part): ?><p><?=$escape($part)?></p><?php endforeach ?>
<?php if($notification['event']==='mail.native_fallback'): ?><p><a href="#settings/mail-settings">Review mail integration</a></p><?php endif ?>
<details><summary class="button cs-disclosure"><i class="fas fa-caret-right cs-disclosure-icon" aria-hidden="true"></i>Technical details</summary><pre style="white-space:pre-wrap"><?=$escape(json_encode(['event'=>$notification['event'],'detail'=>$notification['detail']],JSON_PRETTY_PRINT))?></pre></details>
</td><td><?php if(!$notification['read_at']): ?><button type="button" class="button cs-notification-read">Mark read</button><?php else: ?><span>Read</span><?php endif ?><p class="cs-notification-read-status" role="status" aria-live="polite"></p></td></tr>
<?php endforeach ?>

