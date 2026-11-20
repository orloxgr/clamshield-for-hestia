<?php // Managed by clamshield; only root-authorized data reaches these templates.
$cs_kind=$data['list'];
if(!in_array($cs_kind,['findings','repairs','exceptions','quarantine','history','notices','activity','automatic','email-stored','email-decisions','email-messages'],true)) throw new RuntimeException('Unknown Review list');
$data=$data['view_data'];
$cs_global=($data['context']['view_scope']??'account')==='server';
$cs_owner=static fn($row)=>$row['owner']??$data['context']['owner'];
$cs_label=static fn($row)=>($cs_global?($row['owner']??$data['context']['owner']).' / ':'').($row['domain']??'');
$cs_compact=static function($value) use (&$cs_compact){
 if(!is_array($value))return $value;
 foreach($value as $key=>$item){
  if(in_array($key,['license','licenses','upstream_notice'],true)&&(is_array($item)||(is_string($item)&&strlen($item)>200)))$value[$key]='Upstream notice retained with installed data. See Settings / Support Us.';
  else $value[$key]=$cs_compact($item);
 }
 return $value;
};
$data=$cs_compact($data);
if($cs_kind==='history')require __DIR__.'/history_format.php';
if($cs_kind==='notices')require __DIR__.'/notification_format.php';
if($cs_kind==='activity')require __DIR__.'/activity_format.php';
require __DIR__.'/automatic_format.php';
require __DIR__.'/review_rows/'.$cs_kind.'.php';
