<?php // Managed by clamshield; shared selection table with independent scan profiles.
$cs_risks=['low'=>'Low','medium'=>'Medium','high'=>'High','not-rated'=>'Not rated','not-applicable'=>'Not applicable','required'=>'Not applicable'];
?>
<details><summary class="button cs-disclosure"><i class="fas fa-caret-right cs-disclosure-icon" aria-hidden="true"></i><?=$escape($cs_provider_title)?> databases</summary>
<div class="scroll"><table><thead><tr><th>Database / purpose</th><th>False-positive risk</th><th>Website files</th><th>Email</th></tr></thead><tbody>
<?php foreach($providers['catalog'][$cs_provider_name] as $row): $cs_risk=$cs_risks[$row['risk']??'not-rated']??'Not rated'; ?>
<tr><td><?=$escape($row['name'].' - '.$row['description'].(!empty($row['paid'])?' (paid)':''))?></td><td><?php if(!empty($row['risk_url'])): ?><a href="<?=$escape($row['risk_url'])?>" target="_blank" rel="noopener noreferrer"><?=$escape($cs_risk)?></a><?php else: ?><?=$escape($cs_risk)?><?php endif ?></td>
<?php foreach(['website'=>'Website files','mail'=>'Email'] as $cs_profile=>$cs_profile_title): $cs_selected=$providers[$cs_provider_name][$cs_profile.'_databases']??$providers[$cs_provider_name]['databases']; ?>
<td><input type="checkbox" name="<?=$cs_provider_prefix?>_<?=$cs_profile?>_databases" value="<?=$escape($row['name'])?>" aria-label="<?=$escape($cs_profile_title.': '.$row['name'])?>" <?=in_array($row['name'],$cs_selected,true)?'checked':''?>></td>
<?php endforeach ?></tr><?php endforeach ?>
</tbody></table></div></details>
