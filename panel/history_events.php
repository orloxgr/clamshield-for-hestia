<?php require __DIR__.'/history_format.php'; ?>
<div class="scroll"><table id="cs-history-events"><colgroup><col style="width:180px"><col style="width:18%"><col style="width:22%"><col></colgroup><thead><tr><th>Time</th><th><?=$cs_global?'Account / actor':'Actor'?></th><th>Event</th><th>Details</th></tr></thead><tbody id="cs-review-history-rows">
<?php require __DIR__.'/review_rows/history.php'; ?></tbody></table></div>
