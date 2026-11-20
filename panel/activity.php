<?php // Managed by clamshield
require __DIR__.'/activity_format.php'; require __DIR__.'/automatic_format.php'; ?>
<?php if($data['context']['admin']): ?>
<h3 id="cs-sa-tasks" tabindex="-1">Updates and configuration</h3>
<div class="scroll"><table><thead><tr><th>Requested (UTC)</th><th>Operation</th><th>Status</th><th>Result</th></tr></thead><tbody id="cs-review-activity-rows">
<?php require __DIR__.'/review_rows/activity.php'; ?></tbody></table></div>
<?php endif ?>
<?php require __DIR__.'/automatic_history.php'; ?>
