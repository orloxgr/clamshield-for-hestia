<?php // Managed by clamshield
require __DIR__.'/activity_format.php'; ?>
<section data-page="activity" hidden><h2>Activity and maintenance</h2>
<h3 id="cs-sa-tasks" tabindex="-1">Updates and configuration</h3><button class="button" type="button" id="cs-sa-refresh-tasks">Refresh activity</button>
<div class="scroll"><table><thead><tr><th>Requested (UTC)</th><th>Operation</th><th>Status</th><th>Result</th></tr></thead><tbody id="cs-review-activity-rows">
<?php require __DIR__.'/review_rows/activity.php'; ?></tbody></table></div>
<?php require __DIR__.'/automatic_history.php'; ?>
</section>
