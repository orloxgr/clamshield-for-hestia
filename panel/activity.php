<?php // Managed by clamshield
require __DIR__.'/activity_format.php'; require __DIR__.'/automatic_format.php'; ?>
<?php if($data['context']['admin']): ?>
<section data-page="update-history" hidden><div class="row"><h2 id="cs-sa-tasks" tabindex="-1">Updates</h2><button class="button" type="button" id="cs-update-history-refresh">Refresh updates</button></div>
<div class="scroll"><table><thead><tr><th>Requested (UTC)</th><th>Operation</th><th>Status</th><th>Result</th></tr></thead><tbody id="cs-review-activity-rows">
<?php require __DIR__.'/review_rows/activity.php'; ?></tbody></table></div>
</section>
<?php endif ?>
<script>document.getElementById('cs-update-history-refresh')?.addEventListener('click',()=>document.dispatchEvent(new CustomEvent('clamshield-review-refresh',{detail:'activity'})));</script>
