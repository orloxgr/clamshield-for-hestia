<?php // Managed by clamshield; native controls and disclosure appearance.
$cs_global=($data['context']['view_scope']??'account')==='server';
$cs_owner=static fn($row)=>$row['owner']??$data['context']['owner'];
$cs_label=static fn($row)=>($cs_global?($row['owner']??$data['context']['owner']).' / ':'').($row['domain']??'');
?>
<section data-page="wordpress-recovery" id="cs-wp-recovery" data-admin="<?=!empty($data['context']['admin'])?'true':'false'?>" data-scope="<?=$cs_global?'server':'account'?>" hidden data-token="<?=$escape($_SESSION['token']??'')?>" data-owner="<?=$escape($data['context']['owner'])?>" data-scan-allowed="<?=($data['website_permissions']['effective']['scan']??true)?'true':'false'?>">
<div class="row"><h2>WordPress</h2><button class="button" type="button" id="cs-wp-refresh">Refresh</button></div>
<p>Analyze compares core, plugins and themes with their installed versions. Review the findings, choose a recovery version, and apply only the changes you select. Analysis and review do not change website files or its database. Changes run only when you press Apply selected changes.</p>
<article class="card"><h3>1. Analyze website</h3>
<form id="cs-wp-analyze">
<?php $cs_target_bulk=false;require __DIR__.'/website_targets.php'; ?>
<p><label>WordPress folder (optional) <input class="form-control" name="path" placeholder="Discover installations in the whole website"></label></p>
<h4>Cleanup actions to propose</h4>
<p><label><input type="checkbox" name="uploads_php" checked> Include PHP and other server scripts in uploads</label></p>
<p><label><input type="checkbox" name="uploads_js"> Include all JavaScript in uploads</label></p>
<p><label><input type="checkbox" name="additional" checked> Include additional files in verified core/plugin/theme directories</label></p>
<p><label><input type="checkbox" name="database" checked> Inspect databases for suspicious content (manual review)</label></p>
<p>These options propose cleanup actions for review. Nothing is removed during analysis. Applied file removals go to quarantine for undo.</p>
<details><summary class="button cs-disclosure"><i class="fas fa-caret-right cs-disclosure-icon" aria-hidden="true"></i>Specific versions and vendor ZIPs (optional)</summary>
<p>Same as installed is the default. Choose Latest stable above to prepare an update, or override an individual component below. Premium/custom components need a clean ZIP from your vendor; its version is read from the package.</p>
<p>Use a private hosting-account path such as ~/tmp/example.zip for vendor ZIPs. Other paths are relative to the website root.</p>
<div class="row"><label>Component directory <input class="form-control" id="cs-wp-component" placeholder="wp-content/plugins/example"></label><label>Version (optional) <input class="form-control" id="cs-wp-version" placeholder="Use recovery version policy"></label><label>Vendor ZIP (optional) <input class="form-control" id="cs-wp-package" placeholder="~/tmp/example.zip"></label><button class="button" type="button" id="cs-wp-add-source">Add selection</button></div>
<p>Use the WordPress installation folder for core (blank for root). Core files come from WordPress.org. Version changes can require WordPress database updates and compatibility checks after recovery.</p><ul id="cs-wp-sources"></ul></details>
<p><button class="button" type="submit" data-capability="scan">Analyze website</button></p></form></article>
<details id="cs-wp-history" hidden><summary class="button cs-disclosure"><i class="fas fa-caret-right cs-disclosure-icon" aria-hidden="true"></i>Previous analyses and recoveries</summary>
<p><label>Previous analysis <select class="form-select" id="cs-wp-plans"><option value="">Choose a previous analysis</option></select></label></p></details>
<p id="cs-wp-status" role="status" aria-live="polite"></p><button class="button" type="button" id="cs-wp-cancel" hidden>Cancel pending work</button>
<article class="card" id="cs-wp-report" hidden>
<h3>2. Findings and recovery actions</h3>
<p><label>Recovery versions <select class="form-select" name="release_policy" form="cs-wp-analyze"><option value="installed">Same as installed (if available)</option><option value="latest">Latest stable from WordPress.org</option></select></label></p>
<p>Analysis always checks installed versions. The recovery version controls replacement candidates; choosing Latest adds separate version-update actions. Change this choice and analyze again to prepare a different recovery version.</p>
<button class="button" type="button" id="cs-wp-prepare-versions">Prepare selected recovery version</button>
<p>Review versions and select the changes to prepare. Preparing the review does not change your website. Version changes require all replacement files for that component.</p>
<div class="scroll" id="cs-wp-version-summary" hidden><table><thead><tr><th>Component</th><th>Installed</th><th>Recovery version</th><th>Installed-version comparison / recovery availability</th></tr></thead><tbody id="cs-wp-versions"></tbody></table></div>
<p id="cs-wp-summary"></p><p id="cs-wp-coverage"></p><p id="cs-wp-error" role="status"></p>
<p>Pause traffic, cron and other website writers during recovery. Each mutation refuses changed content; a batch can stop with completed actions retained for undo. Replacing files does not close the original vulnerability or invalidate stolen credentials.</p>
<div class="row"><button class="button" type="button" id="cs-wp-recommended">Select all</button><button class="button" type="button" id="cs-wp-clear">Clear selection</button><button class="button" type="button" id="cs-wp-review">Preview selected changes</button></div>
<form id="cs-wp-filter" class="row cs-controls-row"><label>Search <input class="form-control" name="search" placeholder="File, database field or reason"></label><label>Action <select class="form-select" name="action"><option value="">All actions</option></select></label><label>Type <select class="form-select" name="type"><option value="">All types</option></select></label><label>State <select class="form-select" name="state"><option value="">All states</option></select></label><label>Rows <select class="form-select" name="limit"><option>25</option><option selected>50</option><option>100</option></select></label><button type="submit" class="button">Search actions</button></form>
<div class="row"><p id="cs-wp-page" role="status"></p><button class="button" type="button" id="cs-wp-previous">Previous</button><button class="button" type="button" id="cs-wp-next">Next</button></div>
<p id="cs-wp-selected"></p><div class="scroll"><table><thead><tr><th>Select</th><th>File / database field</th><th>Action and evidence</th><th>State</th></tr></thead><tbody id="cs-wp-items"></tbody></table></div>
<p id="cs-wp-empty" role="status" hidden></p>

<details><summary class="button cs-disclosure"><i class="fas fa-caret-right cs-disclosure-icon" aria-hidden="true"></i>Investigation and coverage</summary><p id="cs-wp-database"></p><pre id="cs-wp-investigation" style="white-space:pre-wrap"></pre></details>
<h3>3. Apply selected changes</h3>
<p id="cs-wp-apply-help">Prepare the selected changes with Preview selected changes before applying them. Originals are retained outside the public root for undo.</p>
<div class="row"><button class="button" type="button" id="cs-wp-apply" disabled>Apply selected changes</button><button class="button" type="button" id="cs-wp-undo" hidden>Undo recovery</button></div>
<p id="cs-wp-rechecks"></p>
</article></section>
<script><?php readfile(__DIR__.'/wordpress_recovery.js'); ?></script>
