<?php // Managed by clamshield; native controls and disclosure appearance. ?>
<section data-page="wordpress-recovery" id="cs-wp-recovery" hidden data-token="<?=$escape($_SESSION['token']??'')?>" data-owner="<?=$escape($data['context']['owner'])?>" data-scan-allowed="<?=($data['website_permissions']['effective']['scan']??true)?'true':'false'?>">
<h2>WordPress recovery</h2>
<p>Analyze WordPress files and database content, review a recovery plan, then apply selected actions. Analysis does not change your website. Originals are retained outside the public root for undo.</p>
<form id="cs-wp-analyze">
<div class="row"><label>Website <select class="form-select" name="domain" required><?php foreach($data['sites'] as $site): ?><option value="<?=$escape($site['domain'])?>" <?=$site['suspended']?'disabled':''?>><?=$escape($site['domain'])?><?=$site['suspended']?' · Suspended':''?></option><?php endforeach ?></select></label>
<label>WordPress folder (optional) <input class="form-control" name="path" placeholder="Discover installations in the whole website"></label></div>
<p><label><input type="checkbox" name="uploads_php" checked> Remove PHP and other server scripts from uploads</label></p>
<p><label><input type="checkbox" name="uploads_js"> Also remove all JavaScript from uploads</label></p>
<p><label><input type="checkbox" name="additional" checked> Recommend removing additional files inside verified core/plugin/theme directories</label></p>
<p><label><input type="checkbox" name="database" checked> Inspect WordPress databases</label></p>
<p>Uploads cleanup is your selected policy. A matching file is not automatically classified as malware. Removed files go to quarantine.</p>
<details><summary class="button cs-disclosure"><i class="fas fa-caret-right cs-disclosure-icon" aria-hidden="true"></i>Versions and trusted vendor ZIPs</summary>
<p>Without a selection, repair uses the installed version. To rebuild with another version, enter it explicitly. Premium/custom components need a ZIP obtained from your vendor. Prefer a private account folder using your file manager or SFTP: ~/tmp/example.zip refers to the selected hosting account's home. Paths without ~/ are relative to the website root. Package identity and scanning do not establish vendor authenticity.</p>
<div class="row"><label>Component directory <input class="form-control" id="cs-wp-component" placeholder="wp-content/plugins/example"></label><label>Version (optional) <input class="form-control" id="cs-wp-version" placeholder="Keep installed version"></label><label>Vendor ZIP (optional) <input class="form-control" id="cs-wp-package" placeholder="~/tmp/example.zip"></label><button class="button" type="button" id="cs-wp-add-source">Add selection</button></div>
<p>Use the WordPress installation folder for core (blank for root). Official core packages are always obtained from WordPress.org. Updates can require database migrations and compatibility checks after recovery.</p><ul id="cs-wp-sources"></ul></details>
<p><button class="button" type="submit" data-capability="scan">Analyze WordPress</button></p></form>
<div class="row"><label>Recovery plans <select class="form-select" id="cs-wp-plans"><option value="">Choose a plan</option></select></label><button class="button" type="button" id="cs-wp-refresh">Refresh</button></div>
<p id="cs-wp-status" role="status" aria-live="polite"></p><button class="button" type="button" id="cs-wp-cancel" hidden>Cancel pending work</button>
<div id="cs-wp-report" hidden>
<p id="cs-wp-summary"></p><p id="cs-wp-coverage"></p><p id="cs-wp-error" role="status"></p>
<p>Pause traffic, cron and other website writers during recovery. Each mutation refuses changed content; a batch can stop with completed actions retained for undo. Replacing files does not close the original vulnerability or invalidate stolen credentials.</p>
<div class="row"><button class="button" type="button" id="cs-wp-recommended">Select recommended actions</button><button class="button" type="button" id="cs-wp-clear">Clear selection</button><button class="button" type="button" id="cs-wp-review">Review selected actions</button><button class="button" type="button" id="cs-wp-apply" disabled>Apply reviewed recovery</button><button class="button" type="button" id="cs-wp-undo" hidden>Undo recovery</button></div>
<p id="cs-wp-selected"></p><div class="scroll"><table><thead><tr><th>Select</th><th>File / database field</th><th>Action and evidence</th><th>State</th></tr></thead><tbody id="cs-wp-items"></tbody></table></div>
<button class="button" type="button" id="cs-wp-more" hidden>More recovery actions</button>
<details><summary class="button cs-disclosure"><i class="fas fa-caret-right cs-disclosure-icon" aria-hidden="true"></i>Investigation and coverage</summary><p id="cs-wp-database"></p><pre id="cs-wp-investigation" style="white-space:pre-wrap"></pre></details>
<p id="cs-wp-rechecks"></p>
</div></section>
<script><?php readfile(__DIR__.'/wordpress_recovery.js'); ?></script>
