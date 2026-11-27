<?php // Managed by clamshield; measurements are separate from live service RAM.
$cs_memory=$resources['signature_memory']??['available'=>false,'running'=>false,'report'=>null]; ?>
<article class="card" id="cs-signature-memory" data-token="<?=$escape($_SESSION['token']??'')?>" data-owner="<?=$escape($data['context']['owner'])?>" data-measurement="<?=$escape(json_encode($cs_memory))?>">
<h3>Signature memory measurements</h3>
<p>Fresh-load peak RAM, measured three times with the active databases. Provider differences overlap; do not add them together. Live service RAM and limits are shown above.</p>
<div id="cs-memory-values"></div>
<div class="row"><button type="button" class="button" id="cs-memory-measure">Measure active signature memory</button><button type="button" class="button" id="cs-memory-refresh">Refresh measurement status</button></div>
<p>Temporarily loads signatures for measurement. Native mail scanning continues; website scans wait. The loading test is limited to 3 minutes; preparation time depends on database size.</p>
<p id="cs-memory-status" role="status" aria-live="polite"></p>
</article>
<script><?php readfile(__DIR__.'/signature_memory.js'); ?></script>
