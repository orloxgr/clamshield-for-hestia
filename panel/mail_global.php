<?php // Managed by clamshield; central settings never use a tenant scope.
if($data['context']['admin']): ?>
<article class="card" id="cs-mail-server" data-scope="<?=($data['context']['view_scope']??'account')==='server'?'server':'account'?>" data-token="<?=$escape($_SESSION['token']??'')?>" data-owner="<?=$escape($data['context']['owner'])?>" data-global="<?=($data['context']['view_scope']??'account')==='server'?'true':'false'?>">
<h3><?=($data['context']['view_scope']??'account')==='server'?'Server-wide email defaults':'Account email defaults'?></h3>
<p><?=($data['context']['view_scope']??'account')==='server'?'Apply to every existing and future hosting account.':'Override global defaults for every existing and future mail domain in this account.'?> Domain and mailbox overrides take precedence. Only administrators control the server connection and services.</p>
<form id="cs-mail-server-form" hidden><div id="cs-mail-server-fields"></div>
<details><summary class="button cs-disclosure"><i class="fas fa-caret-right cs-disclosure-icon" aria-hidden="true"></i><?=($data['context']['view_scope']??'account')==='server'?'Default hosting-user email permissions':'Hosting-user email permissions for this account'?></summary>
<p>Customers can make only the changes you allow here. Account-specific permissions override these defaults.</p><div id="cs-mail-server-permissions"></div></details>
<button class="button" type="submit">Save email defaults and permissions</button></form><?php if(($data['context']['view_scope']??'account')!=='server'): ?><button class="button" id="cs-mail-server-reset" type="button">Use global email defaults and permissions</button><?php endif ?>
<button class="button" type="button" id="cs-mail-server-refresh">Refresh email defaults</button><p id="cs-mail-server-status" role="status" aria-live="polite"></p>
</article>
<script><?php readfile(__DIR__.'/mail_global.js'); ?></script>
<?php endif ?>
