<?php // Managed by clamshield; Global email uses one scoped, paged message list.
if(($data['context']['view_scope']??'account')==='server'): ?>
<div class="row"><button class="button" type="button" id="cs-email-messages-refresh">Refresh email</button></div>
<div class="scroll"><table><thead><tr><th>Time UTC</th><th>Account / recipient</th><th>Subject / sender</th><th>Classification / decision</th><th>Delivery status</th><th>Action</th></tr></thead><tbody id="cs-mail-messages"></tbody></table></div>
<?php endif ?>
