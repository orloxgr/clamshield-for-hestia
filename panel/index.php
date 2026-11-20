<?php
// Managed by clamshield; additional route, no vendor files modified.
declare(strict_types=1);
$root = '/usr/local/hestia';
chdir($root . '/web');
$TAB = 'WEB';
$panel = new class implements ArrayAccess {
    public function offsetExists(mixed $offset): bool { return true; }
    public function offsetGet(mixed $offset): mixed {
        $name = trim((string)$offset, "'");
        if (!preg_match('/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/D', $name)) return ['SUSPENDED' => 'yes'];
        return get_user_data($name)[$name] ?? ['SUSPENDED' => 'yes'];
    }
    public function offsetSet(mixed $offset, mixed $value): void { throw new LogicException('Read only'); }
    public function offsetUnset(mixed $offset): void { throw new LogicException('Read only'); }
};
require $root . '/web/inc/main.php';
header('Cache-Control: no-store, private');
header('X-Robots-Tag: noindex, nofollow');
header('X-Content-Type-Options: nosniff');
$respond = static function(int $status, array $data): never {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_THROW_ON_ERROR);
    exit;
};
$actor = $_SESSION['user'] ?? '';
// Native "log in as" context must retain tenant permissions in the bridge.
if (($_SESSION['userContext'] ?? '') === 'admin' && !empty($_SESSION['look'])) $actor = $_SESSION['look'];
$request = ['actor' => $actor, 'native_user' => $_SESSION['user'] ?? '',
    'native_session' => session_id(), 'owner' => $_GET['owner'] ?? $actor, 'action' => 'dashboard'];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!empty($read_only) || !is_string($_POST['token'] ?? null) ||
        !hash_equals($_SESSION['token'] ?? '', $_POST['token'])) $respond(403, ['ok'=>false,'error'=>'Request token invalid or account is read only.']);
    foreach (['owner','action','scope','domain','mailbox','path','job_id','finding_id','operation_id','plan_id','delivery_id','profile','release','provider','name','content','exception_id','kind','note','notification_id','generation','search','source_id','rule_id','revision','stage'] as $key) {
        if (isset($_POST[$key])) {
            if (!is_string($_POST[$key])) $respond(400, ['ok'=>false,'error'=>'Invalid request field.']);
            $request[$key] = $_POST[$key];
        }
    }
    if (isset($_POST['source'])) {
        if (!is_string($_POST['source'])) $respond(400,['ok'=>false,'error'=>'Invalid rule source.']);
        $request['source']=json_decode($_POST['source']);
    }
    if (isset($_POST['enabled'])) {
        if (!is_string($_POST['enabled']) || !in_array($_POST['enabled'],['true','false'],true)) $respond(400,['ok'=>false,'error'=>'Invalid state.']);
        $request['enabled']=$_POST['enabled']==='true';
    }
    if (isset($_POST['cascade'])) {
        if (!is_string($_POST['cascade']) || !in_array($_POST['cascade'],['true','false'],true)) $respond(400,['ok'=>false,'error'=>'Invalid dependency option.']);
        $request['cascade']=$_POST['cascade']==='true';
    }
    if (isset($_POST['policy'])) {
        if (!is_string($_POST['policy'])) $respond(400,['ok'=>false,'error'=>'Invalid policy.']);
        // Keep {} as an object through the JSON bridge; [] must stay an array.
        $request['policy'] = json_decode($_POST['policy']);
    }
    if (isset($_POST['offset'])) {
        if (!is_string($_POST['offset']) || !ctype_digit($_POST['offset'])) $respond(400,['ok'=>false,'error'=>'Invalid report offset.']);
        $request['offset'] = (int)$_POST['offset'];
    }
    if (isset($_POST['providers'])) {
        if (!is_string($_POST['providers'])) $respond(400,['ok'=>false,'error'=>'Invalid provider settings.']);
        $request['providers'] = json_decode($_POST['providers']);
    }
} elseif ($_SERVER['REQUEST_METHOD'] !== 'GET') $respond(405, ['ok'=>false,'error'=>'Method not supported.']);
if (!is_string($request['owner'])) $respond(400, ['ok'=>false,'error'=>'Invalid account.']);
$process = proc_open(['/usr/bin/sudo','-n',$root.'/bin/v-clamshield','request'],
    [0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']], $pipes);
if (!is_resource($process)) $respond(503, ['ok'=>false,'error'=>'ClamShield is unavailable.']);
fwrite($pipes[0], json_encode($request, JSON_THROW_ON_ERROR)); fclose($pipes[0]);
$output = ''; $diagnostic = ''; $open = [1=>$pipes[1],2=>$pipes[2]];
foreach ($open as $pipe) stream_set_blocking($pipe, false);
while ($open) {
    $ready = array_values($open); $write = null; $except = null;
    if (stream_select($ready, $write, $except, 65) === 0) { proc_terminate($process); break; }
    foreach ($open as $key=>$pipe) {
        if (!in_array($pipe,$ready,true)) continue;
        $chunk = fread($pipe,8192);
        if ($chunk !== false) { if ($key===1) $output.=$chunk; else $diagnostic.=$chunk; }
        if (strlen($output)>8*1024*1024 || strlen($diagnostic)>65536) { proc_terminate($process); break 2; }
        if (feof($pipe)) { fclose($pipe); unset($open[$key]); }
    }
}
foreach ($open as $pipe) fclose($pipe);
$status = proc_close($process);
$data = json_decode($output,true);
if (!is_array($data)) $respond(503, ['ok'=>false,'error'=>'ClamShield is unavailable.']);
if ($_SERVER['REQUEST_METHOD']==='POST' || ($_GET['format']??'')==='json') {
    // The bounded root JSON was validated above. Forward it without a PHP
    // associative-array round trip, which changes empty objects {} into [].
    http_response_code($status===0?200:400);
    header('Content-Type: application/json; charset=utf-8');
    echo $output;
    exit;
}
if ($status!==0 || empty($data['ok'])) $respond(403,['ok'=>false,'error'=>$data['error']??'Access denied.']);
$escape = static fn($value) => htmlspecialchars((string)$value, ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');
require $root . '/web/templates/header.php';
top_panel($_SESSION['user'] ?? '', 'WEB');
require '/opt/clamshield/panel/view.php';
require $root . '/web/templates/footer.php';
