"""Native inventory only; command allowlist prevents arbitrary root commands."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

from .errors import AccessDenied, ClamShieldError

COMMANDS = frozenset(('v-list-user', 'v-list-users', 'v-list-web-domain',
                      'v-list-web-domains', 'v-list-mail-domains', 'v-list-mail-accounts', 'v-list-user-backups'))


def account_name(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', value):
        raise AccessDenied('Invalid account')
    return value


class Hestia:
    def __init__(self, root=Path('/usr/local/hestia'),*,timeout=60,deadline=None):
        self.root = Path(root)
        self.timeout,self.deadline=timeout,deadline

    def remaining(self,maximum=None):
        value=min(self.timeout,maximum or self.timeout)
        if self.deadline is not None:value=min(value,self.deadline-time.monotonic())
        if value<=0:raise ClamShieldError('Native Hestia request time budget is exhausted')
        return value

    def call(self, command, *args):
        if command not in COMMANDS or any(not isinstance(a, str) or '\0' in a for a in args):
            raise AccessDenied('Unsupported Hestia command')
        try:
            result = subprocess.run([str(self.root / 'bin' / command), *args],
                                    capture_output=True, text=True, timeout=self.remaining(),
                                    env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin',
                                         'HESTIA': str(self.root), 'LANG': 'C.UTF-8'})
        except (OSError, subprocess.SubprocessError) as exc:
            raise ClamShieldError('Native Hestia inventory is unavailable or timed out') from exc
        if result.returncode:
            raise ClamShieldError('Native Hestia inventory is unavailable')
        try:
            data = json.loads(result.stdout)
        except ValueError as exc:
            raise ClamShieldError('Native Hestia returned an invalid inventory') from exc
        if not isinstance(data, dict):
            raise ClamShieldError('Native Hestia returned an invalid inventory')
        return data

    def birth(self, fd):
        result = subprocess.run(['/usr/bin/stat', '--dereference', '--format=%W\n%w', '--', '/proc/self/fd/'+str(fd)],
                                pass_fds=(fd,), capture_output=True, text=True, timeout=self.remaining(10))
        lines = result.stdout.strip().splitlines()
        fraction = re.search(r'\.(\d{1,9}) [+-]\d{4}$', lines[1]) if len(lines) == 2 else None
        if result.returncode or not fraction or not lines[0].isdigit() or int(lines[0]) <= 0:
            raise ClamShieldError('Stable native filesystem birth times are required')
        return lines[1], int(lines[0])*1_000_000_000+int(fraction[1].ljust(9,'0'))

    def identity_details(self, owner):
        account_name(owner)
        from .paths import directory
        import pwd
        path = self.root / 'data' / 'users' / owner
        # Linux birth time is stable through account password/package changes.
        with directory(path) as fd:
            info = os.fstat(fd); uid = pwd.getpwnam(owner).pw_uid
            birth, birth_ns = self.birth(fd)
            with directory(path) as live:
                current = os.fstat(live)
                if (current.st_dev,current.st_ino) != (info.st_dev,info.st_ino) or pwd.getpwnam(owner).pw_uid != uid:
                    raise AccessDenied('Native account changed while reading its identity')
        # Preserve the existing identity digest; upgrading must not hide history.
        return hashlib.sha256(f'{uid}:{info.st_dev}:{info.st_ino}:{birth}'.encode()).hexdigest(), birth_ns

    def identity(self, owner):
        return self.identity_details(owner)[0]

    def panel_session(self, actor, native_user, session_id):
        """Bind the server's PHP session inode to the current login account.

        Hestia regenerates its file session at authentication. A same-name account
        replacement must not let a still-live old PHP session enter the new user.
        Native auth-log tail retention is deliberately not an authentication gate.
        """
        from .paths import file_handle
        import pwd
        actor,native_user=account_name(actor),account_name(native_user)
        if not isinstance(session_id,str) or not re.fullmatch(r'[A-Za-z0-9,-]{16,128}',session_id):
            raise AccessDenied('A native panel session is required; sign in again')
        # A native administrator may impersonate a tenant, retaining tenant role.
        context=self.authorize(native_user,actor)
        identity,account_birth=self.identity_details(native_user)
        with file_handle(self.root/'data/sessions','sess_'+session_id) as (fd,info):
            if info.st_uid!=pwd.getpwnam('hestiaweb').pw_uid or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)&0o077:
                raise AccessDenied('Native panel session is unavailable; sign in again')
            _,session_birth=self.birth(fd)
            if session_birth<=account_birth:
                raise AccessDenied('Native panel session predates this account; sign out and sign in again')
        binding={native_user:identity,actor:context['identity']}
        self.verify_panel_session(binding)
        return binding

    def verify_panel_session(self, binding):
        if any(self.identity(owner)!=identity for owner,identity in binding.items()):
            raise AccessDenied('Native panel account changed; sign out and sign in again')

    def authorize(self, actor, owner=None):
        actor = account_name(actor)
        owner = account_name(owner or actor)
        row = self.call('v-list-user', actor, 'json').get(actor)
        if not row or row.get('SUSPENDED') == 'yes':
            raise AccessDenied('Account unavailable')
        admin = row.get('ROLE') == 'admin'
        if owner != actor and not admin:
            raise AccessDenied('Another account cannot be selected')
        target = row if actor == owner else self.call('v-list-user', owner, 'json').get(owner)
        if not target or (target.get('SUSPENDED') == 'yes' and not admin):
            raise AccessDenied('Account unavailable')
        return {'actor': actor, 'owner': owner, 'admin': admin,
                'identity': self.identity(owner)}

    def sites(self, owner):
        owner = account_name(owner)
        rows = self.call('v-list-web-domains', owner, 'json')
        identity = self.identity(owner)
        result = []
        for domain, row in sorted(rows.items()):
            root = row.get('DOCUMENT_ROOT') or row.get('document_root')
            if not root:
                details = self.call('v-list-web-domain', owner, domain, 'json').get(domain, {})
                root = details.get('DOCUMENT_ROOT') or details.get('document_root')
            if not isinstance(root, str) or not root.startswith('/') or '..' in Path(root).parts or '\0' in root:
                raise ClamShieldError('Native document root is unavailable')
            result.append({'owner': owner, 'identity': identity, 'domain': domain,
                           'root': str(Path(root)), 'suspended': row.get('SUSPENDED') == 'yes'})
        return result

    def inventory(self):
        # Build all data before returning; failures cannot become a partial sync.
        users = self.call('v-list-users', 'json')
        return [{'owner': account_name(owner), 'role': row.get('ROLE'),
                 'suspended': row.get('SUSPENDED') == 'yes',
                 'identity': self.identity(owner), 'sites': self.sites(owner)}
                for owner, row in sorted(users.items())]
