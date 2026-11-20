"""Sanitized native Hestia mail inventory and envelope-recipient resolution."""
import re

from .errors import AccessDenied, ClamShieldError


def domain_name(value):
    if not isinstance(value, str) or len(value) > 253:
        raise AccessDenied('Invalid mail domain')
    try:
        result = value.encode('idna').decode('ascii').lower()
    except UnicodeError as exc:
        raise AccessDenied('Invalid mail domain') from exc
    if not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', result):
        raise AccessDenied('Invalid mail domain')
    return result


def local_name(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_.+-]{1,64}', value):
        raise AccessDenied('Invalid mailbox name')
    return value.lower()


def domains(hestia, owner, selected=None):
    from .hestia import account_name
    owner = account_name(owner)
    selected = domain_name(selected) if selected is not None else None
    before = hestia.identity(owner)
    result = []
    for raw_domain, row in sorted(hestia.call('v-list-mail-domains', owner, 'json').items()):
        domain = domain_name(raw_domain)
        if raw_domain != domain or not isinstance(row, dict):
            raise ClamShieldError('Native mail domain inventory is invalid')
        if selected is not None and domain != selected:continue
        accounts = []
        for raw_name, account in sorted(hestia.call('v-list-mail-accounts', owner, domain, 'json').items()):
            name = local_name(raw_name)
            if raw_name != name or not isinstance(account, dict):
                raise ClamShieldError('Native mailbox inventory is invalid')
            raw_aliases = account.get('ALIAS', '')
            if not isinstance(raw_aliases, str):
                raise ClamShieldError('Native mailbox alias inventory is invalid')
            aliases = sorted({local_name(n.strip()) for n in raw_aliases.split(',') if n.strip()})
            # Only selected non-secret native fields cross this boundary.
            accounts.append({'name': name, 'address': name + '@' + domain,
                             'aliases': aliases, 'suspended': account.get('SUSPENDED') == 'yes',
                             'forward_only': account.get('FWD_ONLY') == 'yes'})
        result.append({'owner': owner, 'identity': before, 'domain': domain,
                       'suspended': row.get('SUSPENDED') == 'yes', 'mailboxes': accounts,
                       'native_antivirus': row.get('ANTIVIRUS') == 'yes',
                       'native_antispam': row.get('ANTISPAM') == 'yes',
                       'native_reject_spam': row.get('REJECT') == 'yes'})
    if hestia.identity(owner) != before:
        raise AccessDenied('Native account changed while reading mail inventory')
    return result


def inventory(hestia):
    # Publish no partial global map when one native call fails.
    result = []
    for owner, user in sorted(hestia.call('v-list-users', 'json').items()):
        rows = domains(hestia, owner)
        if user.get('SUSPENDED') == 'yes':
            rows = [dict(row, suspended=True) for row in rows]
        result.extend(rows)
    if len({row['domain'] for row in result}) != len(result):
        raise ClamShieldError('Native mail domain ownership is ambiguous')
    return result


def resolve(rows, recipient):
    """Return canonical mailbox policy target; retain the original envelope later.

    An unknown local part still uses the owning domain policy: native routing
    remains authoritative for catchall and forwarding. Never guess plus aliases.
    """
    if not isinstance(recipient, str) or recipient.count('@') != 1:
        raise AccessDenied('Invalid envelope recipient')
    local, domain = recipient.rsplit('@', 1)
    domain = domain_name(domain)
    targets = [row for row in rows if row['domain'] == domain]
    if not targets:
        return None
    if len(targets) != 1:
        raise ClamShieldError('Native mail domain ownership is ambiguous')
    row = targets[0]
    matches = [m for m in row['mailboxes'] if local.lower() == m['name'] or local.lower() in m['aliases']]
    if len(matches) > 1:
        raise ClamShieldError('Native mailbox alias ownership is ambiguous')
    mailbox = matches[0] if matches else None
    return {'owner': row['owner'], 'identity': row['identity'], 'domain': domain,
            'mailbox': mailbox['name'] if mailbox else '',
            'recipient': recipient, 'suspended': row['suspended'] or bool(mailbox and mailbox['suspended'])}
