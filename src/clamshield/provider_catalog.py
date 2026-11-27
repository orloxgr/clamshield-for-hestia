"""Selectable upstream data files; no customer-specific URLs or credentials."""
MAX_DATABASE_BYTES = 512 * 1024**2
SECURITEINFO_BASE = 'https://www.securiteinfo.com/get/signatures'
SANE_MIRROR = 'rsync://rsync.sanesecurity.net/sanesecurity/'
SANE_KEY_URL = 'https://www.sanesecurity.com/publickey.gpg'
SANE_FINGERPRINT = '4E025A1CBA90A0653F38D2D8D691DED931EA4D9E'

# Risk labels reproduce the provider's qualitative categories, not a score.
SANE = {
    'sanesecurity.ftm': ('File-type mappings (required)', 'required', 'support'),
    'sigwhitelist.ign2': ('Provider false-positive exceptions (required)', 'required', 'support'),
    'phish.ndb': ('Phishing and malware', 'low', 'mixed'),
    'rogue.hdb': ('Malware and rogue software', 'low', 'malware'),
    'malwarehash.hsb': ('Malware hashes', 'low', 'malware'),
    'foxhole_filename.cdb': ('Suspicious archive filenames', 'low', 'malware'),
    'foxhole_generic.cdb': ('Suspicious archives', 'low', 'malware'),
    'badmacro.ndb': ('Dangerous document macros', 'medium', 'malware'),
    'shelter.ldb': ('Phishing and malware', 'medium', 'mixed'),
    'junk.ndb': ('Spam, phishing and scams; mixed signature groups', 'low', 'mixed'),
    'jurlbl.ndb': ('Junk URLs', 'low', 'spam'),
    'jurlbla.ndb': ('Automatically generated junk URLs', 'medium', 'spam'),
    'lott.ndb': ('Lottery spam', 'medium', 'spam'),
    'scam.ndb': ('Spam and scams', 'low', 'spam'),
    'spam.ldb': ('Logical spam signatures', 'medium', 'spam'),
    'spamimg.hdb': ('Spam images', 'low', 'spam'),
    'spamattach.hdb': ('Spammed attachments', 'low', 'spam'),
    'spear.ndb': ('Spear-phishing addresses', 'medium', 'phishing'),
    'spearl.ndb': ('Spear-phishing URLs', 'medium', 'phishing'),
    'blurl.ndb': ('Recent malicious and spam URLs', 'low', 'mixed'),
}
SANE_REQUIRED = ('sanesecurity.ftm', 'sigwhitelist.ign2')
SI_BASIC = ('securiteinfo.ign2', 'securiteinfoold.hdb')
SI = {
    'securiteinfo.ign2': ('Provider false-positive exceptions', False),
    'securiteinfoold.hdb': ('Older malware signatures', False),
    'securiteinfo.hdb': ('Malware hashes', True),
    'javascript.ndb': ('Malicious JavaScript', True),
    'securiteinfohtml.hdb': ('Malicious HTML', True),
    'securiteinfoascii.hdb': ('Scripts and text malware', True),
    'securiteinfoandroid.hdb': ('Android malware', True),
    'securiteinfopdf.hdb': ('Malicious PDF files', True),
    'securiteinfo0hour.hdb': ('Zero-hour malware', True),
    'securiteinfo.mdb': ('Generic malware signatures', True),
    'securiteinfo.yara': ('Provider YARA signatures for ClamAV', True),
    'securiteinfo.pdb': ('Phishing signatures', True),
    'securiteinfo.wdb': ('Phishing allowlist', True),
    'spam_marketing.ndb': ('Marketing spam', True),
    'securiteinfo-pua-app-and-vulnerabilities.ndb': ('Potentially unwanted applications', True),
}


RISK_URL = 'https://sanesecurity.com/usage/signatures/'
SI_SUPPORT = ('securiteinfo.ign2', 'securiteinfo.wdb')
ENGINE_WIDE_SUFFIXES = frozenset(('.ftm', '.ign2', '.fp', '.sfp', '.wdb', '.pdb'))


def server_wide(name):
    return name.endswith(tuple(ENGINE_WIDE_SUFFIXES))


def recommended(plan='basic'):
    """Deliberate presets, independent of saved settings and updater runs."""
    si_web = list(SI_BASIC) if plan == 'basic' else [
        name for name in SI if name not in ('spam_marketing.ndb',
        'securiteinfo-pua-app-and-vulnerabilities.ndb', 'securiteinfoandroid.hdb',
        'securiteinfo.pdb', 'securiteinfo.wdb')]
    si_mail = list(si_web)
    if plan != 'basic':
        si_mail += ['spam_marketing.ndb']
    # Only documented Low/Medium groups enter a preset; unknown/high never do.
    sane_web = list(SANE_REQUIRED) + [name for name, row in SANE.items()
        if row[1] in ('low', 'medium') and row[2] in ('malware', 'mixed')
        and name not in ('junk.ndb', 'blurl.ndb')]
    sane_mail = list(SANE_REQUIRED) + [name for name, row in SANE.items()
        if row[1] in ('low', 'medium')]
    return {'securiteinfo': {'website_databases': si_web, 'mail_databases': si_mail},
            'sanesecurity': {'website_databases': sane_web, 'mail_databases': sane_mail}}


def catalog():
    return {'securiteinfo': [{'name': name, 'description': row[0], 'paid': row[1],
                'risk': 'not-applicable' if name in SI_SUPPORT else 'not-rated', 'risk_url': None,
                'scope': 'server' if server_wide(name) else 'profile'}
                for name, row in SI.items()],
            'sanesecurity': [{'name': name, 'description': row[0],
                'risk': 'not-applicable' if row[1] == 'required' else row[1],
                'risk_url': RISK_URL, 'category': row[2], 'scope': 'server' if server_wide(name) else 'profile'}
                for name, row in SANE.items()]}
