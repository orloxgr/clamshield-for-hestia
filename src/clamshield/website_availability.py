"""Display live website scope without rewriting historical security results.

This is an inventory snapshot for the UI, never authorization for a mutation.
Every action still performs its existing native and descriptor-bound checks.
"""


class WebsiteAvailability:
    def __init__(self, context, sites):
        self.context = context
        self.sites = {site['domain']: site for site in sites}

    def describe(self, record, *, root=None):
        state, message = 'available', ''
        site = self.sites.get(record.get('domain'))
        if any(record.get(key) != self.context[key] for key in ('owner', 'identity')):
            state, message = 'account_changed', 'This record belongs to a different account generation.'
        elif site is None:
            state, message = 'removed', 'This website is no longer in the account inventory.'
        elif any(site.get(key) != self.context[key] for key in ('owner', 'identity')):
            state, message = 'account_changed', 'The website account changed. Reload before taking action.'
        elif not (root if root is not None else record.get('root')):
            state, message = 'unknown', 'The original document root is unavailable.'
        elif site['root'] != (root if root is not None else record['root']):
            state, message = 'root_changed', 'The website document root changed since this record was created.'
        elif site['suspended']:
            state, message = 'suspended', 'This website is suspended.'
        return dict(available=state == 'available', state=state, message=message)

    def annotate(self, data):
        for collection in ('jobs', 'findings', 'repairs', 'quarantine', 'remediation_history'):
            for record in data[collection]:
                root = record['metadata'].get('root') if collection == 'quarantine' else None
                record['site_availability'] = self.describe(record, root=root)
