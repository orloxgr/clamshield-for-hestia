"""The supported source types are shared by building and runtime evaluation."""

KINDS=frozenset(('forge','web-hosting','local','remote'))
PROVIDERS=frozenset(('yara-forge','web-hosting','local','remote','yara'))


def unsupported(config):
    return {key for key,source in config.get('sources',{}).items() if source.get('kind') not in KINDS}


def supported(config):
    removed=unsupported(config)
    return dict(config,sources={key:value for key,value in config['sources'].items() if key not in removed},
        disabled=[value for value in config['disabled'] if value.split(':',1)[0] not in removed])


def finding_supported(finding):
    return finding['engine']!='yara' or finding['provider'] in PROVIDERS
