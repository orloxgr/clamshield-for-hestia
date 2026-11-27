"""Validate immutable per-message contributions, never recalculate old verdicts."""
import json
import math
import re


def number(value):
    if type(value) not in (int, float) or not math.isfinite(value) or abs(value) > 1e6:
        raise ValueError('Invalid SpamAssassin score')
    return value


def validate(value):
    if (not isinstance(value, dict) or
            set(value)-{'dns_observations'} != {'version', 'complete', 'score', 'threshold', 'engine_version', 'rules_version', 'rules', 'reporter_sha256'} or
            type(value['version']) is not int or value['version'] != 1 or
            type(value['complete']) is not int or value['complete'] != 1):
        raise ValueError('Incomplete SpamAssassin contribution report')
    if not isinstance(value['reporter_sha256'], str) or not re.fullmatch(r'[0-9a-f]{64}', value['reporter_sha256']):
        raise ValueError('Invalid SpamAssassin reporter identity')
    number(value['score']); number(value['threshold'])
    from .dns_health import validate as validate_dns
    validate_dns(value.get('dns_observations',[]))
    for key in ('engine_version', 'rules_version'):
        if not isinstance(value[key], str) or not re.fullmatch(r'[A-Za-z0-9.,_-]{0,128}', value[key]):
            raise ValueError('Invalid SpamAssassin data version')
    rules = value['rules']
    if not isinstance(rules, list) or len(rules) > 1000:
        raise ValueError('Invalid SpamAssassin contributions')
    seen = set()
    for rule in rules:
        if (not isinstance(rule, dict) or set(rule) != {'name', 'score', 'description', 'hits'} or
                not isinstance(rule['name'], str) or not re.fullmatch(r'[A-Za-z0-9_]{1,128}', rule['name']) or
                rule['name'] in seen or type(rule['hits']) is not int or not 1 <= rule['hits'] <= 1000 or
                not isinstance(rule['description'], str) or len(rule['description']) > 512 or
                any(ord(c) < 32 or ord(c) == 127 for c in rule['description'])):
            raise ValueError('Invalid SpamAssassin rule contribution')
        seen.add(rule['name']); number(rule['score'])
    # Native check() may round the final score to three decimal places.
    if abs(math.fsum(rule['score'] for rule in rules) - value['score']) > .000501:
        raise ValueError('SpamAssassin contributions do not explain its score')
    return value


def parse(body):
    prefix, separator, payload = body.decode('ascii').strip('\r\n').partition('\n')
    match = re.fullmatch(r'CLAMSHIELD/1 ([0-9a-f]{64})\r?', prefix)
    if not separator or not match:
        raise ValueError('Missing SpamAssassin report version')
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('Duplicate report field')
            value[key] = item
        return value
    value = validate(json.loads(payload, object_pairs_hook=unique))
    return value | {'revision': match[1]}
