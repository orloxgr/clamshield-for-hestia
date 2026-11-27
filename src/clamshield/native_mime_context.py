"""Authenticated native extension-policy match; never a malware verdict."""


def observe(blocked):
    if blocked is not True:return None
    return dict(source='native-exim-acl',policy='blocked-extension',matched=True,score_contribution=0)


def verified(value):
    return isinstance(value,dict) and type(value.get('matched')) is bool and value==observe(True)
