"""A scan's policy generation includes YARA and website ClamAV database data."""
import json


def current(settings):
    yara = settings.state / 'rules/current'
    yara_name = yara.resolve().name if yara.is_symlink() else 'unconfigured'
    clamav = settings.signatures / 'current'
    if clamav.is_symlink():
        clamav_name = clamav.resolve().name
    else:
        clamav_name = 'ubuntu-native'
    from .yara_settings import YaraSettings
    policy = YaraSettings(settings)
    selection = '|scanner:' + policy.token() if policy.path.exists() or policy.path.is_symlink() else ''
    return yara_name + selection + '|clamav:' + clamav_name
