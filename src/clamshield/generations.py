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
    return yara_name + '|clamav:' + clamav_name
