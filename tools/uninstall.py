#!/usr/bin/python3
"""Remove owned integration, retaining settings, history, quarantine and code."""
from pathlib import Path
import json
import os
import sys

SOURCE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(SOURCE/'src'))


def main():
    if os.geteuid()!=0 or os.environ.get('SUDO_USER')=='hestiaweb':raise SystemExit('Uninstall from an administrator root shell')
    from clamshield.installation import Installation
    from clamshield.settings import Settings
    from clamshield.errors import ClamShieldError
    try:print(json.dumps(Installation(Settings()).uninstall()));return 0
    except (OSError,ValueError,ClamShieldError) as exc:
        print(json.dumps(dict(uninstalled=False,error=str(exc),data_retained=True)));return 1


if __name__=='__main__':raise SystemExit(main())
