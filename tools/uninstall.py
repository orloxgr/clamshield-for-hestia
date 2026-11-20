#!/usr/bin/python3
"""Remove owned integration, retaining settings, history, quarantine and code."""
from pathlib import Path
import argparse
import json
import os
import shlex
import sys

SOURCE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(SOURCE/'src'))


def cleanup_report(result,source):
    if not result.get('uninstalled'):return result
    directories=list(result.get('retained_directories',[]));source=Path(source)
    if source.exists() and not any(source.is_relative_to(Path(row['path'])) for row in directories):
        directories.append(dict(path=str(source),purpose='ClamShield source checkout'))
    return result|{'retained_directories':[row|{'delete_command':shlex.join(['sudo','rm','-rf','--',row['path']])} for row in directories]}


def display(result,json_output=False):
    if json_output:
        print(json.dumps(result));return
    if not result.get('uninstalled'):
        print('ClamShield removal failed: '+result['error']);return
    print('ClamShield - Uninstall completed')
    print('Panel integration and owned services removed. Ubuntu/Hestia packages are unchanged.')
    directories=result['retained_directories']
    if not directories:
        print('No retained ClamShield directories were found.');return
    print('\nRetained directories - these have NOT been deleted:')
    for row in directories:
        print('\n  '+row['path']+'\n    '+row['purpose'])
        print('    Delete: '+row['delete_command'])
    print('\nFor a complete cleanup, run the Delete commands for the directories listed above.')
    print('Deleting the state directory also removes quarantine originals, email copies and recovery/undo data.')


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--json',action='store_true',help='Write the result and exact retained-directory list as JSON')
    args=parser.parse_args(argv)
    if os.geteuid()!=0 or os.environ.get('SUDO_USER')=='hestiaweb':raise SystemExit('Uninstall from an administrator root shell')
    from clamshield.installation import Installation
    from clamshield.settings import Settings
    from clamshield.errors import ClamShieldError
    try:result=cleanup_report(Installation(Settings()).uninstall(),SOURCE)
    except (OSError,ValueError,ClamShieldError) as exc:
        display(dict(uninstalled=False,error=str(exc),data_retained=True),args.json);return 1
    display(result,args.json);return 0


if __name__=='__main__':raise SystemExit(main())
