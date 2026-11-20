import argparse
from contextlib import nullcontext
import json
import os
import subprocess
import sys

from .application import Application
from .errors import ClamShieldError
from .hestia import Hestia
from .settings import Settings
from .store import Store


def main(argv=None):
    parser = argparse.ArgumentParser(description='ClamShield for Hestia')
    parser.add_argument('command', choices=('request', 'worker', 'maintenance', 'recover', 'mail-service', 'mail-delivery', 'mail-guard', 'tick', 'inventory', 'engines'))
    args = parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise ClamShieldError('Use the native panel or an administrator root shell')
        if os.environ.get('SUDO_USER') == 'hestiaweb' and args.command != 'request':
            raise ClamShieldError('Maintenance requires an administrator root shell')
        settings = Settings()
        settings.prepare()
        from .installation import Installation
        gate=Installation(settings).runtime() if args.command not in ('mail-service','mail-delivery','mail-guard') else nullcontext()
        with gate:return execute(args,settings)
    except ClamShieldError as exc:
        print(json.dumps({'ok': False, 'error': str(exc)}))
        return 1
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        print(json.dumps({'ok': False, 'error': 'Operation failed; inspect ClamShield service logs'}))
        return 1


def execute(args,settings):
    store, hestia = Store(settings.database), Hestia(settings.hestia)
    app = Application(settings, store, hestia)
    if args.command == 'request':
        maximum = 8 * 1024 * 1024
        raw = sys.stdin.buffer.read(maximum + 1)
        if len(raw) > maximum:
            raise ClamShieldError('Request is too large')
        value = app.dispatch(json.loads(raw))
    elif args.command == 'worker':
        from .worker import Worker
        value = {'worked': Worker(settings, store, hestia).once()}
    elif args.command == 'tick':
        from .scheduler import Scheduler
        value = Scheduler(settings, store, hestia).once()
    elif args.command == 'maintenance':
        from .maintenance import Maintenance
        value = Maintenance(settings, store, hestia).once()
    elif args.command == 'recover':
        from .repairs import Repairs
        from .mail_custody import MailCustody
        from .mail_delivery import MailDelivery
        from .mail_acceptance import MailAcceptance
        from .quarantine import Quarantine
        from .remediation import Remediation
        from .mail_retention import MailRetention
        from .history_retention import HistoryRetention
        from .server_history import ServerHistory
        value = {**Repairs(settings, store, hestia).recover_pending(),
                 **Quarantine(settings,store,hestia).recover_pending(),
                 **Remediation(settings,store,hestia).once(),
                 **MailCustody(settings, store, hestia).recover(),
                 **MailAcceptance(settings, store, hestia).recover(),
                 **MailRetention(settings, store, hestia).once(),
                 **MailDelivery(settings, store, hestia).recover(),
                 **HistoryRetention(settings, store, hestia).once(),
                 **ServerHistory(settings, store, hestia).once()}
    elif args.command == 'mail-delivery':
        from .mail_delivery import MailDelivery
        value = MailDelivery(settings, store, hestia).once()
    elif args.command == 'mail-service':
        from .mail_service import serve
        serve(settings);value={'stopped':True}
    elif args.command=='mail-guard':
        from .mail_integration import MailIntegration
        value=MailIntegration(settings,store,hestia).guard()
    elif args.command == 'engines':
        value = app.engine_status()
    else:
        value = {'accounts': hestia.inventory()}
    print(json.dumps({'ok': True, **value}, ensure_ascii=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
