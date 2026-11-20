"""Asynchronous provider updates; HTTP requests never wait for downloads or reloads."""
import fcntl
import json
import os
import socket
import subprocess
import time
import uuid

from .errors import ClamShieldError
from .signatures import Signatures


class Maintenance:
    def __init__(self, settings, store, hestia):
        self.settings, self.store, self.hestia = settings, store, hestia
        self.worker = f'{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex}'

    def once(self):
        self.settings.prepare()
        with (self.settings.state / 'maintenance.lock').open('a+b') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return {'busy': True}
            with self.store.connection() as db:
                abandoned = [dict(row) for row in db.execute("SELECT * FROM maintenance WHERE status='running'").fetchall()]
            for stale in abandoned:
                self.store.finish_task(stale, error='Maintenance worker stopped before completion')
            from .resources import Resources
            resources=Resources(self.settings)
            if resources.journal.exists():
                recovered=resources.recover_limits()
                self.store.audit({'actor':'clamshield-maintenance','owner':'@admin','identity':''},'resources.recovered','server',recovered)
                self.store.notify('@admin','','maintenance.recovered','resources',{'message':'Interrupted resource limits were recovered'})
            if (self.settings.state / 'signature-activation.json').exists():
                Signatures(self.settings).recover()
                self.store.notify('@admin', '', 'maintenance.recovered', 'signatures',
                                  {'message': 'An interrupted database activation was rolled back'})
            if (self.settings.state / 'spamassassin-activation.json').exists():
                from .spamassassin import SpamAssassinControls
                SpamAssassinControls(self.settings).recover()
                self.store.notify('@admin', '', 'maintenance.recovered', 'spamassassin',
                                  {'message': 'An interrupted SpamAssassin activation was rolled back'})
            task = self.store.claim_task(self.worker)
            if resources.website_journal.exists() and not (task and task['action']=='website-engine-stop'):
                try:
                    recovered=resources.recover_website()
                    self.store.audit({'actor':'clamshield-maintenance','owner':'@admin','identity':''},'website-engine.recovered','website-clamav',recovered)
                    self.store.notify('@admin','','maintenance.recovered','website-engine',{'message':'Interrupted website engine control was recovered'})
                except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError,ClamShieldError):
                    if task:self.store.finish_task(task,error='Website engine recovery is pending; review or stop the engine')
                    return {'worked':bool(task),'website_recovery_pending':True}
            from .mail_integration import MailIntegration
            integration=MailIntegration(self.settings,self.store,self.hestia)
            if integration.journal.exists() and not (task and task['action'] in ('mail-integration-disable','mail-protection-disable')):
                try:
                    integration.recover()
                    self.store.notify('@admin','','maintenance.recovered','mail-integration',{'message':'An interrupted mail integration transition was restored'})
                except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError,ClamShieldError):
                    if task:self.store.finish_task(task,error='Mail integration recovery is pending; review or disable the integration')
                    return {'worked':bool(task),'mail_recovery_pending':True}
            if task is None:
                return {'worked': False,'mail_refresh':integration.reconcile()}
            try:
                context = self.hestia.authorize(task['actor'], task['owner'])
                if not context['admin'] or context['identity'] != task['identity']:
                    raise ClamShieldError('Maintenance account is unavailable or was replaced')
                signatures = Signatures(self.settings)
                if task['action']=='yara-settings-save':
                    from .yara_settings import YaraSettings
                    result={'policy':YaraSettings(self.settings).apply(task['payload']['policy'])}
                elif task['action']=='resources-save':
                    result=resources.apply(task['payload']['policy'])
                    self.store.audit({'actor':context['actor'],'owner':'@admin','identity':''},'resources.applied','server',dict(result,policy=task['payload']['policy']))
                elif task['action'] in ('website-engine-start','website-engine-stop'):
                    result=resources.website(task['action']=='website-engine-start')
                    self.store.audit({'actor':context['actor'],'owner':'@admin','identity':''},task['action'],'website-clamav',result)
                elif task['action']=='resources-recover':
                    result={'limits':resources.recover_limits(),'website':resources.recover_website()}
                elif task['action'] == 'signatures-update':
                    result = signatures.update(task['payload'].get('provider', 'all'))
                elif task['action'] == 'signatures-activate':
                    result = signatures.update('local', acquire=False)
                elif task['action'] == 'signatures-rollback':
                    result = signatures.rollback()
                elif task['action'] == 'spamassassin-save':
                    from .spamassassin import SpamAssassinControls
                    result = SpamAssassinControls(self.settings).apply(task['payload']['policy'])
                    self.store.audit(context, 'spamassassin.applied', 'server', {'revision': result['revision']})
                elif task['action'] in ('mail-adapter-build','mail-adapter-verify'):
                    from .mail_adapter import MailAdapter
                    adapter=MailAdapter(self.settings)
                    result=adapter.build() if task['action']=='mail-adapter-build' else adapter.verify()
                    self.store.audit(context,'mail.adapter_prepared' if task['action']=='mail-adapter-build' else 'mail.adapter_verified','server',{'generation':result['generation'],'native':result['native']})
                elif task['action'] in ('mail-protection-enable','mail-protection-disable'):
                    from .mail_protection import MailProtection
                    protection=MailProtection(self.settings,self.store,self.hestia)
                    result=protection.enable(context,progress=lambda phase:self.store.task_progress(task,phase)) if task['action']=='mail-protection-enable' else protection.disable()
                    self.store.audit(context,task['action'],'server',result)
                elif task['action'].startswith('mail-integration-'):
                    from .mail_integration import MailIntegration
                    integration=MailIntegration(self.settings,self.store,self.hestia)
                    method={'mail-integration-enable':integration.enable,'mail-integration-disable':integration.disable,'mail-integration-refresh':integration.refresh,'mail-integration-recover':integration.recover}.get(task['action'])
                    if method is None:raise ClamShieldError('Unsupported mail integration operation')
                    result=method();self.store.audit(context,task['action'],'server',result)
                elif task['action'].startswith('rules-'):
                    from .rule_manager import RuleManager
                    manager=RuleManager(self.settings); payload=task['payload']
                    if task['action']=='rules-options-save':
                        from .yara_settings import YaraSettings
                        with YaraSettings(self.settings).locked():result=manager.configure_hosting(payload['policy'])
                    elif task['action']=='rules-install':
                        if payload.get('automatic') and manager.automatic_update()!=payload:
                            raise ClamShieldError('Automatic YARA update settings changed; no rules were downloaded or activated')
                        result=manager.install(payload['profile'],payload.get('release'),progress=lambda phase:self.store.task_progress(task,phase),
                            **({'automatic':payload} if payload.get('automatic') else {}))
                    elif task['action']=='rules-update':result=manager.forge(payload['profile'],payload.get('release'))
                    elif task['action']=='rules-php-hosting':result=manager.php_hosting()
                    elif task['action']=='rules-web-hosting':result=manager.web_hosting()
                    elif task['action']=='rules-build':result=manager.build(payload.get('revision'))
                    elif task['action']=='rules-fetch':result=manager.fetch(payload['source_id'])
                    elif task['action']=='rules-activate':result=manager.activate(payload['generation'])
                    elif task['action']=='rules-rollback':result=manager.rollback()
                    else:raise ClamShieldError('Unsupported rules operation')
                    if payload.get('apply'):
                        result=manager.activate(result['generation']) | {'activated':True}
                else:
                    raise ClamShieldError('Unsupported maintenance operation')
                self.store.finish_task(task, result=result)
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, ClamShieldError) as exc:
                message = str(exc) if isinstance(exc, ClamShieldError) else 'Maintenance failed or timed out; inspect task status'
                try:
                    if task['action'].startswith('signatures-'):
                        Signatures(self.settings).providers.status('activation', state='error', error=message)
                except OSError:
                    pass
                self.store.finish_task(task, error=message)
            return {'worked': True, 'task_id': task['id']}
