"""One scoped application API for the native panel and root CLI."""
import json
import os
from pathlib import Path
import time

from . import __version__
from .engines import ClamAV, Yara
from .errors import AccessDenied, ClamShieldError
from .paths import relative_path
from .quarantine import Quarantine
from .rules import Rules
from .scheduler import Scheduler
from .providers import Providers
from .signatures import Signatures
from .generations import current as current_generation
from .exceptions import Exceptions
from .health import Health
from .wordpress import WordPress
from .repairs import Repairs
from .rule_manager import RuleManager
from .rule_trials import RuleTrials
from .mail_policy import MailPolicies
from .mail_custody import MailCustody


class Application:
    def __init__(self, settings, store, hestia):
        self.settings, self.store, self.hestia = settings, store, hestia

    def dispatch(self, request):
        if not isinstance(request, dict):
            raise AccessDenied('Expected a request object')
        binding=None
        if os.environ.get('SUDO_USER')=='hestiaweb' or 'native_user' in request or 'native_session' in request:
            binding=self.hestia.panel_session(request.get('actor'),request.get('native_user'),request.get('native_session'))
        context = self.hestia.authorize(request.get('actor'), request.get('owner'))
        if binding is not None:self.hestia.verify_panel_session(binding)
        action = request.get('action', 'dashboard')
        if not isinstance(action, str):
            raise AccessDenied('Invalid operation')
        from .website_permissions import WebsitePermissions
        permissions=WebsitePermissions(self.settings,self.store,self.hestia)
        if action=='website-permissions-get':result=permissions.get(context,server=request.get('scope')=='server')
        elif action in ('website-permissions-save','website-permissions-reset'):result=permissions.save(context,request.get('policy'),server=request.get('scope')=='server',reset=action.endswith('-reset'))
        else:
            with permissions.guard(context,action,request) as live:result=self._dispatch(request,live or context)
        if binding is not None:self.hestia.verify_panel_session(binding)
        return result

    def _dispatch(self,request,context):
        action=request.get('action','dashboard')
        if action in ('wordpress-recovery-analyze','wordpress-recovery-status','wordpress-recovery-list','wordpress-recovery-preview','wordpress-recovery-apply','wordpress-recovery-undo'):
            from .wordpress_recovery import WordPressRecovery
            recovery=WordPressRecovery(self.settings,self.store,self.hestia)
            if action=='wordpress-recovery-analyze':return recovery.analyze(context,request.get('domain'),request.get('path',''),request.get('policy',{}))
            if action=='wordpress-recovery-list':
                if request.get('scope')=='server':
                    if not context['admin']:raise AccessDenied('Administrator access required')
                    plans=[]
                    for account in self.hestia.inventory():
                        live=self.hestia.authorize(context['actor'],account['owner'])
                        plans.extend(dict(row,owner=live['owner']) for row in recovery.list(live))
                    return {'plans':sorted(plans,key=lambda row:row['created'],reverse=True)}
                return {'plans':[dict(row,owner=context['owner']) for row in recovery.list(context)]}
            if action=='wordpress-recovery-status':return recovery.status(context,request.get('plan_id'),request.get('offset',0))
            return recovery.request(context,request.get('plan_id'),action.removeprefix('wordpress-recovery-'),request.get('revision'),request.get('policy'))
        if action=='scan-targets':
            return {'sites':[{'domain':site['domain'],'suspended':site['suspended']}
                             for site in self.hestia.sites(context['owner'])]}
        if action in ('scans-status','scan-cancel'):
            from .scan_status import ScanStatus
            scans=ScanStatus(self.store,self.hestia)
            if action=='scan-cancel':return scans.cancel(context,request.get('job_id'),request.get('scope','account'))
            return scans.list(context,request.get('scope','account'),request.get('search',''),request.get('kind','all'),request.get('offset',0))
        if action in ('server-history-get','server-history-preview','server-history-save','server-history-reset'):
            if not context['admin']:raise AccessDenied('Administrator access required')
            from .server_history import ServerHistory,validate as validate_server_history
            server=ServerHistory(self.settings,self.store,self.hestia)
            if action=='server-history-save':return server.save(context,request.get('policy'),request.get('revision'))
            if action=='server-history-reset':return server.save(context,None,request.get('revision'),reset=True)
            if action=='server-history-preview':validate_server_history(request.get('policy'))
            return server.get(context,request.get('policy') if action=='server-history-preview' else None)
        if action in ('history-retention-get','history-retention-preview','history-retention-save','history-retention-reset','history-retention-permission'):
            from .history_retention import HistoryRetention
            history = HistoryRetention(self.settings,self.store,self.hestia)
            if action=='history-retention-permission':
                value=request.get('policy')
                if not isinstance(value,dict) or set(value)!={'allowed'}:raise ClamShieldError('Choose whether the hosting user can change retention')
                return history.permission(context,value['allowed'],request.get('revision'))
            if action=='history-retention-save':return history.save(context,request.get('policy'),request.get('revision'))
            if action=='history-retention-reset':return history.save(context,None,request.get('revision'),reset=True)
            if action=='history-retention-preview':
                from .history_retention import validate
                validate(request.get('policy'))
            return history.get(context,request.get('policy') if action=='history-retention-preview' else None)
        if action in ('resources-status','resources-save','website-engine-start','website-engine-stop','resources-recover'):
            if not context['admin']:raise AccessDenied('Administrator access required')
            from .resources import Resources,validate as validate_resources
            if action=='resources-status':return Resources(self.settings).status()
            payload={'policy':validate_resources(request.get('policy'))} if action=='resources-save' else {}
            task_context=self.hestia.authorize(context['actor'],context['actor'])
            task=self.store.enqueue_task(task_context,action,payload)
            self.store.audit({'actor':context['actor'],'owner':'@admin','identity':''},'resources.queued','server',{'task_id':task,'action':action})
            return {'queued':True,'task_id':task}
        if action in ('mail-protection-status','mail-protection-enable','mail-protection-disable'):
            if not context['admin']:raise AccessDenied('Administrator access required')
            task_context=self.hestia.authorize(context['actor'],context['actor'])
            if action=='mail-protection-status':
                from .mail_protection import MailProtection
                return {**self.store.mail_protection_status(task_context),'protection':MailProtection(self.settings,self.store,self.hestia).status()}
            return {'queued':True,'task_id':self.store.enqueue_task(task_context,action,{})}
        if action in ('mail-integration-status','mail-integration-enable','mail-integration-disable','mail-integration-refresh','mail-integration-recover'):
            if not context['admin']:raise AccessDenied('Administrator access required')
            from .mail_integration import MailIntegration
            if action=='mail-integration-status':return MailIntegration(self.settings,self.store,self.hestia).status()
            task_context=self.hestia.authorize(context['actor'],context['actor'])
            task=self.store.enqueue_task(task_context,action,{})
            self.store.audit(context,'mail.integration_queued','server',{'task_id':task,'operation':action})
            return {'queued':True,'task_id':task}
        if action in ('mail-adapter-status','mail-adapter-build','mail-adapter-verify'):
            if not context['admin']:
                raise AccessDenied('Administrator access required')
            from .mail_adapter import MailAdapter
            if action=='mail-adapter-status':return MailAdapter(self.settings).status()
            task_context=self.hestia.authorize(context['actor'],context['actor'])
            task=self.store.enqueue_task(task_context,action,{})
            self.store.audit(context,'mail.adapter_preparation_queued','server',{'task_id':task})
            return {'queued':True,'task_id':task}
        if action in ('spamassassin-status', 'spamassassin-catalog', 'spamassassin-save'):
            if not context['admin']:
                raise AccessDenied('Administrator access required')
            from .spamassassin import SpamAssassinControls, validate as validate_spamassassin
            controls = SpamAssassinControls(self.settings)
            if action == 'spamassassin-status':
                return controls.status()
            if action == 'spamassassin-catalog':
                return controls.catalog()
            policy = validate_spamassassin(request.get('policy'))
            task_context = self.hestia.authorize(context['actor'], context['actor'])
            task = self.store.enqueue_task(task_context, action, {'policy': policy})
            self.store.audit(context, 'spamassassin.queued', 'server', {'task_id': task})
            return {'task_id': task, 'queued': True}
        if action in ('mail-review', 'mail-review-recheck'):
            from .mail_review import MailReview
            review = MailReview(self.settings, self.store, self.hestia)
            if action == 'mail-review':return review.list(context, request.get('search', ''), request.get('offset', 0))
            return review.recheck(context, request.get('delivery_id'), request.get('stage'))
        if action in ('mail-retention-get', 'mail-retention-preview', 'mail-retention-save', 'mail-retention-history', 'mail-retention-retry'):
            from .mail_retention import MailRetention
            retention = MailRetention(self.settings, self.store, self.hestia)
            if action == 'mail-retention-history':
                return retention.history(context, request.get('search', ''), request.get('offset', 0))
            if action == 'mail-retention-retry':return retention.retry(context, request.get('delivery_id'))
            if action == 'mail-retention-save':
                return retention.save(context, request.get('domain'), request.get('mailbox', ''), request.get('policy'), request.get('revision'))
            if action == 'mail-retention-preview':
                from .mail_retention import days
                days(request.get('policy'))
            return retention.get(context, request.get('domain'), request.get('mailbox', ''),
                                 proposed=request.get('policy') if action == 'mail-retention-preview' else None)
        if action in ('mail-quarantine', 'mail-preview', 'mail-release', 'mail-delete', 'mail-quarantine-exception'):
            custody = MailCustody(self.settings, self.store, self.hestia)
            if action == 'mail-quarantine':
                return custody.list(context, request.get('search', ''), request.get('offset', 0))
            if action == 'mail-preview':
                return {'preview': custody.preview(context, request.get('delivery_id'))}
            if action == 'mail-release':
                return custody.queue_release(context, request.get('delivery_id'), request.get('note', ''))
            if action == 'mail-quarantine-exception':
                return custody.add_exception(context, request.get('delivery_id'), request.get('policy'))
            return custody.delete(context, request.get('delivery_id'))
        if action in ('mail-exception-add', 'mail-exception-remove', 'mail-exceptions-inherit'):
            operation = {'mail-exception-add': 'add', 'mail-exception-remove': 'remove', 'mail-exceptions-inherit': 'inherit'}[action]
            return MailPolicies(self.store,self.hestia).change_exception(context, request.get('domain'),
                request.get('mailbox',''), operation, request.get('policy'), entry_id=request.get('exception_id'),
                revision=request.get('revision'))
        if action=='mail-server-activity':
            if not context['admin']:raise AccessDenied('Administrator access required')
            mail=MailPolicies(self.store,self.hestia);custody=MailCustody(self.settings,self.store,self.hestia)
            accounts=[];decisions=[];quarantine=[];totals=dict(domains=0,decisions=0,quarantine=0)
            for account in self.hestia.inventory():
                live=self.hestia.authorize(context['actor'],account['owner'])
                inventory=mail.list(live);history=mail.decisions(live);stored=custody.list(live)
                counts=dict(domains=len(inventory['domains']),decisions=history['total'],quarantine=stored['total'])
                accounts.append(dict(owner=live['owner'],**counts))
                for key,value in counts.items():totals[key]+=value
                decisions.extend(dict(row,owner=live['owner']) for row in history['decisions'])
                quarantine.extend(dict(row,owner=live['owner']) for row in stored['messages'])
            return dict(accounts=accounts,totals=totals,
                        decisions=sorted(decisions,key=lambda row:row['created'],reverse=True)[:100],
                        quarantine=sorted(quarantine,key=lambda row:row['created'],reverse=True)[:100])
        if action in ('mail-account-get','mail-account-save','mail-account-reset'):
            if not context['admin']:raise AccessDenied('Administrator access required')
            mail=MailPolicies(self.store,self.hestia)
            return mail.account(context) if action=='mail-account-get' else mail.save_account(context,request.get('policy'),request.get('revision'),reset=action=='mail-account-reset')
        if action in ('mail-server-get','mail-server-save'):
            if not context['admin']:raise AccessDenied('Administrator access required')
            admin=self.hestia.authorize(context['actor'],context['actor'])
            mail=MailPolicies(self.store,self.hestia)
            return mail.save_server(admin,request.get('policy'),request.get('revision')) if action=='mail-server-save' else mail.server(admin)
        if action in ('mail-dashboard', 'mail-policy-get', 'mail-policy-save', 'mail-policy-reset',
                      'mail-permissions-save', 'mail-permissions-reset', 'mail-decisions'):
            mail = MailPolicies(self.store, self.hestia)
            if action == 'mail-dashboard':
                return mail.list(context)
            if action == 'mail-policy-get':
                return mail.get(context, request.get('domain'), request.get('mailbox', ''))
            if action in ('mail-policy-save', 'mail-policy-reset'):
                return mail.save(context, request.get('domain'), request.get('mailbox', ''),
                                 request.get('policy'), reset=action == 'mail-policy-reset', revision=request.get('revision'))
            if action in ('mail-permissions-save','mail-permissions-reset'):
                return {'permissions': mail.save_permissions(context, request.get('policy'),reset=action=='mail-permissions-reset')}
            return mail.decisions(context, request.get('search', ''), request.get('offset', 0))
        if action == 'dashboard':
            scope=request.get('scope','account')
            if scope not in ('account','server','auto'):raise AccessDenied('Invalid dashboard scope')
            server=scope=='server' or scope=='auto' and context['admin']
            if server and not context['admin']:raise AccessDenied('Administrator access required')
            return self.dashboard(context,server=server)
        if action=='rules-trial':
            return {'jobs':[RuleTrials(self.settings,self.store,self.hestia).queue(context,request.get('domain'),request.get('path',''),request.get('generation'))]}
        if action=='rules-trial-report':
            return RuleTrials(self.settings,self.store,self.hestia).report(context,request.get('job_id'),request.get('offset',0))
        if action == 'repair-preview':
            return {'plan_id': Repairs(self.settings, self.store, self.hestia).queue(context, request.get('finding_id')), 'queued': True}
        if action=='cleanup-preview':
            return {'plan_id':Repairs(self.settings,self.store,self.hestia).queue(context,request.get('finding_id'),cleanup=True),'queued':True}
        if action in ('remediation-policy-get','remediation-policy-save','remediation-history','remediation-cancel'):
            from .remediation import Remediation
            automatic=Remediation(self.settings,self.store,self.hestia)
            if action=='remediation-history':return {'actions':automatic.history(context)}
            if action=='remediation-cancel':return automatic.cancel(context,request.get('operation_id'))
            if request.get('scope','site') not in ('site','account','server'):raise AccessDenied('Invalid remediation scope')
            server=request.get('scope')=='server'
            if server and not context['admin']:raise AccessDenied('Administrator access required')
            domain=None if request.get('scope') in ('account','server') else request.get('domain')
            if domain is None and request.get('scope') not in ('account','server'):raise AccessDenied('Choose a website')
            result=automatic.save(context,request.get('policy'),domain,server) if action=='remediation-policy-save' else automatic.policy(context,domain,server)
            return {'policy':result}
        if action=='repair-backups':
            from .native_backups import NativeBackups
            return NativeBackups(self.settings,self.store,self.hestia).catalog(context,self.store.finding(context,request.get('finding_id')))
        if action=='repair-hestia-preview':
            if not isinstance(request.get('name'),str) or not request['name']:raise AccessDenied('Choose a native Hestia backup')
            return {'plan_id':Repairs(self.settings,self.store,self.hestia).queue(context,request.get('finding_id'),backup_name=request['name']),'queued':True}
        if action == 'repair-backup-preview':
            if not isinstance(request.get('path'), str) or not request['path']:
                raise AccessDenied('Choose a backup path relative to this website')
            return {'plan_id': Repairs(self.settings, self.store, self.hestia).queue(
                context, request.get('finding_id'), backup_path=request['path']), 'queued': True}
        if action == 'repair-plan':
            return {'repair': Repairs(self.settings, self.store, self.hestia).get(context, request.get('plan_id'))}
        if action in ('repair-apply', 'repair-undo', 'repair-recover'):
            repairs = Repairs(self.settings, self.store, self.hestia)
            method = {'repair-apply': repairs.apply, 'repair-undo': repairs.undo, 'repair-recover': repairs.recover}[action]
            return method(context, request.get('plan_id'))
        if action == 'wordpress-report':
            return WordPress(self.settings, self.store, self.hestia).report(context, request.get('job_id'), request.get('offset', 0))
        if action == 'wordpress-scan':
            site = next((s for s in self.hestia.sites(context['owner'])
                         if s['domain'] == request.get('domain') and not s['suspended']), None)
            if site is None:
                raise AccessDenied('Site unavailable')
            target = relative_path(request.get('path', ''))
            job_id = self.store.enqueue(context, site, target, source='wordpress-integrity', generation=self.generation())
            return {'jobs': [job_id]}
        if action == 'scan':
            domain = request.get('domain')
            scope = request.get('scope', 'site')
            if scope not in ('site', 'account', 'server'):
                raise AccessDenied('Invalid scan scope')
            if scope == 'server' and not context['admin']:
                raise AccessDenied('Administrator access required')
            targets = []
            if scope == 'server':
                for account in self.hestia.inventory():
                    if account['suspended']:
                        continue
                    owner_context = self.hestia.authorize(context['actor'], account['owner'])
                    targets.extend((owner_context, s) for s in account['sites'] if not s['suspended'])
            else:
                sites = self.hestia.sites(context['owner'])
                if scope == 'site':
                    sites = [site for site in sites if site['domain'] == domain]
                    if not sites:
                        raise AccessDenied('Site is unavailable for this account')
                targets = [(context, site) for site in sites if not site['suspended']]
            if not targets:
                raise ClamShieldError('No active websites were selected')
            target = relative_path(request.get('path', ''))
            if scope != 'site' and target:
                raise AccessDenied('Choose one site when scanning a relative path')
            jobs = [self.store.enqueue(c, site, target, generation=self.generation()) for c, site in targets]
            return {'jobs': jobs}
        if action == 'cancel':
            self.store.cancel(context, request.get('job_id'))
            return {'cancel_requested': True}
        if action == 'quarantine':
            operation = Quarantine(self.settings, self.store, self.hestia).capture(context, request.get('finding_id'))
            return {'operation_id': operation}
        if action == 'restore':
            Quarantine(self.settings, self.store, self.hestia).restore(context, request.get('operation_id'))
            return {'restored': True}
        if action=='quarantine-recover':
            row=Quarantine(self.settings,self.store,self.hestia).recover(context,request.get('operation_id'))
            return {'operation_id':row['id'],'status':row['status']}
        if action=='rules-status':
            if not context['admin']:raise AccessDenied('Administrator access required')
            task_context=self.hestia.authorize(context['actor'],context['actor'])
            active=Rules(self.settings).status()
            return {**self.store.rule_install_status(task_context),
                    'active':{key:active[key] for key in ('configured','profile','version','enabled','rules','generation','created') if key in active}}
        if action in ('rules-install','rules-update','rules-php-hosting','rules-web-hosting','rules-rollback','rules-build','rules-activate','rules-source-save',
                      'rules-source-toggle','rules-source-review','rules-source-fetch','rules-rule-toggle','rules-catalog'):
            if not context['admin']:
                raise AccessDenied('Administrator access required')
            manager=RuleManager(self.settings)
            if action=='rules-catalog':return manager.catalog(request.get('generation'),request.get('search',''),request.get('offset',0))
            task_context=self.hestia.authorize(context['actor'],context['actor'])
            task_action,payload=action,{}
            if action in ('rules-install','rules-update'):
                if request.get('profile','core') not in ('core','extended','full'):raise ClamShieldError('Invalid Forge profile')
                payload={'profile':request.get('profile','core'),'release':request.get('release')}
            elif action=='rules-source-save':
                saved=manager.save_source(request.get('source'))
                task_action='rules-fetch' if saved['fetch_required'] else 'rules-build'
                payload={'source_id':saved['source_id']} if saved['fetch_required'] else {'revision':saved['revision']}
            elif action in ('rules-source-toggle','rules-rule-toggle'):
                saved=manager.toggle_source(request.get('source_id'),request.get('enabled')) if action=='rules-source-toggle' else manager.toggle_rule(request.get('rule_id'),request.get('enabled'),request.get('cascade',False))
                task_action,payload='rules-build',{'revision':saved['revision']}
            elif action=='rules-source-fetch':task_action,payload='rules-fetch',{'source_id':request.get('source_id')}
            elif action=='rules-source-review':
                saved=manager.review_mode(request.get('source_id'),request.get('enabled'))
                task_action,payload='rules-build',{'revision':saved['revision']}
            elif action=='rules-activate':payload={'generation':request.get('generation')}
            elif action=='rules-build':payload={'revision':manager.status()['revision']}
            self.store.audit(context,action,'rules',{'queued_action':task_action})
            return {'task_id':self.store.enqueue_task(task_context,task_action,payload),'queued':True}
        if action in ('policy-defaults-get','policy-defaults-save','policy-defaults-reset'):
            server=request.get('scope')=='server'
            if server and not context['admin']:raise AccessDenied('Administrator access required')
            scheduler=Scheduler(self.settings,self.store,self.hestia)
            return {'policy':scheduler.defaults(context,server) if action=='policy-defaults-get' else scheduler.save_defaults(context,request.get('policy'),server,reset=action=='policy-defaults-reset')}
        if action in ('policy-save','policy-reset'):
            site = next((s for s in self.hestia.sites(context['owner']) if s['domain'] == request.get('domain')), None)
            if site is None:
                raise AccessDenied('Site unavailable')
            scheduler=Scheduler(self.settings,self.store,self.hestia)
            return {'policy':scheduler.reset(context,site) if action=='policy-reset' else scheduler.save(context,site,request.get('policy'))}
        if action in ('providers-save', 'signature-local-save', 'signature-local-delete', 'signatures-update', 'signatures-activate', 'signatures-rollback'):
            if not context['admin']:
                raise AccessDenied('Administrator access required')
            providers = Providers(self.settings)
            if action == 'providers-save':
                result = providers.save(request.get('providers'))
                self.store.audit(context, 'providers.saved', 'server', {'configured': True})
                return {'providers': result}
            if action == 'signature-local-save':
                result = providers.save_local(request.get('name'), request.get('content'))
                self.store.audit(context, 'signatures.local_saved', result['name'], {})
                return result
            if action == 'signature-local-delete':
                result = providers.delete_local(request.get('name'))
                self.store.audit(context, 'signatures.local_deleted', result['name'], {})
                return result
            task_context = self.hestia.authorize(context['actor'], context['actor'])
            provider = request.get('provider', 'all')
            if provider not in ('all', 'official', 'securiteinfo', 'sanesecurity', 'local'):
                raise ClamShieldError('Unknown signature provider')
            task_id = self.store.enqueue_task(task_context, action, {'provider': provider})
            return {'task_id': task_id, 'queued': True}
        if action == 'exception-add':
            exception_id = Exceptions(self.store).add(context, request.get('finding_id'),
                request.get('kind', 'file'), request.get('note', ''), request.get('expires'), request.get('whole_site', False))
            return {'exception_id': exception_id}
        if action == 'exception-remove':
            Exceptions(self.store).remove(context, request.get('exception_id'))
            return {'removed': True}
        if action == 'notification-read':
            self.store.read_notification(context, request.get('notification_id'))
            return {'read': True}
        raise AccessDenied('Unsupported operation')

    def account_dashboard(self,context,sites=None):
        sites=self.hestia.sites(context['owner']) if sites is None else sites
        scheduler=Scheduler(self.settings,self.store,self.hestia)
        sites=[site|{'policy':scheduler.policy(context,site)} for site in sites]
        data=dict(sites=sites,summary=self.store.dashboard_counts(context),jobs=self.store.list_jobs(context),
                  findings=self.store.list_findings(context),quarantine=Quarantine(self.settings,self.store,self.hestia).list(context),
                  history=self.store.history(context),exceptions=Exceptions(self.store).list(context),
                  notifications=self.store.notifications(context),wordpress=WordPress(self.settings,self.store,self.hestia).list(context),
                  repairs=Repairs(self.settings,self.store,self.hestia).list(context),
                  rule_trials=RuleTrials(self.settings,self.store,self.hestia).list(context))
        from .website_permissions import WebsitePermissions
        from .remediation import Remediation
        data['website_permissions']=WebsitePermissions(self.settings,self.store,self.hestia).get(context)
        remediation=Remediation(self.settings,self.store,self.hestia)
        data['remediation_policy']=remediation.policy(context)
        data['remediation_history']=remediation.history(context)
        remediation.site_policies(context,sites)
        from .website_availability import WebsiteAvailability
        WebsiteAvailability(context,sites).annotate(data)
        for key in ('jobs','findings','quarantine','history','exceptions','notifications','wordpress','repairs','rule_trials','remediation_history'):
            data[key]=[dict(row,owner=row.get('owner',context['owner']),identity=row.get('identity',context['identity'])) for row in data[key]]
        return data

    def dashboard(self,context,*,server=False):
        inventory=self.hestia.inventory() if context['admin'] else None
        if server:
            context=self.hestia.authorize(context['actor'],context['actor'])
            if not context['admin']:raise AccessDenied('Administrator access required')
            keys=('sites','jobs','findings','quarantine','history','exceptions','notifications','wordpress','repairs','rule_trials','remediation_history')
            data={key:[] for key in keys};data['summary']=dict(open_findings=0,active_scans=0,quarantined=0)
            for account in inventory:
                live=dict(context,owner=account['owner'],identity=account['identity'])
                account_data=self.account_dashboard(live,account['sites'])
                for key in keys:data[key].extend(account_data[key])
                for key,value in account_data['summary'].items():data['summary'][key]+=value
            data['preview_limits']={}
            for key in keys[1:]:
                unique={}
                for row in data[key]:unique[(row['owner'],row['identity'],str(row.get('id',row.get('job_id',json.dumps(row,sort_keys=True)))))]=row
                rows=sorted(unique.values(),key=lambda row:row.get('created',0),reverse=True)
                if len(rows)>500:data['preview_limits'][key]=500
                data[key]=rows[:500]
            from .website_permissions import WebsitePermissions
            from .remediation import Remediation
            data['website_permissions']=WebsitePermissions(self.settings,self.store,self.hestia).get(context,server=True)
            data['remediation_policy']=Remediation(self.settings,self.store,self.hestia).policy(context,server=True)
        else:data=self.account_dashboard(context)
        context=dict(context,view_scope='server' if server else 'account')
        data.update(version=__version__,context=context,engines=self.engine_status(),rules=Rules(self.settings).status())
        from .readiness import public_status
        data['website_readiness']=public_status(Health(self.settings,self.store).status().get('website-coverage'),time.time())
        data['rule_candidate']=RuleManager(self.settings).candidate()
        data['schedule_defaults']=Scheduler(self.settings,self.store,self.hestia).defaults(context,server=server)
        if context['admin']:
            from .resources import Resources
            from .spamassassin import SpamAssassinControls
            from .mail_adapter import MailAdapter
            from .mail_integration import MailIntegration
            data.update(resources=Resources(self.settings).status(),rule_manager=RuleManager(self.settings).status(),
                        providers=Providers(self.settings).public(),health=Health(self.settings,self.store).status(),
                        signatures=Signatures(self.settings).status(),spamassassin=SpamAssassinControls(self.settings).status(),
                        mail_adapter=MailAdapter(self.settings).status(),mail_integration=MailIntegration(self.settings,self.store,self.hestia).status(),
                        maintenance=self.store.list_tasks(self.hestia.authorize(context['actor'],context['actor'])),
                        accounts=[dict(owner=a['owner'],role=a['role'],suspended=a['suspended'],sites=len(a['sites'])) for a in inventory])
        return data

    def generation(self):
        return current_generation(self.settings)

    def engine_status(self):
        result = {}
        for engine in (ClamAV(self.settings.clamd_socket),
                       Yara(self.settings.yara_binary, self.settings.rules)):
            try:
                result[engine.name] = {'available': True, 'version': engine.version()}
            except ClamShieldError as exc:
                result[engine.name] = {'available': False, 'error': str(exc)}
        result['yara']['rules_available'] = self.settings.rules.is_file()
        return result
