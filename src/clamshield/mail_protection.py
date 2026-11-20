"""One user-facing activation, backed by the existing verified mail lifecycle."""
from .errors import EngineError
from .mail_integration import MailIntegration
from .mail_policy import MailPolicies
from .mail_service import configuration, transport_active
from .rule_manager import RuleManager
from .signatures import Signatures


class MailProtection:
    def __init__(self,settings,store,hestia):
        self.settings,self.store,self.hestia=settings,store,hestia

    def enable(self,context,progress=lambda _phase:None):
        progress('signatures')
        signatures=Signatures(self.settings)
        if signatures.manifest() is None:signatures.update('all')
        if configuration()['yara_enabled'] and not self.settings.rules.is_file():
            progress('rules');RuleManager(self.settings).install('core')
        progress('preparing')
        # This already builds/verifies the adapter, configures initial owned
        # SpamAssassin settings and starts/probes the isolated scanner services.
        result=MailIntegration(self.settings,self.store,self.hestia).enable()
        progress('verifying')
        if not result.get('enabled') or not transport_active():
            raise EngineError('Mail protection did not establish a verified connection')
        progress('policies')
        MailPolicies(self.store,self.hestia).enable_server_defaults(context)
        if not transport_active():raise EngineError('Mail connection changed before activation completed')
        return {'enabled':True,'defaults_enabled':True}

    def disable(self):
        # Keep all policies/custody; the lifecycle drains and detaches safely.
        return MailIntegration(self.settings,self.store,self.hestia).disable()

    def status(self):
        integration=MailIntegration(self.settings,self.store,self.hestia).status()
        defaults=bool(MailPolicies(self.store,self.hestia).server_defaults().get('enabled',False))
        connected=transport_active()
        return dict(enabled=defaults and connected and integration['phase']=='active' and not integration.get('transition'),
                    connected=connected,defaults_enabled=defaults,
                    phase=integration['phase'],transition=integration.get('transition'),error=integration.get('error'))
