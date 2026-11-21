"""Cancellation and resume of the explicitly enabled initial monitoring scan."""
import time

from .errors import AccessDenied


class InitialMonitoring:
    @staticmethod
    def scope(context,site):
        if (site['owner'],site['identity'])!=(context['owner'],context['identity']):
            raise AccessDenied('Website monitoring scope changed')
        return context['owner'],context['identity'],site['domain'],site['root']

    @classmethod
    def paused(cls,db,context,site):
        scope=cls.scope(context,site)
        row=db.execute('SELECT paused FROM monitoring_pauses WHERE owner=? AND identity=? AND domain=? AND root=?',scope).fetchone()
        if row is not None:return bool(row['paused'])
        # Do not replace an earlier cancelled post-update scan with a monitoring
        # baseline when no observations exist. Explicit Resume overrides this.
        return db.execute("""SELECT 1 FROM jobs WHERE owner=? AND identity=? AND domain=? AND root=?
          AND target='' AND source IN ('watch-initial','signature-update') AND cancel_requested=1 LIMIT 1""",scope).fetchone() is not None

    @classmethod
    def set(cls,db,context,site,paused):
        db.execute("""INSERT INTO monitoring_pauses VALUES(?,?,?,?,?,?)
          ON CONFLICT(owner,identity,domain,root) DO UPDATE SET paused=excluded.paused,updated=excluded.updated""",
          (*cls.scope(context,site),int(paused),time.time()))

    @classmethod
    def status(cls,store,context,site):
        with store.connection() as db:return cls.paused(db,context,site)

    @classmethod
    def resume(cls,store,hestia,context,site):
        live=hestia.authorize(context['actor'],context['owner'])
        if live['identity']!=context['identity']:raise AccessDenied('Hosting account changed')
        current=next((s for s in hestia.sites(live['owner']) if s['domain']==site['domain']),None)
        if not current or current['root']!=site['root'] or current['suspended']:
            raise AccessDenied('Website changed; refresh before resuming monitoring')
        with store.connection(True) as db:
            cls.set(db,live,current,False)
            store.audit(live,'scan.monitoring_resumed',current['domain'],{},db)
        return {'initial_monitoring_paused':False}
