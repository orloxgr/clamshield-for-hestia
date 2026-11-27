#!/usr/bin/python3
"""Install addon-owned resources; Ubuntu engines remain managed by APT."""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

SOURCE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE / 'src'))
from clamshield import __version__
from clamshield import installer_output as progress

OWNER = 'clamshield'
PACKAGES = ('clamav', 'clamav-daemon', 'yara', 'python3-plyara', 'python3-pymysql', 'gnupg', 'rsync', 'gcc', 'libc6-dev')


def owned_directory(path, mode=0o755):
    if path.exists() or path.is_symlink():
        marker = path / '.clamshield-owner'
        if path.is_symlink() or not path.is_dir() or not marker.is_file() or marker.is_symlink() or marker.read_text() != OWNER + '\n':
            raise RuntimeError('Refusing an unmanaged directory: ' + str(path))
    else:
        path.mkdir(mode=mode)
        (path / '.clamshield-owner').write_text(OWNER + '\n')
    path.chmod(mode)


def write_owned(path, content, mode=0o644):
    if path.is_symlink() or path.parent.resolve() != path.parent:
        raise RuntimeError('Refusing a symlink integration: ' + str(path))
    if path.exists() and 'Managed by clamshield' not in path.read_text():
        raise RuntimeError('Refusing an unmanaged integration: ' + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.clamshield-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def extension_directory(path):
    """Create a missing shared extension container without claiming its ownership."""
    if path.is_symlink() or path.parent.resolve() != path.parent:
        raise RuntimeError('Refusing a symlink extension container: ' + str(path))
    if path.exists():
        if not path.is_dir():
            raise RuntimeError('Extension container is not a directory: ' + str(path))
    else:
        path.mkdir(mode=0o755)


def run(*args):
    with progress.command(args):
        return subprocess.run(args, check=True, capture_output=True,
            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8', 'DEBIAN_FRONTEND': 'noninteractive'})


def ensure_packages():
    """Install missing distro dependencies without upgrading installed engines."""
    progress.stage('Checking installed Ubuntu dependencies')
    result = subprocess.run(['/usr/bin/dpkg-query', '-W',
        '-f=${binary:Package}\t${db:Status-Status}\n', *PACKAGES],
        capture_output=True, text=True)
    if result.returncode not in (0, 1):
        raise RuntimeError('Could not inspect Ubuntu package dependencies')
    installed = set()
    for line in result.stdout.splitlines():
        name, separator, status = line.partition('\t')
        if separator and status == 'installed':
            installed.add(name.split(':', 1)[0])
    missing = [name for name in PACKAGES if name not in installed]
    if missing:
        progress.stage('Installing missing Ubuntu dependencies: ' + ', '.join(missing))
        run('/usr/bin/apt-get', 'update', '-o', 'APT::Update::Error-Mode=any')
        run('/usr/bin/apt-get', 'install', '-y', '--no-install-recommends', '--no-remove', *missing)
    else:
        progress.stage('All Ubuntu dependencies are already installed; skipping APT')
    return missing


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--install-packages', action='store_true',
                        help='Compatibility option; missing Ubuntu dependencies are installed automatically')
    parser.add_argument('--json', action='store_true',
                        help='Write the final result as JSON to stdout; progress and diagnostics stay on stderr')
    args = parser.parse_args(argv)
    return progress.execute(lambda: perform(args), version=__version__, json_output=args.json)


def validate_source():
    for name in ('spamassassin-config.pl', 'spamassassin-report.pm'):
        helper = SOURCE / 'tools' / name
        if not helper.is_file() or helper.is_symlink():
            raise RuntimeError('ClamShield checkout is incomplete: tools/' + name + ' is missing; update the checkout and retry')


def perform(args):
    if os.geteuid() != 0 or os.environ.get('SUDO_USER') == 'hestiaweb':
        raise PermissionError('Install from an administrator root shell')
    validate_source()
    sys.path.insert(0,str(SOURCE/'src'))
    from clamshield.installation import Installation
    from clamshield.settings import Settings
    lifecycle=Installation(Settings())
    progress.stage('Acquiring installation priority')
    with lifecycle.update(SOURCE,report=progress.stage):
        progress.stage('Installation locks acquired')
        return install(args,lifecycle)


def install(args,lifecycle):
    progress.stage('[1/10] Checking Hestia and saved scanner settings')
    hestia = Path('/usr/local/hestia')
    if not (hestia / 'web/inc/main.php').is_file():
        raise RuntimeError('Hestia is required')
    # Reject unsafe saved startup intent before publishing code or starting timers.
    sys.path.insert(0,str(SOURCE/'src'))
    from clamshield.settings import Settings
    from clamshield.website_policy import website_policy
    policy = website_policy(Settings())
    packages = ensure_packages()
    import importlib.util
    if importlib.util.find_spec('plyara') is None:
        raise RuntimeError('Ubuntu python3-plyara is still unavailable after dependency installation')
    for binary in ('/usr/bin/yara', '/usr/bin/yarac', '/usr/sbin/clamd', '/usr/bin/sigtool'):
        if not Path(binary).is_file():
            raise RuntimeError('Ubuntu engine binary is unavailable after dependency installation: ' + binary)
    # Validate PHP before publishing a new code generation.
    templates = sorted((SOURCE / 'panel').rglob('*.php'))
    progress.stage('[2/10] Validating ' + str(len(templates)) + ' Hestia PHP templates')
    for path in templates:
        run(str(hestia / 'php/bin/php'), '-l', str(path))
    progress.stage('[3/10] Recovering any interrupted scanner configuration')
    lifecycle.recover_configuration()
    lifecycle.recover_mail_configuration()
    if lifecycle.settings.database.exists():lifecycle.recover_operations()
    progress.stage('[4/10] Publishing application code and native Hestia integration')
    extension_directory(hestia / 'web/plugins')
    extension_directory(Path('/etc/systemd/system/exim4.service.d'))
    releases = Path('/opt/clamshield.releases')
    owned_directory(releases)
    target = Path('/opt/clamshield')
    existing = target.exists() or target.is_symlink()
    from clamshield.providers import Providers
    Providers(lifecycle.settings).initialize(existing=existing or lifecycle.settings.database.exists() or lifecycle.manifest.exists())
    if target.exists() or target.is_symlink():
        if not target.is_symlink() or target.resolve().parent != releases:
            raise RuntimeError('Refusing an unmanaged installation')
    release = Path(tempfile.mkdtemp(prefix='release-', dir=releases))
    release.chmod(0o755)
    for folder in ('src', 'panel', 'config', 'systemd', 'tools', 'docs', 'native'):
        shutil.copytree(SOURCE / folder, release / folder,
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc', 'lab*'))
    shutil.copyfile(SOURCE / 'entry.py', release / 'entry.py')
    (release / '.clamshield-owner').write_text(OWNER + '\n')
    for directory, _, files in os.walk(release):
        os.chmod(directory, 0o755)
        for filename in files:
            path = Path(directory) / filename
            path.chmod(0o644)
            with path.open('rb') as stream:
                os.fsync(stream.fileno())
    link = target.with_name('.clamshield-next')
    if link.exists() or link.is_symlink():
        if not link.is_symlink():raise SystemExit('Unexpected install staging pointer')
        lifecycle.code(link.resolve())
        link.unlink()
    link.symlink_to(release)
    os.replace(link, target)
    route = hestia / 'web/plugins/clamshield'
    owned_directory(route)
    write_owned(route / 'index.php', (release / 'panel/index.php').read_text())
    write_owned(hestia / 'web/js/custom_scripts/clamshield.js', (release / 'panel/menu.js').read_text())
    write_owned(hestia / 'bin/v-clamshield',
                '#!/bin/sh\n# Managed by clamshield\nexec /usr/bin/python3 -I -B /opt/clamshield/entry.py "$@"\n', 0o755)
    progress.stage('[5/10] Preserving configuration and loading owned AppArmor profiles')
    config = Path('/etc/clamshield')
    owned_directory(config)
    # Preserve administrator settings across code updates.
    if not (config / 'clamd.conf').exists():
        write_owned(config / 'clamd.conf', (release / 'config/clamd.conf').read_text())
    for name in ('mail-clamd.conf','mail.json','spamd.env'):
        if not (config/name).exists():write_owned(config/name,(release/'config'/name).read_text(),0o600 if name in ('mail.json','spamd.env') else 0o644)
    owned_directory(config / 'spamassassin')
    if not (config / 'spamassassin/active.cf').exists():
        write_owned(config / 'spamassassin/active.cf', (release / 'config/spamassassin.cf').read_text(), 0o644)
    from clamshield.spamassassin import SpamAssassinControls
    SpamAssassinControls(Settings()).upgrade_safety()
    if Path('/sys/module/apparmor/parameters/enabled').exists() and Path('/sys/module/apparmor/parameters/enabled').read_text().strip() == 'Y':
        for profile in ('clamshield-clamd', 'clamshield-freshclam', 'clamshield-mail-clamd'):
            apparmor = Path('/etc/apparmor.d') / profile
            write_owned(apparmor, (release / 'config' / (profile + '.apparmor')).read_text())
            run('/usr/sbin/apparmor_parser', '-r', str(apparmor))
    for folder in ('/var/lib/clamshield-signatures', '/var/lib/clamshield-cache', '/var/lib/clamshield-mail-adapters'):
        owned_directory(Path(folder))
    owned_directory(Path('/opt/clamshield-mail'))
    progress.stage('[6/10] Installing owned services and retaining resource limits')
    for unit in (release / 'systemd').iterdir():
        write_owned(Path('/etc/systemd/system') / unit.name, unit.read_text())
    for unit in ('clamshield-worker','clamshield-clamd','clamshield-mail','clamshield-mail-clamd','clamshield-mail-spamd','clamshield-maintenance'):
        extension_directory(Path('/etc/systemd/system')/(unit+'.service.d'))
    from clamshield.resources import Resources,render
    configured=Resources(Settings()).configured()
    if configured:
        resources=Resources(Settings())
        for key,row in configured['policy'].items():
            path=resources.config_path(key)
            if (path.exists() or path.is_symlink()) and resources.snapshot(path,limits=True)['text']!=render(row):raise RuntimeError('Resource override differs from retained policy')
            write_owned(path,render(row))
    progress.stage('[7/10] Recording owned integration files and reloading systemd')
    lifecycle.register(release)
    run('/usr/bin/systemctl', 'daemon-reload')
    progress.stage('[8/10] Checking scanning-data compatibility and archive coverage')
    lifecycle.migrate_signatures()
    lifecycle.migrate_website_coverage()
    from clamshield.native_integration import NativeIntegration
    progress.stage('Connecting website and email scanning to native ClamAV')
    NativeIntegration(Settings()).connect()
    run('/usr/bin/systemctl','restart','clamshield-native-gate.service')
    from clamshield.mail_runtime import state as mail_runtime_state
    retained_mail=mail_runtime_state(Settings())
    if retained_mail and retained_mail['phase']=='active':
        from clamshield.mail_integration import MailIntegration
        from clamshield.store import Store
        from clamshield.hestia import Hestia
        progress.stage('Refreshing the active email broker for the shared native engine')
        MailIntegration(Settings(),Store(Settings().database),Hestia(Settings().hestia)).refresh()
    from clamshield.rule_manager import RuleManager
    progress.stage('Checking active YARA sources against the supported selection')
    RuleManager(Settings()).rebuild_supported()
    progress.stage('[9/10] Enabling the five ClamShield background timers')
    run('/usr/bin/systemctl', 'enable', '--now', 'clamshield-worker.timer')
    run('/usr/bin/systemctl', 'enable', '--now', 'clamshield-monitor.timer')
    run('/usr/bin/systemctl', 'enable', '--now', 'clamshield-maintenance.timer')
    run('/usr/bin/systemctl', 'enable', '--now', 'clamshield-recovery.timer')
    run('/usr/bin/systemctl', 'enable', '--now', 'clamshield-notifications.timer')
    progress.stage('[10/10] Restoring the saved website-engine choice and finalizing')
    startup = lifecycle.restore_website()
    lifecycle.finish_install()
    ready = startup.get('verified', False)
    website = ('Ready; saved Start choice verified' if ready else
               'Saved Stop choice retained' if policy is not None and not policy['enabled'] else
               'Configure scanning data and start from the panel')
    return {'installed': True, 'mode': 'Update / reinstall' if existing else 'New installation',
            'route': '/plugins/clamshield/', 'code_generation': release.name,
            'hestia_files_modified': False, 'native_clamav_conffile_managed': True, 'dependencies_installed': packages,
            'php_templates_checked': len(templates), 'timers_enabled': 4,
            'website_engine': website,
            'next_steps': ([] if ready or (policy is not None and not policy['enabled']) else
                ['Open Hestia > Plugins > ClamShield.',
                 'Select and update Signature providers; stage and activate YARA rules.',
                 'Review Resources, then choose Start website ClamAV.',
                 'Configure and enable Mail integration separately if required.'])}


if __name__ == '__main__':
    raise SystemExit(main())
