#!/usr/bin/python3
"""Install addon-owned resources; Ubuntu engines remain managed by APT."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

SOURCE = Path(__file__).resolve().parents[1]
OWNER = 'clamshield'
PACKAGES = ('clamav', 'clamav-daemon', 'yara', 'python3-plyara', 'gnupg', 'rsync', 'gcc', 'libc6-dev')


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
    subprocess.run(args, check=True, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8',
                                        'DEBIAN_FRONTEND': 'noninteractive'})


def ensure_packages():
    """Install missing distro dependencies without upgrading installed engines."""
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
        print('Installing missing Ubuntu dependencies: ' + ', '.join(missing), file=sys.stderr, flush=True)
        run('/usr/bin/apt-get', 'update', '-o', 'APT::Update::Error-Mode=any')
        run('/usr/bin/apt-get', 'install', '-y', '--no-install-recommends', '--no-remove', *missing)
    return missing


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--install-packages', action='store_true',
                        help='Compatibility option; missing Ubuntu dependencies are installed automatically')
    args = parser.parse_args()
    if os.geteuid() != 0 or os.environ.get('SUDO_USER') == 'hestiaweb':
        raise SystemExit('Install from an administrator root shell')
    sys.path.insert(0,str(SOURCE/'src'))
    from clamshield.installation import Installation
    from clamshield.settings import Settings
    lifecycle=Installation(Settings())
    with lifecycle.locked(exclusive=True,control=True),lifecycle.locked(exclusive=True):
        install(args,lifecycle)


def install(args,lifecycle):
    hestia = Path('/usr/local/hestia')
    if not (hestia / 'web/inc/main.php').is_file():
        raise SystemExit('Hestia is required')
    # Reject unsafe saved startup intent before publishing code or starting timers.
    sys.path.insert(0,str(SOURCE/'src'))
    from clamshield.settings import Settings
    from clamshield.website_policy import website_policy
    website_policy(Settings())
    ensure_packages()
    import importlib.util
    if importlib.util.find_spec('plyara') is None:
        raise SystemExit('Install Ubuntu python3-plyara first, or use --install-packages')
    for binary in ('/usr/bin/yara', '/usr/bin/yarac', '/usr/sbin/clamd', '/usr/bin/sigtool'):
        if not Path(binary).is_file():
            raise SystemExit('Install Ubuntu engine packages first, or use --install-packages')
    # Validate PHP before publishing a new code generation.
    for path in (SOURCE / 'panel').glob('*.php'):
        run(str(hestia / 'php/bin/php'), '-l', str(path))
    lifecycle.recover_configuration()
    lifecycle.begin_install(SOURCE)
    extension_directory(hestia / 'web/plugins')
    extension_directory(Path('/etc/systemd/system/exim4.service.d'))
    releases = Path('/opt/clamshield.releases')
    owned_directory(releases)
    target = Path('/opt/clamshield')
    if target.exists() or target.is_symlink():
        if not target.is_symlink() or target.resolve().parent != releases:
            raise SystemExit('Refusing an unmanaged installation')
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
    if Path('/sys/module/apparmor/parameters/enabled').exists() and Path('/sys/module/apparmor/parameters/enabled').read_text().strip() == 'Y':
        for profile in ('clamshield-clamd', 'clamshield-freshclam', 'clamshield-mail-clamd'):
            apparmor = Path('/etc/apparmor.d') / profile
            write_owned(apparmor, (release / 'config' / (profile + '.apparmor')).read_text())
            run('/usr/sbin/apparmor_parser', '-r', str(apparmor))
    for folder in ('/var/lib/clamshield-signatures', '/var/lib/clamshield-cache', '/var/lib/clamshield-mail-adapters'):
        owned_directory(Path(folder))
    owned_directory(Path('/opt/clamshield-mail'))
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
    lifecycle.register(release)
    run('/usr/bin/systemctl', 'daemon-reload')
    lifecycle.migrate_signatures()
    lifecycle.migrate_website_coverage()
    run('/usr/bin/systemctl', 'enable', '--now', 'clamshield-worker.timer')
    run('/usr/bin/systemctl', 'enable', '--now', 'clamshield-monitor.timer')
    run('/usr/bin/systemctl', 'enable', '--now', 'clamshield-maintenance.timer')
    run('/usr/bin/systemctl', 'enable', '--now', 'clamshield-recovery.timer')
    lifecycle.restore_website()
    lifecycle.finish_install()
    print(json.dumps({'installed': True, 'route': '/plugins/clamshield/',
                      'code_generation': release.name, 'vendor_files_modified': False}))


if __name__ == '__main__':
    main()
