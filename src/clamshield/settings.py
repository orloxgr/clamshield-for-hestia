from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    state: Path = Path('/var/lib/clamshield')
    hestia: Path = Path('/usr/local/hestia')
    clamd_socket: Path = Path('/run/clamshield/clamd.sock')
    yara_binary: str = '/usr/bin/yara'
    rules: Path = Path('/var/lib/clamshield/rules/current/rules.yarac')
    max_file_bytes: int = 50 * 1024 * 1024
    engine_timeout: int = 45

    @property
    def database(self):
        return self.state / 'state.sqlite3'

    @property
    def snapshots(self):
        return self.state / 'snapshots'

    @property
    def quarantine(self):
        return self.state / 'quarantine'

    @property
    def signatures(self):
        return self.state.with_name(self.state.name + '-signatures')

    @property
    def provider_cache(self):
        return self.state.with_name(self.state.name + '-cache')

    @property
    def mail_adapters(self):
        return self.state.with_name(self.state.name + '-mail-adapters')

    def prepare(self):
        for path in (self.state, self.snapshots, self.quarantine):
            if path.is_symlink():
                raise ValueError('State directory cannot be a symbolic link')
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.chmod(0o700)
