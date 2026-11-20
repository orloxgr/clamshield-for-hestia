"""Small durable writes to addon-owned paths."""
import json
import os
from pathlib import Path
import tempfile


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write(path, content, mode=0o600):
    path = Path(path)
    if path.is_symlink() or path.parent.resolve() != path.parent:
        raise ValueError('Unexpected addon storage path')
    fd, name = tempfile.mkstemp(prefix='.clamshield-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content.encode() if isinstance(content, str) else content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
        sync_directory(path.parent)
    finally:
        Path(name).unlink(missing_ok=True)


def write_json(path, value, mode=0o600):
    write(path, json.dumps(value, sort_keys=True, separators=(',', ':')), mode)
