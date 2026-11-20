"""Descriptor-based Linux file access: no symlinks, device files or path races."""
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path, PurePosixPath
import stat
import tempfile

from .errors import AccessDenied, Conflict


def relative_path(value, allow_root=True):
    if not isinstance(value, str) or '\0' in value or '\\' in value:
        raise AccessDenied('Invalid relative path')
    path = PurePosixPath(value)
    if path.is_absolute() or '..' in path.parts or (not allow_root and not path.parts):
        raise AccessDenied('Path must remain inside the selected website')
    return str(path) if path.parts else ''


@contextmanager
def directory(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise AccessDenied('Invalid document root')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


@contextmanager
def parent(root, relative):
    relative = relative_path(relative, allow_root=False)
    parts = PurePosixPath(relative).parts
    with directory(root) as root_fd:
        fd = os.dup(root_fd)
        try:
            for part in parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            yield fd, parts[-1]
        finally:
            os.close(fd)


@contextmanager
def file_handle(root, relative):
    with parent(root, relative) as (parent_fd, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise AccessDenied('Only regular files can be scanned')
            yield fd, info
        finally:
            os.close(fd)


def attributes(info):
    return {'device': info.st_dev, 'inode': info.st_ino, 'size': info.st_size,
            'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns,
            'uid': info.st_uid, 'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode),
            'links': info.st_nlink}


def hash_fd(fd):
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while chunk := os.read(fd, 1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def absence(root, relative):
    """Bind a missing path to its nearest existing directory, without links."""
    relative = relative_path(relative, allow_root=False)
    parts = PurePosixPath(relative).parts
    with directory(root) as root_fd:
        fd = os.dup(root_fd)
        try:
            for index, part in enumerate(parts):
                try:
                    os.stat(part, dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    info = os.fstat(fd)
                    anchor_path = '/'.join(parts[:index])
                    with directory(Path(root)/anchor_path) as live:
                        actual = os.fstat(live)
                        if (actual.st_dev, actual.st_ino) != (info.st_dev, info.st_ino):
                            raise Conflict('Missing-file parent changed during inspection')
                    return dict(missing=True, sha256=None, device=info.st_dev,
                                anchor_path=anchor_path, anchor={'device': info.st_dev, 'inode': info.st_ino},
                                suffix='/'.join(parts[index:]))
                if index == len(parts)-1:
                    raise Conflict('The missing-file target now exists; scan again')
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd); fd = child
        finally:
            os.close(fd)


@contextmanager
def snapshot(root, relative, destination, maximum):
    with file_handle(root, relative) as (fd, before):
        if before.st_size > maximum:
            raise Conflict('File exceeds the configured scan size limit')
        digest = hashlib.sha256()
        total = 0
        # An anonymous file disappears even if the worker is killed before a
        # Python finally block can run. Engines read this process's held fd;
        # YARA separately seals/inherits its own copy before dropping privilege.
        with tempfile.TemporaryFile(prefix='scan-', dir=destination) as stream:
            while chunk := os.read(fd, 1024 * 1024):
                total += len(chunk)
                if total > maximum:
                    raise Conflict('File grew beyond the configured scan size limit')
                digest.update(chunk)
                stream.write(chunk)
            stream.flush()
            after = os.fstat(fd)
            if attributes(before) != attributes(after) or total != before.st_size:
                raise Conflict('File changed during snapshot capture')
            yield Path('/proc/self/fd') / str(stream.fileno()), attributes(after) | {'sha256': digest.hexdigest()}


def walk(root, target=''):
    """Yield relative path, regular|skipped|error, detail. Never silently prune."""
    target = relative_path(target)
    def descend(fd, prefix):
        try:
            names = sorted(os.listdir(fd))
        except OSError:
            yield prefix, 'error', 'Directory cannot be read'
            return
        for name in names:
            relative = prefix + '/' + name if prefix else name
            try:
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        yield from descend(child, relative)
                    finally:
                        os.close(child)
                elif stat.S_ISREG(info.st_mode):
                    yield relative, 'regular', ''
                else:
                    yield relative, 'skipped', 'Symbolic link or special file was not followed'
            except OSError:
                yield relative, 'error', 'File or directory changed or cannot be read'
    with directory(root) as root_fd:
        if not target:
            yield from descend(root_fd, '')
        else:
            with parent(root, target) as (fd, name):
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        yield from descend(child, target)
                    finally:
                        os.close(child)
                elif stat.S_ISREG(info.st_mode):
                    yield target, 'regular', ''
                else:
                    yield target, 'skipped', 'Symbolic link or special file was not followed'
