"""Bounded, HTTPS-only WordPress.org references. Never load website PHP."""
import hashlib
import io
import json
import re
import stat
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
import zipfile

from .atomic import write as atomic_write
from .errors import ClamShieldError
from .paths import relative_path


class ReferenceUnavailable(ClamShieldError):
    pass


def checksum_matches(expected,digest):
    accepted=expected['digest']
    return digest in accepted if isinstance(accepted,list) else digest==accepted


def token(value, kind):
    patterns = {'version': r'[0-9][0-9A-Za-z._-]{0,63}',
                'slug': r'[a-z0-9][a-z0-9-]{0,99}',
                'locale': r'[A-Za-z]{2,3}(?:_[A-Za-z0-9]{2,12}){0,2}'}
    if not isinstance(value, str) or not re.fullmatch(patterns[kind], value):
        raise ReferenceUnavailable('Invalid WordPress ' + kind)
    return value


def trusted_url(url):
    try:
        parts = urlsplit(url)
        valid = (parts.scheme == 'https' and parts.hostname in ('api.wordpress.org', 'downloads.wordpress.org')
                 and parts.port in (None, 443) and not parts.username and not parts.password and not parts.fragment)
    except ValueError:
        valid = False
    if not valid:
        raise ReferenceUnavailable('WordPress reference URL is not trusted')
    return url


class Redirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        trusted_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url, maximum):
    trusted_url(url)
    try:
        request = Request(url, headers={'User-Agent': 'ClamShield/WordPress-integrity',
                                       'Accept-Encoding': 'identity'})
        with build_opener(Redirects()).open(request, timeout=25) as response:
            trusted_url(response.url)
            if response.status != 200:
                raise ReferenceUnavailable('WordPress.org reference is unavailable')
            deadline = time.monotonic() + 120
            output = bytearray()
            while chunk := response.read(min(1024 * 1024, maximum + 1 - len(output))):
                output.extend(chunk)
                if len(output) > maximum or time.monotonic() > deadline:
                    raise ReferenceUnavailable('WordPress.org reference exceeds download limits')
            return bytes(output)
    except HTTPError as exc:
        if exc.code in (404,410):
            message='No WordPress.org reference is available for this component/version. Compare with an original package from its publisher.'
        elif exc.code==429:
            message='WordPress.org request limit reached. Try the check again later.'
        else:message='WordPress.org request failed (HTTP '+str(exc.code)+'). Try the check again later.'
        raise ReferenceUnavailable(message) from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise ReferenceUnavailable('Could not connect to WordPress.org. Check connectivity and try again.') from exc


def archive_files(data, prefix, maximum=256 * 1024 * 1024):
    """Return bytes by canonical relative name; never extract paths to disk."""
    result, total = {}, 0
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            if len(archive.infolist()) > 50000:
                raise ReferenceUnavailable('WordPress archive contains too many entries')
            seen = set()
            for item in archive.infolist():
                name = item.filename
                mode = item.external_attr >> 16
                canonical = relative_path(name, allow_root=False)
                if canonical != name.rstrip('/') or canonical in seen:
                    raise ReferenceUnavailable('WordPress archive contains ambiguous paths')
                seen.add(canonical)
                if not name.startswith(prefix + '/'):
                    raise ReferenceUnavailable('WordPress archive has an unexpected root')
                if item.is_dir():
                    continue
                if (stat.S_IFMT(mode) not in (0, stat.S_IFREG) or item.flag_bits & 1
                        or item.file_size > 50 * 1024 * 1024):
                    raise ReferenceUnavailable('WordPress archive contains unsupported entries')
                total += item.file_size
                if total > maximum:
                    raise ReferenceUnavailable('WordPress archive exceeds expanded size limit')
                relative = name[len(prefix) + 1:]
                if not relative:
                    raise ReferenceUnavailable('WordPress archive has an invalid filename')
                result[relative] = archive.read(item)
    except (zipfile.BadZipFile, RuntimeError, ValueError, ClamShieldError) as exc:
        if isinstance(exc, ReferenceUnavailable):
            raise
        raise ReferenceUnavailable('WordPress archive failed validation') from exc
    if not result:
        raise ReferenceUnavailable('WordPress archive is empty')
    return result


class References:
    def __init__(self, settings, fetch=download):
        self.settings, self.fetch = settings, fetch

    def get(self, url, maximum):
        cache = self.settings.state / 'wordpress-cache'
        cache.mkdir(mode=0o700, exist_ok=True)
        path = cache / hashlib.sha256(url.encode()).hexdigest()
        if path.is_file() and not path.is_symlink() and path.stat().st_size <= maximum:
            if time.time() - path.stat().st_mtime < 86400:
                return path.read_bytes()
        data = self.fetch(url, maximum)
        atomic_write(path, data, mode=0o600)
        return data

    def manifest(self, component):
        kind = component['kind']
        version = token(component['version'], 'version')
        slug = token(component.get('slug', 'wordpress'), 'slug')
        locale = token(component.get('locale', 'en_US'), 'locale')
        if kind == 'core':
            url = 'https://api.wordpress.org/core/checksums/1.0/?' + urlencode({'version': version, 'locale': locale})
        elif kind == 'plugin':
            url = f'https://downloads.wordpress.org/plugin-checksums/{slug}/{version}.json'
        elif kind == 'theme':
            url = f'https://downloads.wordpress.org/theme/{slug}.{version}.zip'
            files = archive_files(self.get(url, 80 * 1024 * 1024), slug)
            return {'source': url, 'files': {p: {'algorithm': 'sha256', 'digest': hashlib.sha256(b).hexdigest()}
                                            for p, b in files.items()}}
        else:
            raise ReferenceUnavailable('Unsupported WordPress component')
        try:
            data = json.loads(self.get(url, 16 * 1024 * 1024))
            if not isinstance(data,dict):raise ValueError('Invalid reference object')
            if kind == 'plugin' and (data.get('plugin') != slug or data.get('version') != version):
                raise ReferenceUnavailable('Plugin reference identity does not match')
            values = data['checksums' if kind == 'core' else 'files']
            if not isinstance(values, dict) or not values or len(values) > 50000:
                raise ValueError('Invalid reference size')
            files = {}
            for path, checksum in values.items():
                if relative_path(path, allow_root=False) != path or path in files:
                    raise ValueError('Invalid reference path')
                # Bundled plugins/themes have independent installed versions.
                if kind == 'core' and path.startswith('wp-content/'):
                    continue
                algorithm = 'md5' if isinstance(checksum, str) or 'sha256' not in checksum else 'sha256'
                digest = checksum if isinstance(checksum, str) else checksum[algorithm]
                # WordPress.org can publish multiple accepted variants for a file.
                accepted=digest if isinstance(digest,list) else [digest]
                if not 1<=len(accepted)<=1024 or any(not isinstance(value,str) or not re.fullmatch(
                        '[a-f0-9]{'+str(32 if algorithm=='md5' else 64)+'}',value) for value in accepted):
                    raise ValueError('Invalid reference digest')
                files[path] = {'algorithm': algorithm, 'digest': sorted(set(accepted)) if isinstance(digest,list) else digest}
            return {'source': url, 'files': files}
        except (ValueError, TypeError, KeyError, ClamShieldError) as exc:
            if isinstance(exc, ReferenceUnavailable):
                raise
            raise ReferenceUnavailable('Official checksum data could not be validated. This component was not compared.') from exc

    def replacement(self, component, path, expected):
        """Fetch only an exact, independently verified release member."""
        path = relative_path(path, allow_root=False)
        manifest = self.manifest(component)
        if manifest['files'].get(path) != expected:
            raise ReferenceUnavailable('Release reference changed since the integrity check')
        kind = component['kind']
        version = token(component['version'], 'version')
        slug = token(component.get('slug', 'wordpress'), 'slug')
        locale = token(component.get('locale', 'en_US'), 'locale')
        if kind == 'core':
            language = '' if locale == 'en_US' else locale + '/'
            url = f'https://downloads.wordpress.org/release/{language}wordpress-{version}.zip'
            prefix = 'wordpress'
        else:
            url = f'https://downloads.wordpress.org/{kind}/{slug}.{version}.zip'
            prefix = slug
        files = archive_files(self.get(url, 80 * 1024 * 1024), prefix)
        content = files.get(path)
        if content is None or not checksum_matches(expected,hashlib.new(expected['algorithm'], content).hexdigest()):
            raise ReferenceUnavailable('Replacement does not match the trusted release checksum')
        return content, {'source': url, 'reference': manifest['source'], 'expected': expected,
                         'sha256': hashlib.sha256(content).hexdigest(), 'size': len(content)}
