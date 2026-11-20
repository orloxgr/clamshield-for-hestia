"""Required website coverage reporting; no engine implementation or build."""
import base64
from pathlib import Path
import re
import tempfile

from .errors import Conflict, CoverageUnavailable, EncryptedContent

# Own benign traditional encrypted ZIP, created with Ubuntu zip. Its one member
# decrypts with public fixture password clamshield-probe to an inert probe line.
# This is data, not an executable or an engine. Never extract or execute it.
PROBE=base64.b64decode('UEsDBAoACQAAAEK/c12HQoTdMAAAACQAAAAMAAAAY292ZXJhZ2UudHh0yFD3HePNzqDJu2oyj9JhKtCk9SsKHDQpghWnZAZiNWG/9gFn8Uxv8dlzHXR85umdUEsHCIdChN0wAAAAJAAAAFBLAQIeAwoACQAAAEK/c12HQoTdMAAAACQAAAAMAAAAAAAAAAEAAACkgQAAAABjb3ZlcmFnZS50eHRQSwUGAAAAAAEAAQA6AAAAagAAAAAA')
REQUIRED=('AlertEncrypted','AlertExceedsMax','ScanArchive')


def harden(text):
    """Preserve unrelated own settings, requiring unambiguous coverage flags."""
    if not isinstance(text,str) or len(text.encode())>65536 or not text.startswith('# Managed by clamshield\n'):
        raise Conflict('Refusing unmanaged website ClamAV configuration')
    for key in REQUIRED:
        pattern=r'(?m)^[ \t]*'+key+r'[ \t]+([^\r\n]+)\r?$'
        values=re.findall(pattern,text)
        if len(values)==1 and values[0].strip().lower() in ('true','yes','1'):continue
        text=re.sub(r'(?m)^[ \t]*'+key+r'(?:[ \t]+[^\n]*)?(?:\n|$)','',text)
        text+=('' if text.endswith('\n') else '\n')+key+' true\n'
    return text


def validate_migration(value):
    if not isinstance(value,dict) or set(value)!={'before','after','was_active'} or type(value['was_active']) is not bool:
        raise Conflict('Invalid website coverage migration intent')
    for field in ('before','after'):
        row=value[field]
        if (not isinstance(row,dict) or set(row)!={'text','mode','gid'} or
                not isinstance(row['text'],str) or len(row['text'].encode())>65536 or
                type(row['mode']) is not int or not 0<=row['mode']<=0o777 or row['mode']&0o022 or
                type(row['gid']) is not int or not 0<=row['gid']<2**31):
            raise Conflict('Invalid retained website coverage configuration')
    if (value['before']['mode'],value['before']['gid'])!=(value['after']['mode'],value['after']['gid']) or harden(value['before']['text'])!=value['after']['text']:
        raise Conflict('Website coverage migration differs from required settings')
    return value


def verify(engine,settings):
    """Require the actual loaded daemon to report inability on encrypted data."""
    with tempfile.NamedTemporaryFile(dir=settings.snapshots) as sample:
        sample.write(PROBE);sample.flush()
        try:engine.scan(Path(sample.name))
        except EncryptedContent:return
    raise CoverageUnavailable('Website ClamAV encrypted-content reporting could not be verified')
