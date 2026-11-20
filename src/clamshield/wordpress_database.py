"""Bounded WordPress database inspection without loading website PHP.

Credentials are parsed as literals and checked against native account inventory.
Reports contain evidence, never credentials. Changes use exact row/content guards.
"""
import base64
from contextlib import contextmanager
import hashlib
import json
import re
import time

from .errors import AccessDenied, Conflict
from .paths import snapshot
from .wordpress import joined


PATTERNS = (
    ('script', re.compile(r'<script\b[^>]*>.*?</script\s*>', re.I | re.S)),
    ('iframe', re.compile(r'<iframe\b[^>]*>.*?</iframe\s*>', re.I | re.S)),
    ('PHP code', re.compile(r'<\?(?:php|=)', re.I)),
    ('encoded/evaluated code', re.compile(r'\b(?:base64_decode|eval|gzinflate)\s*\(', re.I)),
    ('JavaScript URL', re.compile(r'javascript\s*:', re.I)),
)


def literal(text, name, assignment=False):
    # Reject concatenation/computed values. Never eval wp-config or wp-cli config.
    string = r"(?P<quote>['\"])(?P<value>(?:\\.|(?! (?P=quote) ).)*) (?P=quote)"
    prefix = r'\$' + re.escape(name) + r'\s*=\s*' if assignment else r"\bdefine\s*\(\s*['\"]" + re.escape(name) + r"['\"]\s*,\s*"
    suffix = r'\s*;' if assignment else r'\s*\)\s*;'
    matches = list(re.finditer(prefix + string + suffix, text, re.X))
    if len(matches) != 1: raise Conflict('Database configuration requires unambiguous literal values')
    value = matches[0]['value']; quote = matches[0]['quote']
    if quote == '"' and ('$' in value or re.search(r'\\(?![\\"])', value)):
        raise Conflict('Computed database configuration is not loaded')
    return value.replace('\\' + quote, quote).replace('\\\\', '\\')


def ident(value):
    if not isinstance(value, str) or not value or len(value) > 64 or '\0' in value:
        raise Conflict('Unsupported database identifier')
    return '`' + value.replace('`', '``') + '`'


def packed(value):
    return base64.b64encode(value).decode('ascii')


def unpacked(value):
    return base64.b64decode(value, validate=True)


def json_guard(before, after):
    if not before.lstrip().startswith((b'{',b'[')):return
    try:json.loads(before)
    except (ValueError,UnicodeError):return
    try:json.loads(after)
    except (ValueError,UnicodeError) as exc:raise Conflict('Replacement would invalidate JSON data') from exc


def serialized_replace(data, old, new):
    """Rewrite strings with byte-correct PHP serialization lengths; no PHP eval.

    Objects/references are refused rather than instantiated or silently corrupted.
    """
    offset = 0
    def parse(depth=0, replace_strings=True):
        nonlocal offset
        if depth > 64 or offset >= len(data): raise Conflict('Unsupported serialized database value')
        start = offset; kind = data[offset:offset+2]; offset += 2
        if kind == b'N;': return kind
        if kind in (b'b:', b'i:', b'd:'):
            end = data.find(b';', offset)
            if end < 0 or not re.fullmatch(rb'[-+0-9.eE]+', data[offset:end]): raise Conflict('Invalid serialized scalar')
            offset = end + 1; return data[start:offset]
        if kind == b's:':
            end = data.find(b':"', offset)
            if end < 0 or not data[offset:end].isdigit(): raise Conflict('Invalid serialized string')
            length = int(data[offset:end]); offset = end + 2
            value = data[offset:offset+length]; offset += length
            if len(value) != length or data[offset:offset+2] != b'";': raise Conflict('Invalid serialized string length')
            offset += 2
            changed=value.replace(old,new) if replace_strings else value
            json_guard(value,changed);value=changed
            return b's:' + str(len(value)).encode() + b':"' + value + b'";'
        if kind == b'a:':
            end = data.find(b':{', offset)
            if end < 0 or not data[offset:end].isdigit(): raise Conflict('Invalid serialized array')
            count = int(data[offset:end])
            if count > 100000: raise Conflict('Serialized array exceeds limit')
            offset = end + 2; values=[]
            for _ in range(count):
                if data[offset:offset+2] not in (b'i:',b's:'):raise Conflict('Invalid serialized array key')
                values.extend((parse(depth+1,False),parse(depth+1,replace_strings)))
            if data[offset:offset+1] != b'}': raise Conflict('Invalid serialized array')
            offset += 1
            return b'a:' + str(count).encode() + b':{' + b''.join(values) + b'}'
        raise Conflict('Serialized objects/references require manual review')
    result = parse()
    if offset != len(data): raise Conflict('Unexpected serialized data')
    return result


def replacement(data, find, replace):
    if not isinstance(find, str) or not find or len(find) > 65536 or not isinstance(replace, str) or len(replace) > 65536:
        raise Conflict('Choose an exact database fragment and replacement')
    old, new = find.encode('utf-8'), replace.encode('utf-8')
    if old not in data: raise Conflict('The selected fragment does not match this database value')
    result = serialized_replace(data, old, new) if re.match(rb'^(?:[abisdOCRr]:|N;)', data) else data.replace(old, new)
    json_guard(data,result)
    if result == data or len(result) > 1024**2: raise Conflict('Database change is empty or exceeds limits')
    return result


class WordPressDatabase:
    def __init__(self, settings, hestia, context, root, installation):
        self.settings, self.hestia, self.context = settings, hestia, context
        self.root, self.installation = root, installation

    @staticmethod
    def schema(cursor,table):
        cursor.execute('SELECT COLUMN_NAME,COLUMN_TYPE,IS_NULLABLE,COLLATION_NAME,EXTRA FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=%s ORDER BY ORDINAL_POSITION',(table,))
        columns=cursor.fetchall()
        cursor.execute('SHOW KEYS FROM '+ident(table)+" WHERE Key_name='PRIMARY'")
        keys=[(row[3],row[4],row[7]) for row in cursor.fetchall()]
        return hashlib.sha256(repr((columns,keys)).encode()).hexdigest()

    def config(self):
        with snapshot(self.root, joined(self.installation, 'wp-config.php'), self.settings.snapshots, 256*1024) as (copy, fingerprint):
            if fingerprint['links'] != 1: raise AccessDenied('Database configuration must be a regular private site file')
            text = copy.read_text(encoding='utf-8')
        values = {key: literal(text, 'DB_' + key) for key in ('NAME','USER','PASSWORD','HOST')}
        prefix = literal(text, 'table_prefix', assignment=True)
        if not re.fullmatch(r'[A-Za-z0-9_]{1,64}', prefix): raise Conflict('Unsupported WordPress table prefix')
        live = self.hestia.authorize(self.context['actor'], self.context['owner'])
        if live['identity'] != self.context['identity']: raise AccessDenied('Database account was replaced')
        rows = self.hestia.call('v-list-databases', self.context['owner'], 'json')
        if values['NAME'] not in rows: raise AccessDenied('WordPress database is not owned by the selected hosting account')
        native_user=rows[values['NAME']].get('USER',rows[values['NAME']].get('DBUSER'))
        if (not isinstance(native_user,str) or native_user!=values['USER'] or
                not values['USER'].startswith(self.context['owner']+'_')):
            raise AccessDenied('WordPress must use its native hosting database user')
        if self.hestia.authorize(self.context['actor'],self.context['owner'])['identity']!=self.context['identity']:
            raise AccessDenied('Database account changed during discovery')
        # Remote database hosts are not inferred from a compromised PHP file.
        match = re.fullmatch(r'(localhost|127\.0\.0\.1)(?::([0-9]{1,5}|/[^\r\n\0]+))?', values['HOST'])
        if not match: raise Conflict('Database host requires a native local connection')
        connection = dict(database=values['NAME'], user=values['USER'], password=values['PASSWORD'],
                          host=match[1], charset='utf8mb4', use_unicode=False, autocommit=False,
                          local_infile=False, binary_prefix=True, connect_timeout=5, read_timeout=15, write_timeout=15)
        if match[2] and match[2].startswith('/'): connection['unix_socket'] = match[2]
        elif match[2]: connection['port'] = int(match[2])
        elif match[1] == 'localhost': connection['unix_socket'] = '/run/mysqld/mysqld.sock'
        return connection, prefix, fingerprint

    @contextmanager
    def opened(self, expected=None):
        import pymysql
        values, prefix, fingerprint = self.config()
        if expected and any(fingerprint[key]!=expected[key] for key in ('sha256','uid','gid','mode','links','device')):
            raise Conflict('Database configuration changed; analyze again')
        try:
            connection = pymysql.connect(**values)
            try: yield connection, prefix, fingerprint
            finally: connection.close()
        except pymysql.MySQLError as exc:
            raise Conflict('WordPress database connection or query failed; inspect native database availability') from exc

    def inspect(self, emit, cancelled=lambda:False):
        deadline = time.monotonic() + 120; scanned = 0; matches = 0; evidence_bytes=0; checked_bytes=0
        with self.opened() as (db, prefix, fingerprint), db.cursor() as cursor:
            cursor.execute('SET TRANSACTION READ ONLY');cursor.execute('START TRANSACTION WITH CONSISTENT SNAPSHOT')
            cursor.execute('SELECT TABLE_NAME,COLUMN_NAME,DATA_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME,ORDINAL_POSITION')
            tables = {}
            for table, column, kind in cursor.fetchall():
                table, column, kind = (v.decode() if isinstance(v, bytes) else v for v in (table,column,kind))
                if table.startswith(prefix): tables.setdefault(table, []).append((column,kind))
            if len(tables) > 500: raise Conflict('Database table inventory exceeds its limit')
            for table, columns in tables.items():
                cursor.execute('SHOW KEYS FROM ' + ident(table) + " WHERE Key_name='PRIMARY'")
                keys = [row[4].decode() if isinstance(row[4],bytes) else row[4] for row in sorted(cursor.fetchall(), key=lambda row:row[3])]
                schema=self.schema(cursor,table)
                text_columns = [name for name,kind in columns if kind in ('char','varchar','tinytext','text','mediumtext','longtext','json')]
                for column in text_columns:
                    offset = 0
                    while True:
                        if cancelled(): raise Conflict('Database inspection cancelled')
                        if time.monotonic() > deadline or scanned >= 100000: raise Conflict('Database inspection reached its time or row limit')
                        fields = ','.join(ident(key) for key in keys)
                        # Bound each value and each response; oversized cells are reported, never certified clean.
                        query = 'SELECT ' + (fields+',' if fields else '') + 'OCTET_LENGTH('+ident(column)+'),LEFT(CAST('+ident(column)+' AS BINARY),1048576) FROM '+ident(table)
                        if keys: query += ' ORDER BY ' + fields
                        cursor.execute(query + ' LIMIT 32 OFFSET %s', (offset,));rows = cursor.fetchall()
                        if not rows: break
                        for row in rows:
                            scanned += 1; size, raw = row[-2:]
                            if raw is None: continue
                            raw = bytes(raw)
                            checked_bytes+=len(raw)
                            if checked_bytes>256*1024**2:raise Conflict('Database inspection reached its byte limit')
                            if size > 1024**2: raise Conflict('Database value exceeds the inspection limit')
                            text = raw.decode('utf-8', errors='replace')
                            evidence = [{'kind':label,'match':match.group(0)[:4096], 'offset':match.start()} for label,pattern in PATTERNS for match in list(pattern.finditer(text))[:10]]
                            # Administrators and cron/options are review points, not malware verdicts.
                            if (column.endswith('capabilities') or column=='meta_value') and 'administrator' in text:
                                evidence.append({'kind':'administrator capability','match':'administrator','offset':text.find('administrator')})
                            if evidence:
                                matches += 1
                                evidence_bytes+=len(raw)
                                if evidence_bytes>16*1024**2:raise Conflict('Database evidence reached its byte limit')
                                emit(dict(table=table,column=column,keys=keys,key_values=[packed(str(v).encode() if not isinstance(v,bytes) else v) for v in row[:-2]],
                                          before=packed(raw),sha256=hashlib.sha256(raw).hexdigest(),config=fingerprint,
                                          installation=self.installation,evidence=evidence,editable=bool(keys),
                                          schema=schema,
                                          excerpt=text[:8192]))
                                if matches >= 1000: raise Conflict('Database findings exceed the report limit')
                        offset += len(rows)
            db.rollback()
        return dict(status='review' if matches else 'completed',values_checked=scanned,findings=matches)

    def change(self, item, before, after, *, inspect_only=False):
        with self.opened(item['config']) as (db, prefix, _), db.cursor() as cursor:
            if not item['table'].startswith(prefix) or not item['keys']: raise AccessDenied('Database row is outside the selected WordPress installation')
            cursor.execute('SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=%s',(item['table'],))
            row = cursor.fetchone()
            if not row or row[0] not in (b'InnoDB','InnoDB'): raise Conflict('Database changes require a transactional InnoDB table')
            predicate = ' AND '.join(ident(key)+'=%s' for key in item['keys'])
            keys = [unpacked(v) for v in item['key_values']]
            cursor.execute('SELECT CAST('+ident(item['column'])+' AS BINARY) FROM '+ident(item['table'])+' WHERE '+predicate+' FOR UPDATE',keys)
            rows = cursor.fetchall()
            if len(rows)!=1 or rows[0][0] is None: raise Conflict('Database row is no longer uniquely available')
            if self.schema(cursor,item['table'])!=item['schema']:raise Conflict('Database table definition changed; analyze again')
            current = bytes(rows[0][0])
            if current == after and not inspect_only: db.rollback();return 'already-applied'
            if current != before: raise Conflict('Database content changed; no row was overwritten')
            if inspect_only: db.rollback();return 'unchanged'
            cursor.execute('UPDATE '+ident(item['table'])+' SET '+ident(item['column'])+'=%s WHERE '+predicate,[after,*keys])
            if cursor.rowcount != 1: raise Conflict('Database change was not applied exactly once')
            cursor.execute('SELECT CAST('+ident(item['column'])+' AS BINARY) FROM '+ident(item['table'])+' WHERE '+predicate,keys)
            verified=cursor.fetchall()
            if len(verified)!=1 or verified[0][0] is None or bytes(verified[0][0])!=after:
                db.rollback();raise Conflict('Database change did not preserve the reviewed replacement; rolled back')
            db.commit();return 'applied'
