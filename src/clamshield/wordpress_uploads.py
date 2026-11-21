"""Uploads cleanup is an explicit script-file policy, not malware detection."""
from pathlib import PurePosixPath
import re


def cleanup_match(path, installations, options, copy):
    if not any(path.startswith((row['path']+'/' if row['path'] else '')+'wp-content/uploads/') for row in installations):
        return False
    file=PurePosixPath(path);suffix=file.suffix.lower()
    script=options['uploads_php'] and suffix in ('.php','.php3','.php4','.php5','.php7','.php8','.phtml','.pht','.phar','.cgi','.pl','.py','.sh')
    javascript=options['uploads_js'] and suffix in ('.js','.mjs','.cjs')
    if not script and not javascript:return False
    # WordPress/plugins use an inert index.php to prevent directory listings.
    # Exempt only this exact small placeholder; other PHP stays reviewable.
    if file.name.lower()=='index.php' and copy.stat().st_size<=256:
        content=copy.read_bytes()
        if re.fullmatch(rb'\s*<\?php\s*(?://[ \t]*Silence is golden\.[ \t]*(?:\r?\n|$)|/\*[ \t]*Silence is golden\.[ \t]*\*/)\s*(?:\?>\s*)?',content,re.I):
            return False
    return True
