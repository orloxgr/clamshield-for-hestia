"""Exact, reviewed infection transformations; never evaluate website code."""
import hashlib
import json
from pathlib import PurePosixPath

from .errors import Conflict


class UnsupportedCleaning(Conflict):
    pass

# Short infection indicators from the original researchers, not entire malware
# programs. Byte-exact matching deliberately refuses unreviewed variants.
RECIPES=(
    dict(id='wp-vcd-post-loader-v1',family='WP-VCD loader',version=1,
         source='https://medium.com/@cirku17/wp-vcd-malware-analysis-7c5dbaad89c3',
         author="Manuel D'Orso",published='2017-07-18',path_suffix='wp-includes/post.php',
         prefix=b"<?php if (file_exists(dirname(__FILE__) . '/wp-vcd.php')) include_once(dirname(__FILE__) . '/wp-vcd.php'); ?>"),
    dict(id='wp-render-option-prefix-v1',family='WordPress render-option injection',version=1,
         source='https://blog.sucuri.net/2015/09/minimalistic-wordpress-injection.html',
         author='Denis Sinegubko / Sucuri',published='2015-09-23',path_suffix=None,
         prefix=br'<?php eval(get_option("\x72\x65\x6e\x64\x65\x72")); ?>'))


def fingerprint(content):return hashlib.sha256(content).hexdigest()


def describe(recipe):
    return {key:value for key,value in recipe.items() if key!='prefix'}|dict(prefix_sha256=fingerprint(recipe['prefix']),prefix_bytes=len(recipe['prefix']))


def revision():return fingerprint(json.dumps([describe(row) for row in RECIPES],sort_keys=True,separators=(',',':')).encode())


def eligible(finding):
    if (finding['status']!='open' or finding['engine'] not in ('clamav','yara') or
            finding['fingerprint'].get('missing') or finding['fingerprint'].get('links')!=1):
        raise Conflict('Targeted cleaning requires an open scanner detection on one regular file')


def transform(content,path,expected_revision):
    if expected_revision!=revision():raise Conflict('Cleaning definitions changed; prepare a fresh preview')
    file=PurePosixPath(path)
    if file.suffix.lower() not in ('.php','.phtml'):raise UnsupportedCleaning('No reviewed cleaning definition matches this file type')
    remaining=content;removed=[]
    for _ in range(4):
        matches=[row for row in RECIPES if remaining.startswith(row['prefix']) and
                 (row['path_suffix'] is None or path==row['path_suffix'] or path.endswith('/'+row['path_suffix']))]
        if not matches:break
        if len(matches)!=1:raise Conflict('Cleaning definitions are ambiguous; use a trusted replacement')
        row=matches[0];removed.append(describe(row)|dict(offset=len(content)-len(remaining)))
        remaining=remaining[len(row['prefix']):]
    if not removed:raise UnsupportedCleaning('No reviewed cleaning definition matches this infection; use quarantine or a trusted replacement')
    if any(remaining.startswith(row['prefix']) for row in RECIPES):raise Conflict('Repeated infection exceeds the reviewed cleaning limit')
    # Removing the entire file, changing PHP token boundaries or guessing an
    # arbitrary embedded substring is not a reviewed transformation.
    tail=remaining.lstrip(b' \t\r\n')
    if not tail.startswith((b'<?php',b'<!DOCTYPE html',b'<html')):
        raise Conflict('The infection boundary has no supported original file continuation')
    provenance=dict(kind='targeted-cleanup',source='ClamShield reviewed infection definitions',
        catalog_revision=expected_revision,recipes=removed,sha256=fingerprint(remaining),size=len(remaining),
        original_sha256=fingerprint(content),removed_bytes=len(content)-len(remaining),
        warning='Only the listed exact infection fragments are removed. Custom code is retained. A successful file scan does not prove the whole site or database is free of persistence; run a full site scan and investigate reinfection.')
    return remaining,provenance
