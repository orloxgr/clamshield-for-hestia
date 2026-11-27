"""Read only the native rejection threshold, independently of message headers.

This is evidence for the envelope-bound broker. Changing native rejection flags
requires separately journaled, account-generation-bound native API operations.
"""
import hashlib
import re

from .errors import EngineError
from .mail_adapter import bounded


def rejection_threshold():
    result=bounded(['/usr/sbin/exim4','-bP','macro','SPAM_REJECT_SCORE'],timeout=3,check=False)
    if result.returncode or len(result.stdout)>128:
        raise EngineError('Native spam rejection threshold is unavailable')
    match=re.fullmatch(rb'SPAM_REJECT_SCORE\s*=\s*([0-9]{1,7})\s*',result.stdout)
    if not match:
        raise EngineError('Native spam rejection threshold is not a supported numeric value')
    return dict(required_score=int(match[1])/10,source='native-exim-macro',
                revision=hashlib.sha256(result.stdout.strip()).hexdigest())


def verify_endpoint():
    result=bounded(['/usr/sbin/exim4','-bP','spamd_address'],timeout=3,check=False)
    if result.returncode or len(result.stdout)>128 or not re.fullmatch(rb'spamd_address\s*=\s*127\.0\.0\.1\s+783\s*',result.stdout):
        raise EngineError('Native SpamAssassin endpoint is not the supported verified loopback service')
