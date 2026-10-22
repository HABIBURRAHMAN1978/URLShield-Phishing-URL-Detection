"""Offline Public Suffix List processing (bundled snapshot; no HTTP requests).
Snapshot from publicsuffix.org, MPL 2.0, embedded in IO::Socket::SSL::PublicSuffix
(2024 snapshot). Private section is included. Dynamic PSL updates are NOT used.
"""
from pathlib import Path
import ipaddress

_raw = Path(__file__).with_name('public_suffix_list.dat').read_text(encoding='utf-8')
_rules = set(line.strip().lower() for line in _raw.splitlines() if line.strip() and not line.strip().startswith('//'))

def registered_domain(host):
    host = str(host).strip('.').lower()
    try:
        ipaddress.ip_address(host.strip('[]'))
        return host
    except ValueError: pass
    try: host = host.encode('idna').decode('ascii')
    except UnicodeError: return host
    labels = host.split('.')
    if len(labels)<2: return host
    matching = 1 # prevailing default * rule
    exception = None
    for i in range(len(labels)):
        suffix = '.'.join(labels[i:])
        if '!' + suffix in _rules:
            exception = len(labels)-i
        if suffix in _rules:
            matching = max(matching, len(labels)-i)
        if i>0 and '*.' + suffix in _rules:
            matching = max(matching, len(labels)-i+1)
    if exception is not None:
        matching = exception-1
    return '.'.join(labels[-(matching+1):]) if len(labels)>matching else host

def subdomain_count(host):
    reg=registered_domain(host)
    return max(0, len(host.strip('.').split('.'))-len(reg.split('.')))

def suffix_length(host):
    reg=registered_domain(host)
    bits=reg.split('.')
    return len('.'.join(bits[1:])) if len(bits)>1 else 0
