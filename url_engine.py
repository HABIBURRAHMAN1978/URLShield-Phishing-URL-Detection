"""Shared offline-only URL parsing and lexical features for COM6011 V7.
No visits, DNS, WHOIS, requests, or URL fetches. y=1 phishing, 0 legitimate.
"""
import re, math, ipaddress
from collections import Counter
from urllib.parse import urlsplit
from domain_utils import registered_domain, subdomain_count, suffix_length

TOKENS=frozenset({'login','verify','account','secure','update','password','signin','confirm','credential','wallet','billing','unlock','suspend','reset','bank','authentication'})
SHORTENERS=frozenset({'bit.ly','tinyurl.com','t.co','is.gd','cutt.ly','rebrand.ly','qrco.de','ow.ly','buff.ly','shorturl.at'})
NUMERIC_FEATURES=[
 'host_length','host_num_dots','host_hyphens','host_digits','host_letters','host_digit_ratio',
 'host_alpha_ratio','host_entropy','host_labels','host_max_label_length','host_avg_label_length',
 'subdomain_count','suffix_length','host_is_ip','host_punycode','host_suspicious_token_count',
 'host_is_shortener','host_underscore_count','host_unique_ratio','host_vowel_ratio',
 'host_longest_digit_run','host_longest_consonant_run','host_longest_hyphen_run',
 'host_token_count','host_short_token_count','host_max_token_length','host_numeric_token_count',
 'host_digit_letter_transitions'
]

def _is_ip(host):
 try: ipaddress.ip_address(host.strip('[]')); return True
 except ValueError: return False

def parse_url(value):
 if not isinstance(value,str): raise ValueError('Please enter a URL string.')
 raw=value.strip()
 if not raw or len(raw)>4096 or any(c.isspace() or ord(c)<32 for c in raw):
  raise ValueError('URL cannot be empty, above 4096 chars, or contain whitespace/control chars.')
 has_scheme=bool(re.match(r'^[a-z][a-z0-9+.-]*://',raw,re.I))
 if has_scheme and not re.match(r'^https?://',raw,re.I): raise ValueError('Only HTTP or HTTPS URL text is supported.')
 if raw.startswith('//'): raise ValueError('Protocol-relative URL is not supported.')
 try:
  parsed=urlsplit(raw if has_scheme else 'http://'+raw)
  host=(parsed.hostname or '').strip('.').lower()
  _=parsed.port
 except (ValueError,AttributeError) as err: raise ValueError('Malformed URL/port.') from err
 if not host or len(host)>253 or '@' in parsed.netloc: raise ValueError('Missing/invalid hostname or unsupported user-info.')
 try: host=host.encode('idna').decode('ascii')
 except UnicodeError as err: raise ValueError('Invalid international hostname.') from err
 if not _is_ip(host):
  if '.' not in host: raise ValueError('A public-looking hostname is required.')
  labels=host.split('.')
  if any(not x or len(x)>63 or not re.fullmatch('[a-z0-9_-]+',x) for x in labels):
   raise ValueError('Invalid hostname labels.')
 host_norm=host[4:] if host.startswith('www.') else host
 return {'raw':raw,'parsed':parsed,'host':host,'host_model':host_norm,'explicit_scheme':has_scheme}

def _entropy(s):
 if not s:return 0.0
 n=len(s)
 return -sum((v/n)*math.log2(v/n) for v in Counter(s).values())

def _max_run(regex,s):
 return max((len(x) for x in re.findall(regex,s,re.I)),default=0)

def host_features(host):
 """Host argument should be normalized by parse_url(... )['host_model']."""
 parts=host.split('.')
 tokens=[x for x in re.split('[^a-z0-9]+',host) if x]
 digit=sum(c.isdigit() for c in host)
 letter=sum(c.isalpha() for c in host)
 out={
  'host_length':len(host),'host_num_dots':host.count('.'),'host_hyphens':host.count('-'),
  'host_digits':digit,'host_letters':letter,'host_digit_ratio':digit/max(1,len(host)),
  'host_alpha_ratio':letter/max(1,len(host)),'host_entropy':_entropy(host),
  'host_labels':len(parts),'host_max_label_length':max(map(len,parts)),
  'host_avg_label_length':sum(map(len,parts))/len(parts),
  'subdomain_count':subdomain_count(host),'suffix_length':suffix_length(host),
  'host_is_ip':int(_is_ip(host)),'host_punycode':int('xn--' in host),
  'host_suspicious_token_count':sum(t in TOKENS for t in tokens),
  'host_is_shortener':int(host in SHORTENERS), 'host_underscore_count':host.count('_'),
  'host_unique_ratio':len(set(host))/max(1,len(host)),
  'host_vowel_ratio':sum(c in 'aeiou' for c in host)/max(1,letter),
  'host_longest_digit_run':_max_run('[0-9]+',host),
  'host_longest_consonant_run':_max_run('[bcdfghjklmnpqrstvwxyz]+',host),
  'host_longest_hyphen_run':_max_run('-+',host),
  'host_token_count':len(tokens),'host_short_token_count':sum(len(t)<=2 for t in tokens),
  'host_max_token_length':max(map(len,tokens),default=0),
  'host_numeric_token_count':sum(t.isdigit() for t in tokens),
  'host_digit_letter_transitions':sum((a.isdigit()!=b.isdigit()) and a.isalnum() and b.isalnum() for a,b in zip(host,host[1:])),
 }
 return out

def full_url_observations(url):
 d=parse_url(url); p=d['parsed']; h=d['host']; raw=d['raw']; observations=[]
 if not d['explicit_scheme']: observations.append('No explicit HTTP/HTTPS scheme was provided.')
 elif p.scheme.lower()=='http': observations.append('HTTP rather than HTTPS is shown in the URL text.')
 if _is_ip(h): observations.append('The URL uses an IP address as hostname.')
 if 'xn--' in h: observations.append('Punycode appears in the hostname.')
 if h.count('-')>=3: observations.append('Multiple hyphens in hostname.')
 if subdomain_count(h)>=3: observations.append('Multiple subdomains in hostname.')
 if h in SHORTENERS: observations.append('URL-shortening service; destination was not visited.')
 words=set(re.findall('[a-z]+',raw.lower())) & TOKENS
 if words: observations.append('Risk-associated words in URL text: '+', '.join(sorted(words)))
 if p.path not in ('','/'): observations.append('A URL path exists; path was not used by this hostname model.')
 if p.query: observations.append('Query parameters exist; query was not used by this hostname model.')
 if not observations: observations.append('No selected advisory patterns; this does NOT establish that a URL is safe.')
 return observations

def full_url_structure(url):
 d=parse_url(url);p=d['parsed'];return {
  'has_https':int(d['explicit_scheme'] and p.scheme.lower()=='https'),
  'has_http':int(d['explicit_scheme'] and p.scheme.lower()=='http'),
  'has_path':int(bool(p.path and p.path!='/')),
  'has_query':int(bool(p.query)),
  'path_length':len(p.path),'query_length':len(p.query),
  'url_length':len(d['raw']),'url_slashes':d['raw'].count('/'),
 }

# COM6011 V7 additions: descriptive full-URL lexical features, computed from URL TEXT ONLY.
FULL_EXTRA_FEATURES=[
 'url_length','scheme_https','scheme_http','scheme_absent','url_num_slashes',
 'url_num_dots','url_num_hyphens','url_num_digits','url_num_at','url_num_question',
 'url_num_equal','url_num_ampersand','url_num_percent','url_num_hash',
 'url_num_underscore','url_num_colons','path_length','path_depth',
 'path_num_digits','path_num_hyphens','path_suspicious_words','path_entropy',
 'path_extension_length','query_length','query_num_pairs','query_num_digits',
 'query_num_equal','query_suspicious_words','full_suspicious_words','full_entropy',
 'url_has_ip','url_subdomain_count','url_has_port','url_has_punycode',
 'path_to_url_ratio','query_to_url_ratio'
]

def full_url_features(url):
 d=parse_url(url);p=d['parsed'];s=d['raw']; path=p.path or '';query=p.query or ''
 words=lambda text: [w for w in re.split('[^a-z0-9]+',text.lower()) if w]
 tokens=set(words(path));qtokens=set(words(query)); all_tokens=set(words(s))
 try: port=p.port
 except ValueError: port=None
 out={
 'url_length':len(s),'scheme_https':int(d['explicit_scheme'] and p.scheme.lower()=='https'),
 'scheme_http':int(d['explicit_scheme'] and p.scheme.lower()=='http'),
 'scheme_absent':int(not d['explicit_scheme']),'url_num_slashes':s.count('/'),
 'url_num_dots':s.count('.'),'url_num_hyphens':s.count('-'),
 'url_num_digits':sum(c.isdigit() for c in s),'url_num_at':s.count('@'),
 'url_num_question':s.count('?'),'url_num_equal':s.count('='),'url_num_ampersand':s.count('&'),
 'url_num_percent':s.count('%'),'url_num_hash':s.count('#'),
 'url_num_underscore':s.count('_'),'url_num_colons':s.count(':'),
 'path_length':len(path),'path_depth':len([q for q in path.split('/') if q]),
 'path_num_digits':sum(c.isdigit() for c in path),'path_num_hyphens':path.count('-'),
 'path_suspicious_words':len(tokens & TOKENS),'path_entropy':_entropy(path),
 'path_extension_length':len(path.rsplit('.',1)[-1]) if '.' in path.rsplit('/',1)[-1] else 0,
 'query_length':len(query),'query_num_pairs':len([q for q in query.split('&') if q]),
 'query_num_digits':sum(c.isdigit() for c in query),'query_num_equal':query.count('='),
 'query_suspicious_words':len(qtokens & TOKENS),'full_suspicious_words':len(all_tokens & TOKENS),
 'full_entropy':_entropy(s),'url_has_ip':int(_is_ip(d['host'])),
 'url_subdomain_count':subdomain_count(d['host']),
 'url_has_port':int(port is not None),'url_has_punycode':int('xn--' in d['host']),
 'path_to_url_ratio':len(path)/max(1,len(s)),
 'query_to_url_ratio':len(query)/max(1,len(s))
 }
 return out

def full_url_observations(url):
 d=parse_url(url);p=d['parsed'];h=d['host'];raw=d['raw'];notes=[]
 if not d['explicit_scheme']:notes.append('Scheme was not provided; this alone does not imply phishing.')
 elif p.scheme.lower()=='http':notes.append('The URL text uses HTTP rather than HTTPS; this is not proof of phishing.')
 if _is_ip(h):notes.append('The hostname is an IP address.')
 if 'xn--' in h:notes.append('Hostname contains Punycode.')
 if h.count('-')>=3:notes.append('Multiple hyphens appear in the hostname.')
 if subdomain_count(h)>=3:notes.append('Many hostname subdomains.')
 if h in SHORTENERS:notes.append('URL shortener recognised; its destination is not inspected.')
 matched=sorted(set(re.findall(r'[a-z]+',raw.lower())) & TOKENS)
 if matched:notes.append('Potentially sensitive words in URL text: '+', '.join(matched)+'. These can also occur in legitimate URLs.')
 if p.path not in ('','/'):notes.append('The URL has a path; full-URL feature candidates can model it.')
 if p.query:notes.append('The URL has query parameters; full-URL feature candidates can model them.')
 if not notes:notes.append('No selected lexical observations; this is NOT evidence of safety.')
 return notes
