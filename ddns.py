#!/usr/bin/env python
# coding:utf-8
"""
Usage: ddns.py <provider> [arguments]

Examples:
    ddns.py aliyun --key KEY --secret SECRET --domain DOMAIN
    ddns.py cloudflare --email EMAIL --key KEY --domain DOMAIN
    ddns.py cloudxns --key KEY --secret SECRET --domain DOMAIN
    ddns.py digitalocean --key KEY --domain DOMAIN
    ddns.py dnsimple --account-id ACCOUNT_ID --key KEY --domain DOMAIN
    ddns.py dnspod --email EMAIL --password PASSWORD --domain DOMAIN
    ddns.py gandi --key KEY --domain DOMAIN
    ddns.py godaddy --key KEY --secret SECRET --domain DOMAIN
    ddns.py he --key KEY --domain DOMAIN
    ddns.py linode --key KEY --domain DOMAIN
    ddns.py namecheap --password PASSWORD --domain DOMAIN
    ddns.py ns1 --key KEY --domain DOMAIN
    ddns.py qcloud --secret-id SECRET_ID --secret-key SECRET_KEY --domain DOMAIN
"""

PY3 = '' is u''
if not PY3:
    reload(__import__('sys')).setdefaultencoding('utf-8')

import base64
import collections
import getopt
import hashlib
import hmac
import json
import logging
import os
import random
import re
import socket
import sys
import sys
import threading
import time
import uuid

if PY3:
    from itertools import zip_longest
    from queue import Queue
    from urllib.parse import urlencode, quote_plus
    from urllib.request import urlopen, Request, HTTPError
else:
    from itertools import izip_longest as zip_longest
    from Queue import Queue
    from urllib import urlencode, quote_plus
    from urllib2 import urlopen, Request, HTTPError

try:
    import publicsuffix
except ImportError:
    publicsuffix = None

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.INFO)


def aliyun(key, secret, domain):
    ip = _getip(domain)
    rfc3339 = lambda: time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    sign = lambda p: base64.b64encode(hmac.new((secret+'&').encode(), ('GET&%2F&'+quote_plus(urlencode(sorted(p)))).encode(), hashlib.sha1).digest())
    api_url = 'https://alidns.aliyuncs.com/'
    record_name, root_domain = _split(domain)
    params = [
        ('Format', 'json'),
        ('Version', '2015-01-09'),
        ('AccessKeyId', key),
        ('Timestamp', rfc3339()),
        ('SignatureMethod', 'HMAC-SHA1'),
        ('SignatureNonce', uuid.uuid4()),
        ('SignatureVersion', '1.0'),
        ('Action', 'DescribeDomainRecords'),
        ('DomainName', root_domain),
    ]
    params += [('Signature', sign(params))]
    _, _, info = _request('GET', api_url, params=params, return_json=True)
    record_id = next(x['RecordId'] for x in info['DomainRecords']['Record'] if x['RR'] == record_name)
    logging.info('aliyun domain=%r to ip=%r record_id: %s', domain, ip, record_id)
    params = [
        ('Format', 'json'),
        ('Version', '2015-01-09'),
        ('AccessKeyId', key),
        ('Timestamp', rfc3339()),
        ('SignatureMethod', 'HMAC-SHA1'),
        ('SignatureNonce', uuid.uuid4()),
        ('SignatureVersion', '1.0'),
        ('Action', 'UpdateDomainRecord'),
        ('RecordId', record_id),
        ('RR', record_name),
        ('Type', 'A'),
        ('Value', ip),
        ('TTL', 600),
    ]
    params += [('Signature', sign(params))]
    _, _, info = _request('GET', api_url, params=params, return_json=True)
    logging.info('aliyun domain=%r to ip=%r info: %s', domain, ip, info)


def cloudflare(email, key, domain):
    ip = _getip(domain)
    headers = {'X-Auth-Email': email, 'X-Auth-Key': key, 'Content-Type': 'application/json'}
    _, zone_name = _split(domain)
    api_url = 'https://api.cloudflare.com/client/v4/zones?name=%s' % zone_name
    code, _, info = _request('GET', api_url, headers=headers, return_json=True)
    zone_id = info['result'][0]['id']
    logging.info('cloudflare domain=%r to ip=%r zone_id: %s', domain, ip, zone_id)
    api_url = 'https://api.cloudflare.com/client/v4/zones/%s/dns_records?name=%s' % (zone_id, domain)
    _, _, info = _request('GET', api_url, headers=headers, return_json=True)
    record_id = info['result'][0]['id']
    logging.info('cloudflare domain=%r to ip=%r record_id: %s', domain, ip, record_id)
    api_url = 'https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s' % (zone_id, record_id)
    info = {'id': zone_id, 'type': 'A', 'ttl': 300, 'proxied': False, 'name': domain, 'content': ip}
    _, _, info = _request('PUT', api_url, headers=headers, json=info, return_json=True)
    logging.info('cloudflare domain=%r to ip=%r result: %s', domain, ip, info['result'])


def cloudxns(key, secret, domain):
    ip = _getip(domain)
    api_url = 'https://www.cloudxns.net/api2/ddns'
    data = json.dumps({'domain': domain, 'ip': ip, 'line_id': '1'})
    date = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())
    api_hmac = hashlib.md5(''.join((key, api_url, data, date, secret)).encode()).hexdigest()
    headers = {'API-KEY': key, 'API-REQUEST-DATE': date, 'API-HMAC': api_hmac, 'API-FORMAT': 'json'}
    resp = urlopen(Request(api_url, data=data.encode(), headers=headers), timeout=5)
    logging.info('cloudxns domain=%r to ip=%r result: %s', domain, ip, resp.read())


def digitalocean(key, domain):
    ip = _getip(domain)
    headers = {'Authorization': 'Bearer '+key}
    record_name, root_domain = _split(domain)
    url = 'https://api.digitalocean.com/v2/domains/%s/records' % root_domain
    _, _, info = _request('GET', url, headers=headers, return_json=True)
    record_id = next(x['id'] for x in info['domain_records'] if x['name'] == record_name and x['type'] == 'A')
    logging.info('digitalocean domain=%r to ip=%r record_id: %s', domain, ip, record_id)
    url = 'https://api.digitalocean.com/v2/domains/%s/records/%s' % (root_domain, record_id)
    info = {'type': 'A', 'name': record_name, 'data': ip, 'ttl': '600'}
    _, _, info = _request('PUT', url, headers=headers, json=info, return_json=True)
    logging.info('digitalocean domain=%r to ip=%r result: %s', domain, ip, info)


def dnsimple(account_id, key, domain):
    ip = _getip(domain)
    headers = {'Authorization': 'Bearer '+key, 'Accept': 'application/json'}
    record_name, root_domain = _split(domain)
    _, _, info = _request('GET', 'https://api.dnsimple.com/v2/whoami', headers=headers, return_json=True)
    account_id = info['data']['id']
    logging.info('digitalocean domain=%r to ip=%r account_id: %s', domain, ip, account_id)
    url = 'https://api.dnsimple.com/v2/%s/zones/%s/records' % (account_id, root_domain)
    _, _, info = _request('GET', url, headers=headers, return_json=True)
    record_id = next(x['id'] for x in info['data'] if x['name'] == record_name and x['type'] == 'A')
    logging.info('digitalocean domain=%r to ip=%r record_id: %s', domain, ip, record_id)
    url = 'https://api.dnsimple.com/v2/%s/zones/%s/records/%s' % (account_id, root_domain, record_id)
    info = {'type': 'A', 'content': ip, 'ttl': '600', 'regions': ['global']}
    _, _, info = _request('PATCH', url, headers=headers, json=info, return_json=True)
    logging.info('digitalocean domain=%r to ip=%r result: %s', domain, ip, info)


def dnspod(email, password, domain):
    ip = _getip(domain)
    record_name, domain = _split(domain)
    params = {'login_email': email, 'login_password': password, 'format': 'json'}
    _, _, info = _request('POST', 'https://dnsapi.cn/Domain.List', params=params, return_json=True)
    domain_id = next(x['id'] for x in info['domains'] if x['punycode'] == domain)
    logging.info('dnspod domain=%r to ip=%r domain_id: %s', domain, ip, domain_id)
    params['domain_id'] = domain_id
    _, _, info = _request('POST', 'https://dnsapi.cn/Record.List', params=params, return_json=True)
    record_id = next(x['id'] for x in info['records'] if x['name'] == record_name and x['type'] == 'A')
    logging.info('dnspod domain=%r to ip=%r record_id: %s', domain, ip, record_id)
    params.update({
        'record_id': record_id,
        'record_type': 'A',
        'record_line': u'默认',
        'value': ip,
        'mx': 5,
        'sub_domain': record_name,
    })
    _, _, info = _request('POST', 'https://dnsapi.cn/Record.Modify', params=params, return_json=True)
    logging.info('dnspod domain=%r to ip=%r info: %s', domain, ip, info)


def gandi(key, domain):
    ip = _getip(domain)
    headers = {'X-Api-Key': key, 'Content-Type': 'application/json'}
    record_name, zone_name = _split(domain)
    api_url = 'https://dns.api.gandi.net/api/v5/zones'
    _, _, info = _request('GET', api_url, headers=headers, return_json=True)
    zone_id = next(x['uuid'] for x in info if x['name'] == zone_name)
    logging.info('gandi domain=%r to ip=%r zone_id: %s', domain, ip, zone_id)
    api_url = 'https://dns.api.gandi.net/api/v5/zones/%s/records/%s/A' % (zone_id, record_name)
    _, _, info = _request('PUT', api_url, json={'rrset_ttl': 300, 'rrset_values': [ip]}, headers=headers)
    logging.info('gandi domain=%r to ip=%r info: %s', domain, ip, info)


def godaddy(key, secret, domain):
    ip = _getip(domain)
    record_name, root_domain = _split(domain)
    headers = {'Authorization': 'sso-key %s:%s' % (key, secret), 'Content-type': 'application/json'}
    api_url = 'https://api.godaddy.com/v1/domains/%s/records/A/%s' % (root_domain, record_name)
    _, _, info = _request('PUT', api_url, headers=headers, json={'data': ip, 'ttl': '600'}, return_json=True)
    logging.info('godaddy domain=%r to ip=%r info: %s', domain, ip, info)


def he(key, domain):
    ip = _getip(domain)
    params = {'hostname': domain, 'password': key, 'myip': ip}
    _, _, content = _request('GET', 'https://dyn.dns.he.net/nic/update', params=params)
    logging.info('dnspod domain=%r to ip=%r result: %s', domain, ip, content)


def linode(key, domain):
    ip = _getip(domain)
    headers = {'Authorization': 'Bearer '+key}
    record_name, root_domain = _split(domain)
    _, _, info = _request('GET', 'https://api.linode.com/v4/domains', headers=headers, return_json=True)
    domain_id = next(x['id'] for x in info['data'] if x['domain'] == root_domain)
    logging.info('linode domain=%r to ip=%r domain_id: %s', domain, ip, domain_id)
    _, _, info = _request('GET', 'https://api.linode.com/v4/domains/%s/records' % domain_id, headers=headers, return_json=True)
    record_id = next(x['id'] for x in info['data'] if x['name'] == domain)
    logging.info('linode domain=%r to ip=%r record_id: %s', domain, ip, record_id)
    _, _, info = _request('PUT', 'https://api.linode.com/v4/domains/%s/records/%s' % (domain_id, record_id), headers=headers, json={'name': domain, 'target': ip})
    logging.info('linode domain=%r to ip=%r result: %s', domain, ip, info)


def ns1(key, domain):
    ip = _getip(domain)
    headers = {'X-NSONE-Key': key}
    _, root_domain = _split(domain)
    url = 'https://api.nsone.net/v1/zones/%s/%s/A' % (root_domain, domain)
    info = {'answers':[{'answer':[ip]}], 'ttl': 600}
    _, _, info = _request('POST', url, headers=headers, json=info, return_json=True)
    logging.info('linode domain=%r to ip=%r result: %s', domain, ip, info)


def namecheap(password, domain):
    record_name, root_domain = _split(domain)
    url = 'https://dynamicdns.park-your-domain.com/update'
    params = {'host': record_name, 'domain': root_domain, 'password': password}
    _, _, info = _request('GET', url, params=params)
    logging.info('linode domain=%r to ip=%r result: %s', domain, ip, info)


def qcloud(secret_id, secret_key, domain):
    ip = _getip(domain)
    sign = lambda p: base64.b64encode(hmac.new(secret_key.encode(), ('GETcns.api.qcloud.com/v2/index.php?'+urlencode(sorted(p))).encode(), hashlib.sha1).digest())
    api_url = 'https://cns.api.qcloud.com/v2/index.php'
    record_name, root_domain = _split(domain)
    params = [
        ('Region', 'sh'),
        ('Timestamp', str(int(time.time()))),
        ('Nonce', str(random.randint(1, 65536))),
        ('SecretId', secret_id),
        ('SignatureMethod', 'HmacSHA1'),
        ('Action', 'RecordList'),
        ('domain', root_domain),
        ('subDomain', record_name),
    ]
    params += [('Signature', sign(params))]
    _, _, info = _request('GET', api_url, params=params, return_json=True)
    record_id = next(x['id'] for x in info['data']['records'] if x['name'] == record_name and x['line'] == u'默认')
    logging.info('aliyun domain=%r to ip=%r record_id: %s', domain, ip, record_id)
    params = [
        ('Region', 'sh'),
        ('Timestamp', str(int(time.time()))),
        ('Nonce', str(random.randint(1, 65536))),
        ('SecretId', secret_id),
        ('SignatureMethod', 'HmacSHA1'),
        ('Action', 'RecordModify'),
        ('domain', root_domain),
        ('subDomain', record_name),
        ('recordId', record_id),
        ('recordType', 'A'),
        ('recordLine', u'默认'),
        ('value', ip),
        ('ttl', '600'),
    ]
    params += [('Signature', sign(params))]
    _, _, info = _request('GET', api_url, params=params, return_json=True)
    logging.info('aliyun domain=%r to ip=%r info: %s', domain, ip, info)


def _getip(domain):
    urls = [
        'http://ip.3322.org',
        'http://whatismyip.akamai.com/',
        'http://checkip.amazonaws.com/',
    ]
    result = Queue()
    def _fetch(url):
        result.put(urlopen(Request(url, headers={'user-agent':'curl/7.53'}), timeout=5))
        logging.info('getip() from %r', url)
    for url in urls:
        t = threading.Thread(target=_fetch, args=(url,))
        t.setDaemon(True)
        t.start()
    text = result.get().read().decode()
    ip = re.search(r'(\d{1,3}.){3}\d{1,3}', text).group()
    if ip == socket.gethostbyname(domain):
        logging.info('remote ip and local ip is same to %s, exit.', ip)
        sys.exit(0)
    return ip


def _request(method, url, params=None, json=None, data=None, headers=None, timeout=None, return_json=False):
    jsonlib = __import__('json')
    if headers is None:
        headers = {}
    if 'User-Agent' not in headers:
        headers.update({'User-Agent': 'curl/7.53'})
    if params:
        if isinstance(params, dict):
            params = sorted(params.items())
        else:
            params = sorted(params)
        if method == 'GET':
            url += '?' + urlencode(params)
        else:
            data = urlencode(params).encode()
    if json:
        assert method != 'GET'
        data = jsonlib.dumps(json).encode()
        headers.update({'Content-Type': 'application/json'})
    if type(data) is type(u''):
        data = data.encode()
    if timeout is None:
        timeout = 8
    req = Request(url, data=data, headers=headers)
    req.get_method = lambda: method
    logging.info('%s \"%s\"', method, url)
    try:
        resp = urlopen(req, timeout=timeout)
    except HTTPError as e:
        resp = e
    content = resp.read()
    if return_json and resp.code == 200:
        content = jsonlib.loads(content)
    return resp.code, dict(resp.headers), content


def _split(domain):
    if publicsuffix:
        root = publicsuffix.PublicSuffixList().get_public_suffix(domain)
    else:
        root = '.'.join(domain.rsplit('.', 2)[-2:])
    record = domain[:-len(root)].strip('.') or '@'
    return record, root


def _main():
    applet = os.path.basename(sys.argv[0])
    funcs = [v for v in globals().values() if type(v) is type(_main) and v.__module__ == '__main__' and not v.__name__.startswith('_')]
    if not PY3:
        for func in funcs:
            setattr(func, '__doc__', getattr(func, 'func_doc'))
            setattr(func, '__defaults__', getattr(func, 'func_defaults'))
            setattr(func, '__code__', getattr(func, 'func_code'))
    funcs = sorted(funcs, key=lambda x:x.__name__)
    params = collections.OrderedDict((f.__name__, list(zip_longest(f.__code__.co_varnames[:f.__code__.co_argcount][::-1], (f.__defaults__ or [])[::-1]))[::-1]) for f in funcs)
    def usage(applet):
        if applet in ('ddns', 'ddns.py'):
            print('Usage: {0} <provider> [arguments]\n\nExamples:\n{1}\n'.format(applet, '\n'.join('\t{0} {1} {2}'.format(applet, k, ' '.join('--{0} {1}'.format(x.replace('_', '-'), x.upper() if y is None else repr(y)) for (x, y) in v)) for k, v in params.items())))
        else:
            print('\nUsage:\n\t{0} {1}'.format(applet, ' '.join('--{0} {1}'.format(x.replace('_', '-'), x.upper() if y is None else repr(y)) for (x, y) in params[applet])))
    if '-h' in sys.argv or '--help' in sys.argv or (applet in ('ddns', 'ddns.py') and not sys.argv[1:]):
        return usage(applet)
    if applet in ('ddns', 'ddns.py'):
        applet = sys.argv[1]
    for f in funcs:
        if f.__name__ == applet:
            break
    else:
        return usage()
    options = [x.replace('_','-')+'=' for x in f.__code__.co_varnames[:f.__code__.co_argcount]]
    kwargs, _ =  getopt.gnu_getopt(sys.argv[1:], '', options)
    kwargs = dict((k[2:].replace('-', '_'),v) for k, v in kwargs)
    logging.debug('main %s(%s)', f.__name__, kwargs)
    try:
        result = f(**kwargs)
    except TypeError as e:
        patterns = [r'missing \d+ .* argument', r'takes (\w+ )+\d+ argument']
        if any(re.search(x, str(e)) for x in patterns):
            return usage(applet)
        raise
    if type(result) == type(b''):
        result = result.decode().strip()
    if result:
        print(result)


if __name__ == '__main__':
    _main()

