import asyncio, os, re, socket
from typing import Any
import dns.asyncresolver
import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI(title='DomainScope', version='1.0.0')
app.mount('/static', StaticFiles(directory='app/static'), name='static')
DOMAIN_RE = re.compile(r'^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$')
DNS_TYPES = ['A','AAAA','MX','NS','TXT','CNAME']

def normalize_domain(domain: str) -> str:
    d=domain.strip().lower().rstrip('.')
    if d.startswith(('http://','https://')) or not DOMAIN_RE.fullmatch(d):
        raise ValueError('Enter a valid domain only, for example: example.com')
    return d

async def resolve_record(domain, typ):
    r=dns.asyncresolver.Resolver(); r.lifetime=4
    try:
        ans=await r.resolve(domain, typ); out=[]
        for a in ans:
            v=a.to_text().strip()
            if typ=='MX': v=v.split(maxsplit=1)[-1].rstrip('.')
            elif typ in ('CNAME','NS'): v=v.rstrip('.')
            out.append(v)
        return sorted(set(out))
    except Exception: return []

async def dns_info(domain):
    vals=await asyncio.gather(*(resolve_record(domain,t) for t in DNS_TYPES))
    return dict(zip(DNS_TYPES,vals))

async def reverse_dns(ip):
    try:
        host,_,_=await asyncio.to_thread(socket.gethostbyaddr,ip); return host.rstrip('.')
    except Exception: return None

async def subdomain_finder_api(domain):
    """Find subdomains using SecurityTrails API when configured.
    Falls back to crt.sh so the project still works without an API key.
    """
    api_key = os.getenv('SECURITYTRAILS_API_KEY', '').strip()
    if api_key:
        try:
            url = f'https://api.securitytrails.com/v1/domain/{domain}/subdomains'
            headers = {'accept': 'application/json', 'apikey': api_key, 'User-Agent': 'DomainScope/2.0'}
            async with httpx.AsyncClient(timeout=15, follow_redirects=False, trust_env=False) as c:
                r = await c.get(url, headers=headers)
                r.raise_for_status()
                data = r.json()
            names = set()
            for sub in data.get('subdomains', []):
                host = f"{str(sub).strip().lower().rstrip('.')}.{domain}"
                if host.endswith('.' + domain) or host == domain:
                    names.add(host)
            return sorted(names)
        except Exception:
            pass

    # Public Certificate Transparency fallback
    try:
        async with httpx.AsyncClient(timeout=12, follow_redirects=False, trust_env=False, headers={'User-Agent':'DomainScope/2.0'}) as c:
            r=await c.get('https://crt.sh/', params={'q':f'%.{domain}','output':'json'}); r.raise_for_status(); data=r.json()
        names=set()
        for row in data:
            for n in str(row.get('name_value','')).splitlines():
                n=n.strip().lower().lstrip('*.')
                if n==domain or n.endswith('.'+domain): names.add(n)
        return sorted(names)
    except Exception: return []

def title_from_html(html):
    m=re.search(r'<title[^>]*>(.*?)</title>',html,re.I|re.S)
    return re.sub(r'\s+',' ',m.group(1)).strip()[:200] if m else None

async def http_probe(domain):
    result={'reachable':False,'url':None,'status_code':None,'final_url':None,'title':None,'server':None,'headers':{},'error':None}
    wanted=['server','content-type','strict-transport-security','content-security-policy','x-content-type-options','x-frame-options','referrer-policy','permissions-policy']
    async with httpx.AsyncClient(timeout=8,follow_redirects=False,headers={'User-Agent':'DomainScope/1.0'}) as c:
        for scheme in ('https','http'):
            try:
                url=f'{scheme}://{domain}/'; r=await c.get(url)
                result.update(reachable=True,url=url,status_code=r.status_code,final_url=str(r.url),title=title_from_html(r.text[:500000]),server=r.headers.get('server'))
                result['headers']={k:r.headers[k] for k in wanted if k in r.headers}
                return result
            except Exception as e: result['error']=str(e)[:180]
    return result

async def report(domain):
    dns_records, subs, http=await asyncio.gather(dns_info(domain),subdomain_finder_api(domain),http_probe(domain))
    ips=sorted(set(dns_records.get('A',[])+dns_records.get('AAAA',[])))
    hosts=await asyncio.gather(*(reverse_dns(ip) for ip in ips))
    reverse={ip:h for ip,h in zip(ips,hosts) if h}
    return {'domain':domain,'dns':dns_records,'ips':ips,'reverse_dns':reverse,'subdomains':subs,'http':http,'sources':['DNS resolvers','SecurityTrails Subdomain API (with crt.sh fallback)','Public HTTP/HTTPS response metadata']}

@app.get('/')
async def home(): return FileResponse('app/static/index.html')
@app.get('/api/health')
async def health(): return {'status':'ok','service':'DomainScope'}
@app.get('/api/enumerate')
async def enumerate_domain(domain: str=Query(...,min_length=1,max_length=253)):
    try: d=normalize_domain(domain)
    except ValueError as e: raise HTTPException(400,str(e))
    try: return await report(d)
    except Exception as e: raise HTTPException(502,'Enumeration failed: '+str(e)[:180])
