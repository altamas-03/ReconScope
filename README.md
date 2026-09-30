# DomainScope

Passive domain-enumeration dashboard for authorized security research.

Features: DNS A/AAAA/MX/NS/TXT/CNAME, reverse DNS, Certificate Transparency subdomains via crt.sh, basic HTTP/HTTPS metadata and JSON download.

## Run

Windows PowerShell:
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Linux/macOS:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000

API: GET /api/enumerate?domain=example.com

Only enumerate domains you own or are explicitly authorized to assess. This project does not perform port scanning, credential attacks, exploitation, or brute-force enumeration.


## Subdomain Finder API update

The subdomain discovery module now supports the SecurityTrails Subdomains API. Set the API key as a server-side environment variable:

PowerShell:
```powershell
$env:SECURITYTRAILS_API_KEY = "YOUR_API_KEY"
```

Then start the app normally. The app calls `GET https://api.securitytrails.com/v1/domain/{hostname}/subdomains`. If no key is configured or the API request fails, it falls back to public Certificate Transparency data from crt.sh. Never put the API key in frontend JavaScript or commit it to Git.

Official documentation: https://docs.securitytrails.com/reference/list-subdomains-old-1
