---
layout: post
title: "Sendai (Medium) — VulnLab"
date: 2025-04-07 22:00:00 +0100
categories:
  - Writeups
  - VulnLab
tags:
  - Sendai
  - Medium
  - Windows
  - ActiveDirectory
  - ADCS
  - ESC4
  - gMSA
image: assets/img/Writeup/VulnLab/Sendai/sendai-01.png
description: Medium Windows Active Directory machine writeup by Uzurly (VulnLab) — ADCS ESC4
---

# Enumeration

```
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
389/tcp  open  ldap          AD LDAP – Domain: sendai.vl
443/tcp  open  ssl/http      Microsoft IIS httpd 10.0
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
```

The LDAP certificate's Subject Alternative Name includes an `othername` OID (`1.3.6.1.4.1.311.25.1`, the NTDS CA GUID extension) — a strong early hint that ADCS is in play on this domain.

```
echo "10.10.85.183 sendai.vl dc.sendai.vl" >> /etc/hosts
```

## SMB — Guest access

```
nxc smb dc.sendai.vl -u 'guest' -p ''
```

![1](/assets/img/Writeup/VulnLab/Sendai/sendai-01.png)

Guest access was enough to RID-brute the domain and build a user list:

![2](/assets/img/Writeup/VulnLab/Sendai/sendai-02.png)
![3](/assets/img/Writeup/VulnLab/Sendai/sendai-03.png)

# From "must change password" to two live accounts

Spraying blank/known values against that user list turned up two accounts flagged **must-change-password**:

![4](/assets/img/Writeup/VulnLab/Sendai/sendai-04.png)

Setting a new password on both (a must-change flag lets any client set one without knowing the old value) got me two working sets of credentials:

![5](/assets/img/Writeup/VulnLab/Sendai/sendai-05.png)
![6](/assets/img/Writeup/VulnLab/Sendai/sendai-06.png)

With valid creds in hand, `bloodhound-python` against both accounts mapped the domain:

![7](/assets/img/Writeup/VulnLab/Sendai/sendai-07.png)
![8](/assets/img/Writeup/VulnLab/Sendai/sendai-08.png)

# Privilege escalation chain

## GenericAll → group membership

Marking `Thomas.Powell` and `Elliot.Yates` as owned in BloodHound surfaced a `GenericAll` right for `Thomas.Powell` over the `ADMSVC` group:

![9](/assets/img/Writeup/VulnLab/Sendai/sendai-09.png)

`GenericAll` on a group means I can just add members to it directly:

```
net rpc group addmem "ADMSVC" "MGTSVC$" -U "sendai.vl"/"Thomas.Powell"%"Idkk01?" -S "dc.sendai.vl"
```

![10](/assets/img/Writeup/VulnLab/Sendai/sendai-10.png)

## Reading a gMSA's password

`MGTSVC$` being in `ADMSVC` was the point — group-managed service account passwords are readable by whichever principals are authorized to, and membership in the right group is exactly that authorization. [gMSADumper](https://github.com/micahvandeusen/gMSADumper) pulled the gMSA's password remotely and converted it to its NT hash:

![11](/assets/img/Writeup/VulnLab/Sendai/sendai-11.png)

## Landing on the gMSA account

```
evil-winrm -i dc.sendai.vl -u 'mgtsvc$' -H <nt hash>
..\PrivescCheck.ps1; Invoke-PrivescCheck -Extended
```

![12](/assets/img/Writeup/VulnLab/Sendai/sendai-12.png)

# ADCS — ESC4

`PrivescCheck` and a look at certificate templates pointed straight at ADCS. Running Certipy against another compromised account, `Clifford.Davey`:

```
certipy find -u "Clifford.Davey" -p "RFmoB2WplgE_3p" -dc-ip 10.10.97.41 -enable -stdout -vulnerable
```

![13](/assets/img/Writeup/VulnLab/Sendai/sendai-13.png)

BloodHound showed `Clifford.Davey` belongs to `ca-operators` — a group with write access over a certificate template, i.e. an [ESC4](https://www.thehacker.recipes/ad/movement/adcs/access-controls#certificate-templates-esc4) condition: whoever can edit a template's security descriptor can reconfigure it to be as exploitable as a purpose-built ESC1 template, then request a certificate that authenticates as any user — including a Domain Admin.

![14](/assets/img/Writeup/VulnLab/Sendai/sendai-14.png)
![15](/assets/img/Writeup/VulnLab/Sendai/sendai-15.png)
![16](/assets/img/Writeup/VulnLab/Sendai/sendai-16.png)

# Domain Admin

With a certificate issued for a Domain Admin identity, the final step was straightforward:

```
evil-winrm -i dc.sendai.vl -u 'Administrator' -H <nt hash from certificate authentication>
```

![17](/assets/img/Writeup/VulnLab/Sendai/sendai-17.png)

# Takeaways

- A certificate's SAN referencing the NTDS CA GUID OID is a fast, reliable tell that ADCS is present before you've even touched port 443.
- "Must change password" accounts are effectively open doors — any client can set a new password without knowing the old one.
- `GenericAll` on a group is as good as `GenericAll` on every member's effective privileges once you add an account you control.
- Group-Managed Service Account passwords are only as safe as the group memberships that are allowed to read them — chaining a `GenericAll`-on-group right straight into gMSA password disclosure turned a low-priv foothold into a service account.
- ESC4 (a writable certificate template ACL) collapses to ESC1 the moment you can edit the template yourself — `ca-operators` membership was the whole game here.
