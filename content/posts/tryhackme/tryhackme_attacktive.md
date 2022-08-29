---
weight: 3
title: "CTF writeup - Attacktive Directory"
date: 2021-03-22T15:57:40+08:00
lastmod: 2021-03-22T16:45:40+08:00
description: "This is my third TryHackMe writeup"

title: CTF writeup - Attacktive Directory
featuredImage: tryhackmebanner.jpg
hiddenfeaturedImage: true

tags: ["TryHackMe", "CTF"]
categories: ["Writeups"]

lightgallery: false
summary: Joining the room __Attacktive Directory__, it tells us that this is a CTF challenge built on Active Directory. 99% of Corporate networks run off of AD. But can you exploit a vulnerable Domain Controller?
---

# TryHackMe - Attacktive Directory [Creators - Spooks]

# {{< figure src="/attacktive/banner.jpg" title="Can you exploit a vulnerable Domain Controller?" >}}

## Summary

1. Recon with nmap & Enumerate the services. SMB on port 139 and 445, and kerberos on 88.
2. Enumeration with enum4linux reveals the domain name, computer name and domain controller.
3. User enumeration with kerbrute against kerberos.
4. With the user accounts we fetch the hashes with  Kerberoasting / ASREPRoasting (users that dont require pre-auth)
5. We get the kerberos hash and crack it with hashcat.
6. Some more enumeration with our acquired hash and smbclient.
7. We find some backup credentials in one of the shares.
8. With the backup account credentials we dump the Domain Controllers NTLM hashes.
9. With the Administrator NTLM hash we gain a shell with pass the hash and / or evil-WinRM

## Recon & Scanning

Basic enumeration starts out with an nmap scan. Nmap is a relatively complex utility that has been refined over the years to detect what ports are open on a device, what services are running, and even detect what operating system is running. It's important to note that not all services may be deteted correctly and not enumerated to it's fullest potential. Despite nmap being an overly complex utility, it cannot enumerate everything. Therefore after an initial nmap scan we'll be using other utilities to help us enumerate the services running on the device.

Our usual Nmap scan:

nmap -Pn -A -T4 -sV -sC -p- 10.10.222.250

{{< figure src="/attacktive/nmap.jpg" title="" >}}

We immidietaly discover some ports that quickly tells us this is a Windows machine with some services worth investigating.

2. Port 445 - Which is SMB running on top of TCP
3. Port 139 - Which is the old SMB that runs on top of NetBIOS.

   

## Enumeration

So, our first step will be to look at the SMB shares using enum4linux and smbclient.

```bash
enum4linux -a 10.10.222.250
```

{{< figure src="/attacktive/enum4linux1.jpg" title="" >}}

We got the domain name.

Also, our NMAP scan just finished and revealed alot more information about the machine.

{{< figure src="/attacktive/nmap2.jpg" title="" >}}

Our scan also reveals the computer name, DNS domain name and even the version of Windows.
We see something else interesting; KERBEROS is also running.

### Enumerating Users via Kerberos

Kerberos is a key authentication service within Active Directory. 
With this port open, we can use a tool called __Kerbrute__ (by Ronnie Flathers @ropnop) to brute force discovery of users, passwords and even password spray!
It is NOT recommended to brute force credentials due to account lockout policies that we cannot enumerate on the domain controller.

__Why Kerbrute you ask?__

It's a tool to quickly bruteforce and enumerate valid Active Directory accounts through Kerberos Pre-Authentication.

- Faster than any other approach
  Potentially stealthier since pre-auth failure does not trigger “traditional” Account failed logon even 4625.
  Can validate usernames or test a login by ONLY sending ONE UDP frame to the KDC (Domain Controller)

We Download the attached userlist and passwordlist. Once we have done that, we can use our Kerbrute attack against the domain by enumerating users.  
We could additionally attempt password spraying attempts or brute force usernames and passwords.

{{< figure src="/attacktive/kerbrute.jpg" title="" >}}

```bash
./kerbrute userenum --dc spookysec.local -d spookysec.local '/home/kali/wordlists/userlistwindows.txt' -t 100
```

We can see here that we have pulled several usernames, including some that stand out; __svc-admin__ and __backup__ . They might prove useful...
Note these down to complete the questions in the room.

## Exploitation

So, we can exploit by abusing Kerberos with an attack method called __ASREPRoasting__.
ASReproasting occurs when a user account has the privilege __"Does not require Pre-Authentication"__ set. 
This means that the account does not need to provide valid identification before requesting a Kerberos Ticket on the specified user account.

### Retrieving Kerberos Ticket

For this we use the __Impacket suite__. Impacket has a tool called "GetNPUsers.py" (located in impacket/examples/GetNPUsers.py) 
that will allow us to query ASReproastable accounts from the Key Distribution Center. The only thing that's necessary to query accounts 
is a valid set of usernames which we enumerated previously via Kerbrute.

{{< figure src="/attacktive/impacket1.jpg" title="" >}}

```bash
python3 GetNPUsers.py -dc-ip 10.10.210.91 spookysec.local/svc-admin -no-pass
```

So we got the Kerberos hash for the svc-admin user. Lets crack it using hashcat and the passwordlist we downloaded earlier!
According to the Hashcat examples wiki, the hashtype is known as “Kerberos 5 AS-REP etype 23”.

We run Hashcat and crack the hashes:

{{< figure src="/attacktive/hashcat.jpg" title="" >}}

```bash
bash hashcat -m 18200 -a 0 krbhashes.txt /home/kali/wordlists/passwordwindows.txt --force
```

Where the “mode” of the hash is 18200.

## More Enumeration:

With a user's account credentials we now have significantly more access within the domain. 
And because we have a valid username and password, We can now attempt to enumerate any shares that the domain controller may be giving out.
We already know that SMB is running, so lets hop on to SMBclient!

{{< figure src="/attacktive/smbclient.jpg" title="" >}}

```bash
smbclient -L 10.10.210.91 -U svc-admin 
smbclient \\\\10.10.210.91\\backup -U 'svc-admin'
dir
more backup_credentials.txt
```

{{< figure src="/attacktive/credentials.jpg" title="" >}}

Interesting! We found what appears to be credentials for the “backup” user account. 
It looks like it is encoded with base64. Lets go to Cyberchef and decode it:

{{< figure src="/attacktive/cyberchef.jpg" title="" >}}

### Dumping NTLM hashes

{{< figure src="/attacktive/ntlmdump.jpg" title="" >}}
Great! We got the Administrator hash.
This opens up a couple of different paths for us.

1. Passing the hash with PSEXEC
2. Evil-WINRM - which gives us a shell administrator privileges in this case

### Gaining a shell

__PsExec__

{{< figure src="/attacktive/psexec.jpg" title="" >}}

```bash
psexec.py -hashes “inserthasheshere” administrator@spookysec.local
```



#### __Evil-WinRM__

{{< figure src="/attacktive/evilwinrm_inserthash.png" title="" >}}

```bash
 evil-winrm -u administrator -H “inserthashhere” -i 10.10.68.12
```

With this shell we can retrieve all the information we want to complete the room:

{{< figure src="/attacktive/complete.jpg" title="" >}}

## Final thoughts

Attacktive Directory was an interesting room. I have never used Evil-WinRM before to gain a shell. Its always nice to learn something new.

