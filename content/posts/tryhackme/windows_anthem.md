---
weight: 3
title: "CTF writeup - Windows Anthem"
date: "'format(Sys.Date(), "%B %d, %Y")'"
lastmod: 2022-08-28T22:16:40+08:00
description: "Another late night CTF on the awesome platform TryHackMe"
featuredImage: "tryhackmebanner.jpg"
hiddenfeaturedImage: false

tags: ["TryHackMe", "CTF", "Windows"]
categories: ["Writeups"]

lightgallery: false
summary: The tags on this box tells us that it involves Windows, privesc, RCE and enumeration.

# Windows: Anthem

This is a write-up of the CTF room “Windows: Anthem” on TryHackMe.

# NMAP scan

```bash
┌──(kali㉿kali)-[~]
└─$ nmap -sC -sV 10.10.247.43                                                                                                                                                                                1 ⨯
Starting Nmap 7.92 ( [https://nmap.org](https://nmap.org/) ) at 2022-07-02 14:32 EDT
Nmap scan report for 10.10.247.43
Host is up (0.059s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=WIN-LU09299160F
| Not valid before: 2022-07-01T18:27:25
|_Not valid after:  2022-12-31T18:27:25
|*ssl-date: 2022-07-02T18:33:52+00:00; +1s from scanner time.
| rdp-ntlm-info:
|   Target_Name: WIN-LU09299160F
|   NetBIOS_Domain_Name: WIN-LU09299160F
|   NetBIOS_Computer_Name: WIN-LU09299160F
|   DNS_Domain_Name: WIN-LU09299160F
|   DNS_Computer_Name: WIN-LU09299160F
|   Product_Version: 10.0.17763
|*  System_Time: 2022-07-02T18:32:46+00:00
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

A basic NMAP scan shows us that RDP and Web service on port 80 is open.

# Dirsearch

Running a quick search with GoBuster and Dirsearch reveals that the robots.txt has a password in it. “UmbracoIsTheBest!”

```bash
python3 [dirsearch.py](http://dirsearch.py/) -u [http://10.10.247.43](http://10.10.247.43/) -e php,cgi,html,txt -x 400,401,403 -r -R 4 -t 100
```

```bash
Extensions: php, cgi, html, txt | HTTP method: GET | Threads: 100 | Wordlist size: 10336
Target: [http://10.10.247.43/](http://10.10.247.43/)
[14:40:40] Starting:
[14:40:42] 200 -    5KB - /.aspx
[14:40:50] 301 -  151B  - /.vscode  ->  [http://10.10.247.43/.vscode/](http://10.10.247.43/.vscode/)     (Added to queue)
[14:40:57] 302 -  126B  - /INSTALL  ->  /umbraco/     (Added to queue)
[14:40:57] 302 -  126B  - /Install  ->  /umbraco/
[14:41:02] 200 -    3KB - /Search
[14:42:27] 301 -  118B  - /archive  ->  /
[14:42:37] 200 -    4KB - /authors
[14:42:46] 200 -    5KB - /blog
[14:42:47] 200 -    5KB - /blog/     (Added to queue)
[14:42:57] 200 -    3KB - /categories
[14:44:04] 302 -  126B  - /install/  ->  /umbraco/
[14:44:04] 302 -  126B  - /install  ->  /umbraco/
[14:45:09] 200 -  192B  - **/robots.txt**
```

# OSINT

So the next couple of questions asks us for the name of the site Administrator, e-mail address etc.

There is a poem in one of the blog posts. Googling this poem reveals the name is “Solomon Grundy”.

The e-mail address in one of the blog posts have “JD@anthem.com” in it.

My guess is that Solomon the Admin would have “SG@anthem.com”.

# Admin access

We can log in to the CMS Admin panel with what we know so far.

![Untitled](windows_anthem/Untitled.png)

# Flags

All the flags in Task 2 can be found looking through the source code of the website.

# RDP access

We log into the box with RDP as the regular user SG : UmbracoIsTheBest!.

We get the 2 first flags which is on the desktop and c:\backup, after changing the privileges of the textfile.

For the last flag, we need admin access. 

Using the password we found in the c:\backup\restore.txt, we can browse into c:\users\Administrator and look through the desktop.

![Untitled](windows_anthem/Untitled%201.png)

There it is, the last flag! =)