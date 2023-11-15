# Finding the machine's IP

## Finding the right interface

To find the interface to scan with `nmap`, use `ip a` to reveal all interfaces and their IP addresses / masks.

### libvirt

Virtual interfaces created using `libvirt` will have a name like `virbrX` or `virbrX-nic`.

### virtualbox

If you're using VirtualBox and a host-only network, the interface will be named `vboxnetX`.

## Scanning the network

```
vboxnet0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 0a:00:27:00:00:00 brd ff:ff:ff:ff:ff:ff
    inet 192.168.56.1/24 brd 192.168.56.255 scope global vboxnet0
       valid_lft forever preferred_lft forever
    inet6 fe80::800:27ff:fe00:0/64 scope link proto kernel_ll 
       valid_lft forever preferred_lft forever
```

Here the address mask is `192.168.56.1/24`, using `nmap` we can scan the network for hosts:

```sh
$ nmap -sn 192.168.56.1/24
Starting Nmap 7.93 ( https://nmap.org ) at 2023-11-15 21:52 CET
Nmap scan report for 192.168.56.1
Host is up (0.00016s latency).
Nmap scan report for 192.168.56.101
Host is up (0.00052s latency).
```

Since `.1` is the gateway, we can assume that `.101` is our VM.

# Scanning the network

```sh
$ nmap -p- 192.168.56.1/24
Nmap scan report for 192.168.56.101
Host is up (0.00016s latency).
Not shown: 65529 closed tcp ports (conn-refused)
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
80/tcp  open  http
143/tcp open  imap
443/tcp open  https
993/tcp open  imaps
```

So there's a lot of services running here.

# HTTPS

Fuzzing the HTTPS service using `ffuf -w fuzz-Bo0oM.txt -u https://192.168.56.101/FUZZ -mc 200,301,302,307,401,403,405,500` reveals multiple endpoints :

```
cgi-bin/                [Status: 403, Size: 291, Words: 21, Lines: 11]
forum/                  [Status: 200, Size: 4984, Words: 312, Lines: 81]
phpmyadmin/             [Status: 200, Size: 7530, Words: 938, Lines: 127]
phpmyadmin/index.php    [Status: 200, Size: 7530, Words: 938, Lines: 127]
server-status/          [Status: 403, Size: 297, Words: 21, Lines: 11]
webmail/src/configtest.php [Status: 403, Size: 309, Words: 21, Lines: 11]
webmail/                [Status: 302, Size: 0, Words: 1, Lines: 1]
```

## Forum

Going into the forum, there are multiple posts made, one called "Probleme login ?" by `lmezard`.

The content of the post seems to be a section of a `/var/log/auth.log` file, but there's a line that's a bit weird:
```
Oct 5 08:45:29 BornToSecHackMe sshd[7547]: Failed password for invalid user !q\]Ej?*5K5cy*AJ from 161.202.39.38 port 57764 ssh2
```

It seems like someone made a mistake when writing the username, and pasted the password instead. The password is `!q\]Ej?*5K5cy*AJ`.

After that, the next user to log-in is `lmezard`, so we can try to spray the password on that user, on every services the VM hosts.

| Service | Result |
|---------|--------|
| SSH     | ❌ |
| FTP     | ❌ |
| Webmail | ❌ |
| phpMyAdmin | ❌ |
| Forum | ✅ |

The forum works, nothing special to see, but in the user's profile, there's an email address: `laurie@borntosec.net`

## SquirrelMail

Attempting to log into SquirrelMail with that email address and the password we found earlier works, and we can see an email from `qudevide@mail.borntosec.net` with the subject `DB Access`, it contains a username:password combo for.. the database.

`root/Fg-'kKXBj87E:aJ$`

The other inboxes (Trash, Sent, Drafts) are empty.

We can login to phpMyAdmin with the credentials we found.

## phpMyAdmin

| Table name | Content |
|------------|---------|
| `mlf2_banlists` | Empty |
| `mlf2_categories` | Empty |
| `mlf2_entries` | Posts / replies |
| `mlf2_entries_cache` | Cache for the posts |
| `mlf2_logincontrol` | Empty |
| `mlf2_pages` | Empty |
| `mlf2_settings` | `MyLittleForum` settings |
| `mlf2_smilies` | Configured aliases for smilies (we don't care) |
| `mlf2_userdata` | ID, type, password hash, email, misc. |
| `mlf2_userdata_cache` | Empty |
| `mlf2_useronline` | List of users currently online (we don't care) |

We can escalate the user `lmezard` to admin by changing the `type` field in `mlf2_userdata` from `0` to `2`.

| Type number | Description |
|-------------|-------------|
| `0` | User |
| `1` | Moderator |
| `2` | Admin |
| Something else | Defaults to User |


# Reversing forum's hashes

Looking at MyLittleForum's source code

```php
function is_pw_correct($pw,$hash)
 {
  if(strlen($hash)==50) // salted sha1 hash with salt
   {
    $salted_hash = substr($hash,0,40);
    $salt = substr($hash,40,10);
    if(sha1($pw.$salt)==$salted_hash) return true;
    else return false;
   }
  elseif(strlen($hash)==32) // md5 hash generated in an older version
   {
    if($hash == md5($pw)) return true;
    else return false;
   }
  else return false;
 }
```

It seems like the first 40 characters are the hash, and the last 10 are the salt.

The forum uses the `sha1` algorithm. To know how to reverse it, we will try to get the hash from the password we found.

In the database the stored hash is : `0171e7dbcbf4bd21a732fa859ea98a2950b4f8aa1e5365dc90`

The hash is : `0171e7dbcbf4bd21a732fa859ea98a2950b4f8aa`, and the salt should be : `1e5365dc90`.

```sh
$ echo -n '!q\]Ej?*5K5cy*AJ1e5365dc90' | sha1sum
0171e7dbcbf4bd21a732fa859ea98a2950b4f8aa
```

Doing the same (reverse) operation with the `admin` user :

The hash is : `ed0fd64f25f3bd3a54f8d272ba93b6e76ce7f3d0`, and the salt is : `516d551c28`.

Let's try to use `rockyou.txt` wordlist along with `hashcat` to crack the password.

```sh
# Concatenate the salt to each word in the wordlist
# because I don't know how to do it with hashcat :^)
$ sed 's/$/516d551c28/' rockyou.txt > rockyou-salted.txt
$ hashcat -m 100 -a 0 -O -o cracked.txt ed0fd64f25f3bd3a54f8d272ba93b6e76ce7f3d0 rockyou-salted.txt
Session..........: hashcat                                
Status...........: Exhausted
Hash.Mode........: 100 (SHA1)
Hash.Target......: ed0fd64f25f3bd3a54f8d272ba93b6e76ce7f3d0
Time.Started.....: Wed Nov 15 23:27:08 2023 (1 sec)
Time.Estimated...: Wed Nov 15 23:27:09 2023 (0 secs)
Kernel.Feature...: Optimized Kernel
Guess.Base.......: File (rockyou-salted.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........: 14646.4 kH/s (0.25ms) @ Accel:256 Loops:1 Thr:128 Vec:1
Recovered........: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)
Progress.........: 14343901/14343901 (100.00%)
Rejected.........: 28307/14343901 (0.20%)
Restore.Point....: 14343901/14343901 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[30323536313432363535313664353531633238] -> $HEX[042a0337c2a156616d6f73210335313664353531633238]
Hardware.Mon.#1..: Temp: 31c Fan:  0% Util: 19% Core:2520MHz Mem:10501MHz Bus:16

Started: Wed Nov 15 23:27:03 2023
Stopped: Wed Nov 15 23:27:10 2023
```

Basically we took the L here, it's not in the wordlist.