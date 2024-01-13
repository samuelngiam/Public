# MySQL

## Info Gathering and Enumeration
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
set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt
set VERBOSE false
```
- Leave `USERNAME` as `root` (high-priority).
- `root` password could be `NULL` i.e. no password required.

```
hydra -l root -P /usr/share/wordlists/metasploit/unix_passwords.txt <ip> mysql
```
- `hydra` does not appear to find `NULL` passwords.

```
[ERROR] Host '<hostname>' is blocked because of many connection errors; unblock with 'mysqladmin flush-hosts'
```
- Brute-forcing MySQL will likely result in your IP being blocked - avoid brute-forcing!

### mysql
```
mysql -u root -p -h <ip>
```
- Press enter for password if `NULL`.

```
MySQL [(none)]> show databases;
MySQL [(none)]> use <database>;
MySQL [(none)]> select * from <table>;
MySQL [(none)]> 
```
- If MySQL is supporting a Web app, hashed credentials for that app can be retrieved.

## Exploitation

## Post-Exploitation
```
cat ~/.mysql_history
```
- `mysql` client logs may contain MySQL credentials and other useful information.

## Others
