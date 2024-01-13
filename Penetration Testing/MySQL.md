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
ERROR] Host 'ip-10-10-21-2.ap-southeast-1.compute.internal' is blocked because of many connection errors; unblock with 'mysqladmin flush-hosts'
```
- Brute-forcing MySQL can result in IP being blocked.

## Exploitation

## Post-Exploitation
```
cat ~/.mysql_history
```
- `mysql` client logs may contain MySQL credentials and other useful information.

## Others
