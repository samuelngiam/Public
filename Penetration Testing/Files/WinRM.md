# WinRM

```
nmap -Pn -sV -p5985,5986 <ip>
```
```
use auxiliary/scanner/winrm/winrm_login
set USER_FILE /usr/share/wordlists/metasploit/unix_users.txt
set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt
set VERBOSE false
```
