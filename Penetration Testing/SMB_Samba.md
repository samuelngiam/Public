# SMB/Samba
- Basic nmap scan.
```
nmap -Pn -sV -sC -p445 <ip>
```

- Brute-force SMB login.
```
hydra -l administrator -P /usr/share/wordlists/metasploit/unix_passwords.txt <ip> smb
```
