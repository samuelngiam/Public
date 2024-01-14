# MySQL
- Basic nmap scan.
```
nmap -Pn -sV -sC -p3306 <ip>
```

- Check for existing exploits.
```
searchsploit MySQL <version>
```
```
search MySQL <version>
```

- Check MySQL version.
```
use auxiliary/scanner/mysql/mysql_version
```

- Brute-force MySQL login.
  - Focus on root.
  - root password can be NULL.
  - hydra does not attempt NULL password?
```
use auxiliary/scanner/mysql/mysql_login
set USERNAME root
set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt
set VERBOSE false
```
```
hydra -l root -P /usr/share/wordlists/metasploit/unix_passwords.txt <ip> mysql
```

- Brute-forcing can result in host being blocked.
  - Need shell on target and MySQL account to run `mysqladmin flush-hosts`.
  - Avoid brute-forcing MySQL? Test for NULL credentials manually.
```
[ERROR] Host '<hostname>' is blocked because of many connection errors; unblock with 'mysqladmin flush-hosts'
```

- Connect to MySQL remotely.
  - Press Enter for password if NULL.
```
mysql -u root -p -h <ip>
```

- Basic SQL commands.
```
show databases;
use <database>;
show tables;
select * from <table>;
```

- Check users' mysql history file for credentials and other information.
```
cat ~/.mysql_history
```

- Check Web app config file for MySQL root password e.g. WordPress (WAMP).
  - Requires admin privileges.
```
meterpreter > cat C:\\wamp\\www\\wordpress\\wp-config.php

/** MySQL database username */
define('DB_USER', 'root');

/** MySQL database password */
define('DB_PASSWORD', '');
```
