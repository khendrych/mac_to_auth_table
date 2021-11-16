# MAC to SRX auth table 

mac_to_auth_table.py is a Junos on-box Python script mapping MAC address to Juniper Networks SRX firewall local auth-table user-name, supports both IPv4 and IPv6.
Handy also for dual stacked scenarios where user-name (MAC) can be used to correlate PFE logs of directly connected endpoints. 

User authentication table records sample - two records for single dual-stacked computer where role is creation Unix timestamp:
```
show security user-identification local-authentication-table user 44:85:00:76:17:5e
Ip-address: 192.168.4.133
Username: 44:85:00:78:17:5e
Roles: 1630911747
 
Ip-address: 2a02:cbf0:8500:2:69e4:d4bb:6618:230
Username: 44:85:00:78:17:5e
Roles: 1630932966
```
Log record has MAC address as user-name, role is timestamp (note that MAC addresses may have their human readable aliases, non-directly connected IPs can have aliases as well):
```
RT_FLOW_SESSION_CLOSE [reason="TCP FIN" ...  application="SSH" ...  username="44:85:00:76:17:5e" roles="1630932966" ... ]
```

For details look at the READ FIRST section of the script.
