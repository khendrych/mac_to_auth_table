# MAC to SRX auth table 

mac_to_auth_table.py is a Junos on-box Python script mapping MAC address to Juniper Networks SRX firewall local auth-table user-name, supports both IPv4 and IPv6.
Handy also for dual stacked scenarios where user-name (MAC) can be used to correlate PFE logs of directly connected endpoints. 

User authentication table records sample - two records for single dual-stacked computer where role is creation Unix timestamp:
```
> show security user-identification local-authentication-table user 44:85:00:76:17:5e
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


# Test-drive instructions (on-demand op-script):
place ```mac_to_auth-table.py``` to ```/var/db/scripts/op/```
```
    set system scripts op file mac_to_auth-table.py
    set system scripts language python3
```
Then 
```
> op mac_to_auth-table.py
```
#
# Operational instructions (periodic event script): 

place ```mac_to_auth-table.py``` to ```/var/db/scripts/event/```

Do your benchmark WRT interval, worst case SRX300 with old eUSB takes 60s to create 25 records
```
    set system login user python-script-user class super-user
    set system scripts language python3
    set event-options generate-event 2-minutes time-interval 120
    set event-options policy mac_to_auth-table events 2-minutes
    set event-options policy mac_to_auth-table then event-script mac_to_auth-table.py
    set event-options event-script file mac_to_auth-table.py python-script-user python-script-user
```
# Common instructions for both op and event scripts:
Configure variables in script CONFIGURATION section 

**sets of IPv4 and IPv6 interfaces of interest**
```
v4_int = { 'ge-0/0/1.0', 'ge-0/0/2.11', 'ge-0/0/2.12', 'ge-0/0/2.13' }
v6_int = { 'ge-0/0/1.0', 'ge-0/0/2.11', 'ge-0/0/2.14' }
```

**TTL of SRX Auth-Table record in seconds, taken into account upon every ARP/ND flap, not extended with ARP/ND re-appearance**
```
flapping_ttl = 3600
```

**verbose soutput (stdout), useful in op script mode (unlike syslog dumps data structures), [0|1]**
```
debug = 0
```

**user.info logging to SYSLOG, 0 to disable, 1 normal, 2 verbose (similar to debug=1)**
```
syslog = 1
```
**enables use of aliases defined in mac_aliases dictionary, [0|1]**
```
use_mac_aliases = 0
```

**include MAC in alias pushed to auth table (alias__MAC), [0|1]**
```
include_mac_in_alias = 0
```

**dictionary with aliases for known MAC addresses, human friendly, remember to clear old Auth-Table records**

mac_aliases = {
'44:85:00:76:17:5e': 'HOST1',
'52:54:00:d2:38:02': 'HOST2',
'00:21:cc:b9:d5:c9': 'HOST3'
}
```

**enables manual auth-table records defined below, do not use for hosts directly connected to interfaces listed above [0|1]**
```
use_ip_users = 0
```

**manual auth-table records dictionary, for tracking few IPs which are not directly connected**
```
ip_users = {
'192.168.9.3': 'HOST1',
'2a02:cbf0:8500:f::3': 'HOST1',
'192.168.9.4': 'HOST2',
'2a02:cbf0:8500:f::4': 'HOST2'
}
```

# Final Junos side configuration

To avoid CSCRIPT_SECURITY_WARNING event log about unsigned script:

```
    set event-options event-script file mac_to_auth-table.py checksum sha-256 [ sha256 mac_to_auth-table.py ]
```
To trigger user-name recording for policies without source-identity match, for example:
```
    set security zones security-zone trust source-identity-log
```
#

