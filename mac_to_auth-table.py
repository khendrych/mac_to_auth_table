#!/usr/bin/python3
"""
Copyright 2021 Karel Hendrych, khendrych@juniper.net

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""
#
# READ FIRST !!!
#
# Quick and dirty script mapping MAC address to SRX local auth-table user-name, supports both IPv4 and IPv6.
# Handy for dual stacked scenarios where user-name (MAC) can be used to correlate PFE logs of directly connected endpoints.
#
# User authentication table records sample - two records for single dual-stacked computer where role is creation Unix timestamp:
# > show security user-identification local-authentication-table user 44:85:00:76:17:5e
#
# Ip-address: 192.168.4.133
# Username: 44:85:00:78:17:5e
# Roles: 1630911747
# 
# Ip-address: 2a02:cbf0:8500:2:69e4:d4bb:6618:230
# Username: 44:85:00:78:17:5e
# Roles: 1630932966
#
# Log record has MAC address as user-name, role is timestamp:
# RT_FLOW_SESSION_CLOSE [reason="TCP FIN" ...  application="SSH" ...  username="44:85:00:76:17:5e" roles="1630932966" ... ]
#
# Thing to remember - new user-name record with existing IP overrides old record having that particular IP.
#
# Script needs to be improved in all aspects for any real life scenario. 
# tested on vSRX3 21.2R1
# version 20210912-01
#
# To-Do: DHCP4 reservations mapping
#
# Test-drive instructions (on-demand op-script):
#   place mac_to_auth-table.py to /var/db/scripts/op/
"""
    set system scripts op file mac_to_auth-table.py
    set system scripts language python3
""" 
#   run > op mac_to_auth-table.py
#
# Operational instructions (periodic event script): 
# (Do your benchmark WRT interval, worst case SRX300 with old eUSB takes 60s to create 25 records)
#   place mac_to_auth-table.py to /var/db/scripts/event/
"""
    set system login user python-script-user class super-user
    set system scripts language python3
    set event-options generate-event 2-minutes time-interval 120
    set event-options policy mac_to_auth-table events 2-minutes
    set event-options policy mac_to_auth-table then event-script mac_to_auth-table.py
    set event-options event-script file mac_to_auth-table.py python-script-user python-script-user
"""
# Common instructions for both op and event scripts:
#   configure variables in CONFIGURATION SECTION below
#
#   to avoid CSCRIPT_SECURITY_WARNING event log about unsigned script:
"""
    set event-options event-script file mac_to_auth-table.py checksum sha-256 [ sha256 mac_to_auth-table.py ]
"""
# Finally, to trigger user-name recording for policies without source-identity match, for example:
"""
    set security zones security-zone trust source-identity-log
"""
#
#######################################
#### BEGIN CONFIGURURATON SECTION  ####

#sets of IPv4 and IPv6 interfaces of interest 
v4_int = { 'ge-0/0/1.0', 'ge-0/0/2.11', 'ge-0/0/2.12', 'ge-0/0/2.13' }
v6_int = { 'ge-0/0/1.0', 'ge-0/0/2.11', 'ge-0/0/2.14' }

#TTL of SRX Auth-Table record in seconds, taken into account upon every ARP/ND flap, not extended with ARP/ND re-appearance
flapping_ttl = 3600

#verbose soutput (stdout), useful in op script mode (unlike syslog dumps data structures), [0|1]
debug = 0

#user.info logging to SYSLOG, 0 to disable, 1 normal, 2 verbose (similar to debug=1)
syslog = 1

#enables use of aliases defined in mac_aliases dictionary, [0|1]
use_mac_aliases = 0

#include MAC in alias pushed to auth table (alias__MAC), [0|1] 
include_mac_in_alias = 0

#dictionary with aliases for known MAC addresses, human friendly, remember to clear old Auth-Table records
mac_aliases = {
'44:85:00:76:17:5e': 'HOST1',
'52:54:00:d2:38:02': 'HOST2',
'00:21:cc:b9:d5:c9': 'HOST3'
}

#enables manual auth-table records defined below, do not use for hosts directly connected to interfaces listed above [0|1]
use_ip_users = 0

#manual auth-table records dictionary, for tracking few IPs which are not directly connected
ip_users = {
'192.168.9.3': 'HOST1',
'2a02:cbf0:8500:f::3': 'HOST1',
'192.168.9.4': 'HOST2',
'2a02:cbf0:8500:f::4': 'HOST2'
}

####  END CONFIGURURATON SECTION   ####
#######################################

from jnpr.junos import Device
from jnpr.junos.utils.config import Config
from jnpr.junos.factory.factory_loader import FactoryLoader
from jnpr.junos.exception import *
import yaml
import time
import jcs

arp_nd_table_aggr = {}
auth_table_aggr = {}

unix_ts = int(time.time())

try:
  dev = Device()
  dev.open()

#template for ARP table
  yml = '''
---
ARPTableYml:
  rpc: get-arp-table-information
  args:
    no-resolve: true
  item: arp-table-entry
  key: mac-address
  view: ARPTableView

ARPTableView:
  fields:
    mac: mac-address
    ip: ip-address
    int: interface-name
'''

  globals().update(FactoryLoader().load(yaml.load(yml,Loader=yaml.FullLoader)))
  arp_table = ARPTableYml(dev)
  arp_table.get()

  #populates aggregated ARP/ND dictionary with lists, MAC as key, IPv4 from ARP as value
  for i in arp_table:
    if i.int in v4_int:
      arp_nd_table_aggr.setdefault(i.mac,[]).append(i.ip)

#template for ND table
  yml = '''
---
NDTable:
  rpc: get-ipv6-nd-information
  item: ipv6-nd-entry
  key: ipv6-nd-neighbor-l2-address
  view: NDTableView

NDTableView:
  fields:
    mac: ipv6-nd-neighbor-l2-address
    ip: ipv6-nd-neighbor-address
    int: ipv6-nd-interface-name
    state: ipv6-nd-state
'''

  globals().update(FactoryLoader().load(yaml.load(yml,Loader=yaml.FullLoader)))
  nd_table = NDTable(dev)
  nd_table.get()

  #populates aggregated ARP/ND dictionary with lists, MAC as key, IPv6 from ND as value
  for i in nd_table:
    if i.int in v6_int:
      #skips link-local and incomplete
      if not (i.ip.startswith('fe80') or i.state == 'incomplete'): 
        arp_nd_table_aggr.setdefault(i.mac,[]).append(i.ip)
 
  if debug == 1: 
    print('<MAC-IPv4/IPv6 mappings>') 
    print(arp_nd_table_aggr)
    print('</MAC-IPv4/IPv6 mappings>') 

#Template for SRX Auth-Table
  yml = '''
---
AuthTableYml:
  rpc: get-userfw-local-auth-table-all
  item: local-authentication-table/local-authentication-info
  key: user-name
  view: AuthTableView

AuthTableView:
  fields:
    ip: ip-address
    user: user-name
    roles: role-name-list/role-name
'''

  globals().update(FactoryLoader().load(yaml.load(yml,Loader=yaml.FullLoader)))
  auth_table = AuthTableYml(dev)
  auth_table.get()

  #reads authentication table, creates dictionary with MAC as key, IPs as values in list, cares about aliases
  for i in auth_table:
    #some MAC aliases are in place
    if len(mac_aliases) > 0 and use_mac_aliases == 1:
      #alias_MAC format, MAC extracted directly
      if include_mac_in_alias == 1 and '__' in i.user:
        #extracts MAC from mac_alias format
        mac_alias = i.user.split("__", 1)[1]
        auth_table_aggr.setdefault(mac_alias,[]).append(i.ip)
      #no alias_MAC format, MAC looked up
      else:
        mac_alias = i.user
        for mac_alias_key, mac_alias_value in mac_aliases.items():
          if i.user == mac_alias_value:
            mac_alias = mac_alias_key
            break
        auth_table_aggr.setdefault(mac_alias,[]).append(i.ip)

    #no aliases defined or disabled
    else:
      auth_table_aggr.setdefault(i.user,[]).append(i.ip)

  if debug == 1:
    print('<SRX Auth-Table>') 
    print(auth_table_aggr)
    print('</SRX Auth-Table>') 

  #loads synthetic records for non-directly connected hosts
  if len(ip_users) > 0 and use_ip_users == 1:
    for ip_users_key, ip_users_value in ip_users.items():
      arp_nd_table_aggr.setdefault(ip_users_value,[]).append(ip_users_key) 

    if debug == 1:
      print('<Synthetic Auth-Table records>') 
      print(ip_users)
      print('</Synthetic Auth-Table records>') 

  #function for adding auth-table records
  def add_mac_ip(mac, ip, sibling):
    user_name = mac
    alias = 0     
    #MAC aliases
    if len(mac_aliases) > 0 and use_mac_aliases == 1:
      for mac_alias_key, mac_alias_value in mac_aliases.items():
        if mac_alias_key == mac:
          if include_mac_in_alias == 1:
            user_name =  '{mac_alias_value}__{mac}'.format(mac_alias_value=mac_alias_value, mac=mac)
          else:
            user_name = mac_alias_value
          alias = 1
          break

    #1st IP record for particular MAC
    if sibling == 0:
      if alias == 0 or (alias == 1 and include_mac_in_alias == 1):
        msg = 'Adding user-auth table record: {user_name}, IP: {ip}'.format(user_name=user_name, ip=ip)
      elif alias == 1 and include_mac_in_alias == 0:
        msg = 'Adding user-auth table record: {user_name} ({mac}), IP: {ip}'.format(user_name=user_name, mac=mac, ip=ip)

    #in case of more than 1 IP record for particular MAC
    else:
      if alias == 0 or (alias == 1 and include_mac_in_alias == 1):
        msg = 'Adding sibling user-auth table record: {user_name}, IP: {ip}'.format(user_name=user_name, ip=ip)
      elif alias == 1 and include_mac_in_alias == 0:
        msg = 'Adding sibling user-auth table record: {user_name} ({mac}), IP: {ip}'.format(user_name=user_name, mac=mac, ip=ip)

    if debug == 1:
      print(msg)
    if syslog >= 1:
      jcs.syslog('14', msg)

    try:
      rsp = dev.rpc.request_userfw_local_auth_table_add(user_name=user_name,ip_address=ip,roles=str(unix_ts))
    except Exception as err:
      print(err)
      if syslog >= 1:
        jcs.syslog('14', err)

  #function to check auth-table record TTL and potentially remove, sibling flag is 1 for users with multiple IPs 
  def ageout_mac_ip(mac, ip, sibling):
    alias = 0
    #direct auth table used due to role data
    for i in auth_table:
      if i.ip == ip:
        try:
          #figure out alias if any for log purpose
          if len(mac_aliases) > 0 and use_mac_aliases == 1:
            for mac_alias_key, mac_alias_value in mac_aliases.items():
              if mac_alias_key == mac:
                mac_alias = mac_alias_value
                alias = 1
                break

          #role records unix timestamp of record
          ttl = flapping_ttl - ( unix_ts - int(i.roles))
          #besides < 0 TTL timeout immediately also synthetic records when disabled
          if ttl < 0 or (use_ip_users == 0 and i.ip in ip_users):
            if debug == 1 or syslog >= 1:
              if sibling == 1 and alias == 1:
                msg = 'Removing sibling user-auth table record: {mac_alias} ({mac}), IP: {ip}, TTL: {ttl}[s]'.format(mac_alias=mac_alias, mac=mac, ip=ip, ttl=ttl)
              elif sibling == 0 and alias == 1:
                msg = 'Removing user-auth table record: {mac_alias} ({mac}), IP: {ip}, TTL: {ttl}[s]'.format(mac_alias=mac_alias, mac=mac, ip=ip, ttl=ttl)
              elif sibling == 1 and alias == 0:
                msg = 'Removing sibling user-auth table record: {mac}, IP: {ip}, TTL: {ttl}[s]'.format(mac=mac, ip=ip, ttl=ttl)
              elif sibling == 0 and alias == 0:
                msg = 'Removing user-auth table record: {mac}, IP: {ip}, TTL: {ttl}[s]'.format(mac=mac, ip=ip, ttl=ttl)

              if debug == 1:
                print(msg)
              if syslog >= 1:
                jcs.syslog('14', msg)

            rsp = dev.rpc.request_userfw_local_auth_table_delete_ip(ip_address=i.ip) 

          elif debug == 1 or syslog == 2:
            if sibling == 1 and alias == 1:
              msg = 'Not removing sibling user-auth table record: {mac_alias} ({mac}), IP: {ip}, TTL: {ttl}[s]'.format(mac_alias=mac_alias, mac=mac, ip=ip, ttl=ttl)
            elif sibling == 0 and alias == 1:
              msg = 'Not removing user-auth table record: {mac_alias} ({mac}), IP: {ip}, TTL: {ttl}[s]'.format(mac_alias=mac_alias, mac=mac, ip=ip, ttl=ttl)
            elif sibling == 1 and alias == 0:
              msg = 'Not removing sibling user-auth table record: {mac}, IP: {ip}, TTL: {ttl}[s]'.format(mac=mac, ip=ip, ttl=ttl)
            elif sibling == 0 and alias == 0:
              msg = 'Not removing user-auth table record: {mac}, IP: {ip}, TTL: {ttl}[s]'.format(mac=mac, ip=ip, ttl=ttl)

            if debug == 1:
              print(msg)
            if syslog == 2:
              jcs.syslog('14', msg)

        except Exception as err:
          #triggers during occasions when role is either missing or not unix timestamp(manual records)
          rsp = dev.rpc.request_userfw_local_auth_table_delete_ip(ip_address=i.ip) 
          print(err)
          if syslog >= 1:
            jcs.syslog('14', err)

  #proceed to ageout if auth-table MAC record is present but neither ND/ARP records exist
  for mac in auth_table_aggr:
    if not mac in arp_nd_table_aggr:
      for ip in auth_table_aggr[mac]: 
        ageout_mac_ip(mac,ip,0)

  #walks over ARP/ND and checks for missing/aging records in Auth-Table
  for mac in arp_nd_table_aggr:
    #checks for MACs present in ARP/ND but not it Auth-Table
    if not mac in auth_table_aggr:
      #add new user-auth table record, record unix timestamp as role
      sibling_counter = 0
      for ip in arp_nd_table_aggr[mac]:
        if sibling_counter == 0:
          add_mac_ip(mac,ip,0)
        else:
          add_mac_ip(mac,ip,1)
        sibling_counter = sibling_counter + 1

    #checks auth table for missing/aging sibling IPs when MAC already exists
    if mac in auth_table_aggr:
      if not (set(auth_table_aggr[mac]) == set(arp_nd_table_aggr[mac])):
        #IP record in ND/ARP, but not in Auth-Table, user(MAC) exists, find and add particular IP to existing user-name (MAC)
        diff = set(arp_nd_table_aggr[mac]).difference(set(auth_table_aggr[mac]))
        if diff:
          for ip in diff:
            add_mac_ip(mac,ip,1)

        #IP record not in ND/ARP, but in Auth-Table, proceed to age-out
        diff = set(auth_table_aggr[mac]).difference(set(arp_nd_table_aggr[mac]))
        if diff:
          for ip in diff:
            ageout_mac_ip(mac,ip,1)

except Exception as err:
  print(err)
  if syslog >= 1:
    jcs.syslog('14', err)

dev.close()
