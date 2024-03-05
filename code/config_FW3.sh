#!/bin/bash

# Flush existing rules and set to DROP by default
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# Allow established and related connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# High-Level Rules

# Incoming traffic for z-nfs
iptables -A FORWARD -p tcp --dport 111 -s 192.168.3.2 -d 10.10.3.2 -m conntrack --ctstate NEW -j ACCEPT # HONEYPOT to NFS (portmapper)
iptables -A FORWARD -p udp --dport 111 -s 192.168.3.2 -d 10.10.3.2 -m conntrack --ctstate NEW -j ACCEPT # HONEYPOT to NFS (portmapper)
iptables -A FORWARD -p tcp --dport 2046 -s 192.168.3.2 -d 10.10.3.2 -m conntrack --ctstate NEW -j ACCEPT # HONEYPOT to NFS (status)
iptables -A FORWARD -p udp --dport 2046 -s 192.168.3.2 -d 10.10.3.2 -m conntrack --ctstate NEW -j ACCEPT # HONEYPOT to NFS (status)
iptables -A FORWARD -p tcp --dport 2047 -s 192.168.3.2 -d 10.10.3.2 -m conntrack --ctstate NEW -j ACCEPT # HONEYPOT to NFS (nlockmgr)
iptables -A FORWARD -p udp --dport 2047 -s 192.168.3.2 -d 10.10.3.2 -m conntrack --ctstate NEW -j ACCEPT # HONEYPOT to NFS (nlockmgr)
iptables -A FORWARD -p tcp --dport 2048 -s 192.168.3.2 -d 10.10.3.2 -m conntrack --ctstate NEW -j ACCEPT # HONEYPOT to NFS (mountd)
iptables -A FORWARD -p udp --dport 2048 -s 192.168.3.2 -d 10.10.3.2 -m conntrack --ctstate NEW -j ACCEPT # HONEYPOT to NFS (mountd)
iptables -A FORWARD -p tcp --dport 2049 -s 192.168.3.2 -d 10.10.3.2 -m conntrack --ctstate NEW -j ACCEPT # HONEYPOT to NFS
iptables -A FORWARD -p udp --dport 2049 -s 192.168.3.2 -d 10.10.3.2 -m conntrack --ctstate NEW -j ACCEPT # HONEYPOT to NFS
iptables -A FORWARD -p tcp --dport 873 -s 192.168.3.3 -d 10.10.3.3 -m conntrack --ctstate NEW -j ACCEPT # U3 to RSYNC
iptables -A FORWARD -p tcp --dport 22 -s 192.168.3.3 -d 10.10.3.3 -m conntrack --ctstate NEW -j ACCEPT # U3 to RSYNC (secured)
iptables -A FORWARD -p tcp --dport 22 -s 10.10.4.6 -d 10.10.3.3 -m conntrack --ctstate NEW -j ACCEPT # SSH to RSYNC
iptables -A FORWARD -d 10.10.3.0/24 -j DROP # input deny

# Outgoing traffic for z-nfs
iptables -A FORWARD -s 10.10.3.0/24 -j DROP # output deny

# Incoming traffic for z-u3
iptables -A FORWARD -p tcp --dport 22 -s 10.10.4.6 -d 192.168.3.2 -m conntrack --ctstate NEW -j ACCEPT # SSH to HONEYPOT
iptables -A FORWARD -d 192.168.3.0/24 -j DROP # input deny

# Outgoing traffic for z-u3
iptables -A FORWARD -p tcp --dport 22 -s 192.168.3.3 -d 10.10.4.6 -m conntrack --ctstate NEW -j ACCEPT # U3 to SSH
iptables -A FORWARD -s 192.168.3.0/24 -j DROP # output deny

# Incoming traffic for z-ssh
iptables -A FORWARD -d 10.10.4.0/24 -j DROP # input deny

# Outgoing traffic for z-ssh
iptables -A FORWARD -s 10.10.4.0/24 -j DROP # output deny

# Other
iptables -A FORWARD -j LOG # Should not happen. Log to be sure.
