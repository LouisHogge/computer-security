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

# Incoming traffic for z-lweb
iptables -A FORWARD -p tcp --dport 21 -s 192.168.1.0/24 -d 10.10.2.2 -m conntrack --ctstate NEW -j ACCEPT # U1 to LWEB (ftp)
iptables -A FORWARD -p tcp --dport 80 -s 192.168.1.0/24 -d 10.10.2.2 -m conntrack --ctstate NEW -j ACCEPT # U1 to LWEB (http)
iptables -A FORWARD -p tcp --dport 80 -s 192.168.2.0/24 -d 10.10.2.2 -m conntrack --ctstate NEW -j ACCEPT  # U1 to LWEB (http)
iptables -A FORWARD -d 10.10.2.0/24 -j DROP # input deny

# Outgoing traffic for z-lweb
iptables -A FORWARD -s 10.10.2.0/24 -j DROP # output deny

# Incoming traffic for z-u1
iptables -A FORWARD -p tcp --dport 22 -s 10.10.1.6 -d 192.168.1.0/24 -m conntrack --ctstate NEW -j ACCEPT # SSH to U1
iptables -A FORWARD -d 192.168.1.0/24 -j DROP # input deny

# Outgoing traffic for z-u1
iptables -A FORWARD -p tcp --dport 3128 -s 192.168.1.0/24 -d 10.10.1.4 -m conntrack --ctstate NEW -j ACCEPT # U1 to HTTP
iptables -A FORWARD -p tcp --dport 53 -s 192.168.1.0/24 -d 10.10.1.3 -m conntrack --ctstate NEW -j ACCEPT # U1 to LDNS
iptables -A FORWARD -p udp --dport 53 -s 192.168.1.0/24 -d 10.10.1.3 -m conntrack --ctstate NEW -j ACCEPT # U1 to LDNS
iptables -A FORWARD -p tcp --dport 25 -s 192.168.1.0/24 -d 10.10.1.5 -m conntrack --ctstate NEW -j ACCEPT # U1 to MAIL (SMTP)
iptables -A FORWARD -p tcp --dport 143 -s 192.168.1.0/24 -d 10.10.1.5 -m conntrack --ctstate NEW -j ACCEPT # U1 to MAIL (IMAP)
iptables -A FORWARD -p tcp --dport 993 -s 192.168.1.0/24 -d 10.10.1.5 -m conntrack --ctstate NEW -j ACCEPT # U1 to MAIL (IMAPS)
iptables -A FORWARD -p tcp --dport 22 -s 192.168.1.0/24 -d 10.10.1.6 -m conntrack --ctstate NEW -j ACCEPT # U1 to SSH
iptables -A FORWARD -p udp --dport 67 -s 192.168.1.2 -d 10.10.1.2 -m conntrack --ctstate NEW -j ACCEPT # DHCP R1 to DHCP
iptables -A FORWARD -s 192.168.1.0/24 -j DROP # output deny

# Incoming traffic for z-u2
iptables -A FORWARD -p tcp --dport 22 -s 10.10.1.6 -d 192.168.2.0/24 -m conntrack --ctstate NEW -j ACCEPT # SSH to U2
iptables -A FORWARD -d 192.168.2.0/24 -j DROP # input deny

# Outgoing traffic for z-u2
iptables -A FORWARD -p tcp --dport 3128 -s 192.168.2.0/24 -d 10.10.1.4 -m conntrack --ctstate NEW -j ACCEPT # U2 to HTTP
iptables -A FORWARD -p tcp --dport 53 -s 192.168.2.0/24 -d 10.10.1.3 -m conntrack --ctstate NEW -j ACCEPT # U2 to LDNS
iptables -A FORWARD -p udp --dport 53 -s 192.168.2.0/24 -d 10.10.1.3 -m conntrack --ctstate NEW -j ACCEPT # U2 to LDNS
iptables -A FORWARD -p tcp --dport 25 -s 192.168.2.0/24 -d 10.10.1.5 -m conntrack --ctstate NEW -j ACCEPT # U2 to MAIL (SMTP)
iptables -A FORWARD -p tcp --dport 143 -s 192.168.2.0/24 -d 10.10.1.5 -m conntrack --ctstate NEW -j ACCEPT # U2 to MAIL (IMAP)
iptables -A FORWARD -p tcp --dport 993 -s 192.168.2.0/24 -d 10.10.1.5 -m conntrack --ctstate NEW -j ACCEPT # U2 to MAIL (IMAPS)
iptables -A FORWARD -p udp --dport 67 -s 192.168.2.2 -d 10.10.1.2 -m conntrack --ctstate NEW -j ACCEPT # DHCP R2 to DHCP
iptables -A FORWARD -s 192.168.2.0/24 -j DROP # output deny

# Incoming traffic for z-all-sandwich
iptables -A FORWARD -d 10.10.1.0/24 -j DROP # input deny

# Outgoing traffic for z-all-sandwich
iptables -A FORWARD -s 10.10.1.0/24 -j DROP # output deny

# Other
iptables -A FORWARD -j LOG # Should not happen. Log to be sure.
