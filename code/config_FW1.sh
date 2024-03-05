#!/bin/bash

# Flush existing rules and set to DROP by default
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# Allow established and related connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# NAT Rules
# Extern
iptables -t nat -A PREROUTING -d 172.32.4.100 -p tcp --dport 22 -j DNAT --to-destination 172.31.6.6:22 # SSH
iptables -t nat -A PREROUTING -d 172.32.4.100 -p tcp --dport 25 -j DNAT --to-destination 172.31.6.5:25 # SMTP(S)
iptables -t nat -A PREROUTING -d 172.32.4.100 -p tcp --dport 993 -j DNAT --to-destination 172.31.6.5:993 # IMAPS

# Intern
iptables -t nat -A POSTROUTING -s 172.31.6.6 -p tcp --dport 22 -o eth0 -j SNAT --to-source 172.32.4.100 # SSH to Internet
iptables -t nat -A POSTROUTING -s 172.31.6.6 -p tcp --dport 22 -o eth1 -j SNAT --to-source 172.32.5.1 # SSH to PWEB
iptables -t nat -A POSTROUTING -s 172.31.6.5 -p tcp --dport 25 -o eth0 -j SNAT --to-source 172.32.4.100 # SMTP(S) to Internet
iptables -t nat -A POSTROUTING -s 172.31.6.5 -p tcp --dport 993 -o eth0 -j SNAT --to-source 172.32.4.100 # IMAPS to Internet
iptables -t nat -A POSTROUTING -s 172.31.5.3 -p udp --dport 53 -o eth0 -j SNAT --to-source 172.32.4.100 # LDNS to Internet
iptables -t nat -A POSTROUTING -s 172.31.5.3 -p tcp --dport 53 -o eth0 -j SNAT --to-source 172.32.4.100 # LDNS to Internet
iptables -t nat -A POSTROUTING -s 172.31.5.4 -p tcp --dport 80 -o eth0 -j SNAT --to-source 172.32.4.100 # HTTP to Internet
iptables -t nat -A POSTROUTING -s 172.31.5.4 -p tcp --dport 443 -o eth0 -j SNAT --to-source 172.32.4.100 # HTTP to Internet
iptables -t nat -A POSTROUTING -s 172.31.5.4 -p tcp --dport 80 -o eth1 -j SNAT --to-source 172.32.5.1 # HTTP to PWEB
iptables -t nat -A POSTROUTING -s 172.31.5.4 -p tcp --dport 443 -o eth1 -j SNAT --to-source 172.32.5.1 # HTTP to PWEB

# High-Level Rules

# Incoming traffic for z-mail-ssh
iptables -A FORWARD -p tcp --dport 993 -d 172.31.6.5 -m conntrack --ctstate NEW -j ACCEPT # Internet to MAIL (IMAPS)
iptables -A FORWARD -p tcp --dport 25 -d 172.31.6.5 -m conntrack --ctstate NEW -j ACCEPT # Internet to MAIL (SMTP)
iptables -A FORWARD -p tcp --dport 22 -d 172.31.6.6 -m conntrack --ctstate NEW -j ACCEPT # Internet to SSH
iptables -A FORWARD -d 172.31.6.0/24 -j DROP # input deny

# Outgoing traffic for z-mail-ssh
iptables -A FORWARD -p tcp --dport 22 -s 172.31.6.6 -m conntrack --ctstate NEW -j ACCEPT # SSH to Internet
iptables -A FORWARD -p tcp --dport 25 -s 172.31.6.5 -m conntrack --ctstate NEW -j ACCEPT # MAIL (SMTP) to Internet
iptables -A FORWARD -s 172.31.6.0/24 -j DROP # output deny

# Incoming traffic for z-http
iptables -A FORWARD -d 172.31.5.0/24 -j DROP # input deny

# Outgoing traffic for z-http
iptables -A FORWARD -p tcp --dport 53 -s 172.31.5.3 -m conntrack --ctstate NEW -j ACCEPT # LDNS to Internet
iptables -A FORWARD -p udp --dport 53 -s 172.31.5.3 -m conntrack --ctstate NEW -j ACCEPT # LDNS to Internet
iptables -A FORWARD -p tcp --dport 80 -s 172.31.5.4 -m conntrack --ctstate NEW -j ACCEPT # HTTP to Internet
iptables -A FORWARD -p tcp --dport 443 -s 172.31.5.4 -m conntrack --ctstate NEW -j ACCEPT # HTTPS to Internet
iptables -A FORWARD -s 172.31.5.0/24 -j DROP # output deny

# Incoming traffic for z-public
iptables -A FORWARD -p tcp --dport 80 -d 172.32.5.2 -m conntrack --ctstate NEW -j ACCEPT # Internet to PWEB
iptables -A FORWARD -p tcp --dport 443 -d 172.32.5.2 -m conntrack --ctstate NEW -j ACCEPT # Internet to PWEB
iptables -A FORWARD -p tcp --dport 22 -s 172.31.6.6 -d 172.32.5.2 -m conntrack --ctstate NEW -j ACCEPT # SSH to PWEB
iptables -A FORWARD -p tcp --dport 53 -d 172.32.5.3 -m conntrack --ctstate NEW -j ACCEPT # Internet to PDNS
iptables -A FORWARD -p udp --dport 53 -d 172.32.5.3 -m conntrack --ctstate NEW -j ACCEPT # Internet to PDNS
iptables -A FORWARD -d 172.32.5.0/24 -j DROP # input deny

# Outgoing traffic for z-public
iptables -A FORWARD -p tcp --dport 53 -s 172.32.5.3 -m conntrack --ctstate NEW -j ACCEPT # PDNS to Internet
iptables -A FORWARD -p udp --dport 53 -s 172.32.5.3 -m conntrack --ctstate NEW -j ACCEPT # PDNS to Internet
iptables -A FORWARD -s 172.32.5.0/24 -j DROP # output deny

# Other
iptables -A FORWARD -j LOG # Should not happen. Log to be sure.
