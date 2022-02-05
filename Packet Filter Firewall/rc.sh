#!/bin/sh

####
# 1.1. Internet ip address
# 
#
Internet_IP="10.0.1.1"
Internet_IP_RANGE="10.0.1.0/24"
Internet_BCAST_ADRESS="10.0.1.255"
Internet_IFACE="enp0s8"

####
# 1.2 Client network configuration.
#
#

#
# IP addresses of the client-side network
#
Client_NET_IP="10.0.2.10"
Client_NET_IP_RANGE="10.0.2.0/24"
Client_NET_BCAST_ADRESS="10.0.2.255"
Client_NET_IFACE="enp0s3"


#
# IP aliases for the server (server's IP address)
#
LO_IFACE="lo"
LO_IP="127.0.0.1"
WEB_IP_ADDRESS="127.0.0.1"
#IP aliases for NATed services (this is the GW's ip on client network)
NAT_WEB_IP_ADDRESS="10.0.2.11"

####
# 1.4 IPTables Configuration.
#

IPTABLES="/sbin/iptables"

#
# Needed to initially load modules
#
/sbin/depmod -a	 

#
# flush iptables
#
$IPTABLES -F 
$IPTABLES -X 
$IPTABLES -F -t nat

#####
# 2.1 Required modules
#

/sbin/modprobe ip_tables
/sbin/modprobe ip_conntrack
/sbin/modprobe iptable_filter
/sbin/modprobe iptable_mangle
/sbin/modprobe iptable_nat
/sbin/modprobe ipt_LOG
/sbin/modprobe ipt_limit
/sbin/modprobe ipt_state

#
# Enable ip_forward, this is critical since it is turned off as defaul in 
# Linux.
#
echo "1" > /proc/sys/net/ipv4/ip_forward

#
# Set default policies for the INPUT, FORWARD and OUTPUT chains
#

# Whitelist (Whitelist is preferred)
$IPTABLES -P INPUT DROP
$IPTABLES -P OUTPUT DROP
$IPTABLES -P FORWARD DROP

#Hemendu Roy: allowing pings to 8.8.8.8 only
$IPTABLES -A INPUT -s 10.0.2.10 -d 8.8.8.8 -p icmp --icmp-type 8 -j ACCEPT
$IPTABLES -A FORWARD -s 10.0.2.10 -d 8.8.8.8 -p icmp -j ACCEPT

#Hemendu Roy: allowing access to the demo page
$IPTABLES -A INPUT -p tcp -j ACCEPT
$IPTABLES -A OUTPUT -p tcp -j ACCEPT

#Hemendu Roy: forwarding traffic between internal and public networks
$IPTABLES -A FORWARD -i enp0s3 -o enp0s8 -j ACCEPT
$IPTABLES -A FORWARD -i enp0s8 -o enp0s3 -m state --state ESTABLISHED,RELATED -j ACCEPT
#Hemendu Roy: enabling postrouting
$IPTABLES -t nat -A POSTROUTING -o enp0s8 -j MASQUERADE
