#!/bin/bash

## Configurable variables
# IF is your interface. Normally eth0.
# TCP_PORTS and UDP_PORTS are arrays. Please enter each port number (or service name) seperated by space. 
IF=eth0
TCP_PORTS=( ) 
UDP_PORTS=( )

## Binaries 
# Paths to the binaries used in this script
IPTABLES=/sbin/iptables
IFCONFIG=/sbin/ifconfig
GREP=/bin/grep
CUT=/usr/bin/cut

## Variables
# SERVER_IP contains the IP-number of interface defined by `IF'
SERVER_IP=$($IFCONFIG $IF | $GREP 'inet addr:' | $CUT -d: -f2 | $CUT -d' ' -f1) 

## Pre configuration
# Flush all current rules
$IPTABLES -F

# Delete all custom chains
$IPTABLES -X

# Add default deny for all chains
$IPTABLES -P INPUT DROP
$IPTABLES -P OUTPUT DROP
$IPTABLES -P FORWARD DROP

## Configuration
# INPUT SECTION

# Accept all connections which is already established.
$IPTABLES -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

# Accept trafic from loopback
$IPTABLES -A INPUT -s 127.0.0.1 -i lo -j ACCEPT

# Accept ingoing icmp-requests and icmp-requests
$IPTABLES -A INPUT -p icmp --icmp-type 8 -d $SERVER_IP -j ACCEPT

# Accept all TCP-ports defined by `TCP_PORTS'
for TCPPORT in ${TCP_PORTS[@]}; do
  $IPTABLES -A INPUT -p tcp --dport $TCPPORT -d $SERVER_IP -j ACCEPT
done

# Accept all UDP-ports defined by `UDP_PORTS'
for UDPPORT in ${UDP_PORTS[@]}; do
  $IPTABLES -A INPUT -p udp --dport $UDPPORT -d $SERVER_IP -j ACCEPT
done

# OUTPUT SECTION 

# Accept all connections which is already established.
$IPTABLES -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

# Accept trafic from loopback
$IPTABLES -A OUTPUT -d 127.0.0.1 -o lo -j ACCEPT

# Accept dns lookups (udp and tcp)
$IPTABLES -A OUTPUT -p tcp --dport 53 -s $SERVER_IP -j ACCEPT
$IPTABLES -A OUTPUT -p udp --dport 53 -s $SERVER_IP -j ACCEPT

# Accept outgoing SSH, HTTP and FTP connections.
$IPTABLES -A OUTPUT -p tcp --dport 22 -s $SERVER_IP -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --dport 20:21 -s $SERVER_IP -j ACCEPT
$IPTABLES -A OUTPUT -p tcp -m multiport --dports 80,443 -s $SERVER_IP -j ACCEPT

# Accept outgoing icmp-echo and icmp-reply
$IPTABLES -A OUTPUT -p icmp --icmp-type 8 -s $SERVER_IP -j ACCEPT
