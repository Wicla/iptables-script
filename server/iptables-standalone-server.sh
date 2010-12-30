#!/bin/bash
####################### READ THIS INTRODUCTION #################################
# This script allows some generic input and output traffic (see list below, please keep it updated if file is edited).
# It also has variables which allows adding ports dynamically without editing the script in its whole.
# Default policy is to DENY both incoming and outgoing traffic if not explicitly told not to.
#
# Following is a list of allowed INPUT traffic.
# * RELATED and ESTABLISHED connections
# * loopback (lo) connections
# * SSH connections (goes through PROTECTSSH chain)
# * ICMP requests

# Following is a list of allowed OUTPUT traffic.
# * RELATED and ESTABLISHED connections
# * DNS requests
# * SSH connections
# * FTP/FTP-data connections
# * HTTP/HTTPS connections
# * Broadcasts
# * ICMP requests

####################### CONFIGURATION BEGINS HERE ##############################

# IF is your interface. Normally eth0.
IF=eth0

# IN_TCP_PORTS, IN_UDP_PORTS, OUT_TCP_PORTS and OUT_UDP_PORTS are arrays. Please enter each port number (or service name) seperated by space.
# Dynamically opened ports. Whitespace equals new value. Both port number and service name allowed (see /etc/services)
IN_TCP_PORTS=( ) 
IN_UDP_PORTS=( )
OUT_TCP_PORTS=( )
OUT_UDP_PORTS=( )

# Used for reject. Reject first 10 packets each 10 minute, then just drop them. 
LIMIT="-m hashlimit --hashlimit 10/minute --hashlimit-burst 10 --hashlimit-mode srcip --hashlimit-name limreject" 

# IP contains the IP-number of interface `IF'
# BCAST contains the broadcast adress of interface `IF'
IP=($(ifconfig $IF)); IP=$(echo ${IP[6]#*:})
BCAST=($(ifconfig $IF)); BCAST=$(echo ${IP[7]#*:})

LOGGING=true
LOGLIMIT='-m limit --limit 1/min --limit-burst 1'

####################### CONFIGURATION ENDS HERE ################################


####################### BINARIES ###############################################

# Paths to frequently used binaries 
IPTABLES=/sbin/iptables

####################### PREPARE FOR CONFIGURATION ##############################

# Flush (remove) all current iptables rules
${IPTABLES} -F

# Remove all user-defined chains
${IPTABLES} -X

# Set defauly policy - Drop everything
${IPTABLES} -P INPUT DROP
${IPTABLES} -P OUTPUT DROP
${IPTABLES} -P FORWARD DROP


####################### CUSTOM DEFINED CHAINS ##################################

# Protect against SSH bruteforce.
# More than 5 connections on the ssh port and it gets blocked for 60 seconds
SSHCHAIN=PROTECTSSH
${IPTABLES} -N $SSHCHAIN
${IPTABLES} -A $SSHCHAIN -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 5 --name SSHBLOCK --rsource -j DROP
${IPTABLES} -A $SSHCHAIN -p tcp --dport 22 -m state --state NEW -m recent --set --name SSHBLOCK --rsource
${IPTABLES} -A $SSHCHAIN -p tcp --dport 22 -j ACCEPT

####################### IPTABLES INPUT RULES ###################################

# Accept all incomming connections which is related or already established
${IPTABLES} -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

# Accept connections from loopback
${IPTABLES} -A INPUT -i lo -j ACCEPT

# Send SSH connections to $SSHCHAIN chain.
${IPTABLES} -A INPUT -p tcp --dport 22 -d ${IP} -j $SSHCHAIN

# Accept all custom TCP-ports defined by `IN_TCP_PORTS'
for TCPPORT in ${IN_TCP_PORTS[@]}; do
  ${IPTABLES} -A INPUT -p tcp --dport ${TCPPORT} -d ${IP} -j ACCEPT
done

# Accept all custom UDP-ports defined by `IN_UDP_PORTS'
for UDPPORT in ${IN_UDP_PORTS[@]}; do
  ${IPTABLES} -A INPUT -p udp --dport ${UDPPORT} -d ${IP} -j ACCEPT
done

# Accept incomming icmp-requests
${IPTABLES} -A INPUT -p icmp --icmp-type 8 -d ${IP} -j ACCEPT
# Block incomming brodcast
${IPTABLES} -A INPUT -m pkttype --pkt-type broadcast -j DROP

if [ $LOGGING ]; then
  ${IPTABLES} -A INPUT ${LOGLIMIT} -j LOG
fi


# Be polite and reject packages instead of just dropping them, to a limit.
${IPTABLES} -A INPUT -p icmp ${LIMIT} -j REJECT --reject-with icmp-admin-prohibited
${IPTABLES} -A INPUT -p udp ${LIMIT} -j REJECT --reject-with icmp-port-unreachable
${IPTABLES} -A INPUT -p tcp ${LIMIT} -j REJECT --reject-with tcp-reset


####################### IPTABLES OUTPUT RULES ##################################

# Accept all outgoing connections which is established or already established.
${IPTABLES} -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

# Accept outgoing connections from lo interface
${IPTABLES} -A OUTPUT -o lo -j ACCEPT

# Accept dns lookups (udp and tcp)
${IPTABLES} -A OUTPUT -p tcp --dport 53 -s ${IP} -j ACCEPT
${IPTABLES} -A OUTPUT -p udp --dport 53 -s ${IP} -j ACCEPT

# Accept outgoing SSH, HTTP and FTP connections.
${IPTABLES} -A OUTPUT -p tcp --dport 22 -s ${IP} -j ACCEPT
${IPTABLES} -A OUTPUT -p tcp --dport 20:21 -s ${IP} -j ACCEPT
${IPTABLES} -A OUTPUT -p tcp -m multiport --dports 80,443 -s ${IP} -j ACCEPT

# Accept all custom TCP-ports defined by `OUT_UDP_PORTS'
for TCPPORT in ${OUT_TCP_PORTS[@]}; do
  ${IPTABLES} -A OUTPUT -p tcp --dport ${TCPPORT} -s ${IP} -j ACCEPT
done

# Accept all custom UDP-ports defined by `OUT_UDP_PORTS'
for UDPPORT in ${OUT_UDP_PORTS[@]}; do
  ${IPTABLES} -A OUTPUT -p udp --dport ${UDPPORT} -s ${IP} -j ACCEPT
done

# Accept outgoing icmp-requests
${IPTABLES} -A OUTPUT -p icmp --icmp-type 8 -s ${IP} -j ACCEPT

# Accept outgoing broadcast messages
${IPTABLES} -A OUTPUT -d ${BCAST} -j ACCEPT
${IPTABLES} -A OUTPUT -d 255.255.255.255 -j ACCEPT

if [ $LOGGING ]; then
  ${IPTABLES} -A OUTPUT ${LOGLIMIT} -j LOG
fi

# vim: set expandtab ts=2 sw=2:
