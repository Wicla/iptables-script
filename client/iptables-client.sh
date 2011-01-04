#!/bin/bash
####################### READ THIS INTRODUCTION #################################
# This script allows some generic input and output traffic (see list below, please keep it updated if file is edited).
# There're also arrays which can be filled with ports which is wanted to be allowed (in all directions and protocol).
# Default policy is set to DROP all unmatched traffic in both directions.
#
# Since this script was written as a script executed by wicd (network manager) it has some code which allows integration with wicd.
# To disable this code just comment out/remove the code related to wicd (it's clearly marked out further down in the script).
# It gets either wired or wireless as argument which decides which interface the rules are to based upon.
#
# Connections passing through INPUT (incoming):
# * RELATED and ESTABLISHED connections
# * loopback (lo) connections
# * ICMP requests (allow ping)
# * Dynamically definied ports (arrays)
#
# Connections passing through OUTPUT (outgoing):
# * RELATED and ESTABLISHED connections
# * DNS queries
# * SSH connections
# * FTP/FTP-data connections
# * HTTP/HTTPS connections
# * Broadcasts
# * ICMP requests
# * Dynamically definied ports (arrays)

####################### CONFIGURATION BEGINS HERE ##############################

# This section is used by wicd (called as a script on connect). If you're not using it, comment according to guidelines.
# Variable $IF contains your IP-address. It's from this value it gets the source/destination IP- and broadcast-address to allow.
## COMMENT THIS SECTION IF NOT USED ##
if [ "$1" == "wireless" ]; then
  IF=wlan0
elif [ "$1" == "wired" ]; then
  IF=eth0
else
  echo 'Something is wrong.'
  echo 'Missing argument (which should be wireless or wired)'
  echo 'Exiting.'
  exit 1.
fi
## END COMMENTING ##
# Set this variable to a suitable value instead (eth0 for example).
#IF=eth0

# Dynamically opened ports. Whitespace separates each value. Both port number and service name allowed (see /etc/services)
# IN_TCP_PORTS, IN_UDP_PORTS, OUT_TCP_PORTS and OUT_UDP_PORTS are arrays. Please enter each port number (or service name) seperated by space.
IN_TCP_PORTS=( ) 
IN_UDP_PORTS=( )
OUT_TCP_PORTS=( )
OUT_UDP_PORTS=( )

# Used for reject (if no INPUT connection is matched). Reject first 10 packets each 10 minute, then just drop them. 
LIMIT="-m hashlimit --hashlimit 10/minute --hashlimit-burst 10 --hashlimit-mode srcip --hashlimit-name limreject"

# IP contains the IP-address of interface $IF
# BCAST contains the broadcast address of interface $IF
IP=($(ifconfig $IF)); IP=$(echo ${IP[6]#*:})
BCAST=($(ifconfig $IF)); BCAST=$(echo ${IP[7]#*:})

# LOGGING defines if unmatched connections should be logged.
# Possibles values are following:
# * true    -- Logs both INPUT and OUTPUT
# * input   -- Logs INPUT
# * output  -- Logs OUTPUT
LOGGING=false
if [ $LOGGING = true \
  -o $(echo $LOGGING | tr [:lower:] [:upper:]) = INPUT \
  -o $(echo $LOGGING | tr [:lower:] [:upper:]) = OUTPUT ]; then
# Chain for INPUT and OUTPUT for LOGGING
  LOGINPUTCHAIN=LOGINPUT
  LOGOUTPUTCHAIN=LOGOUTPUT
# Loglimit and loglimitburst
  LOGLIMIT='1/min'
  LOGLIMITBURST='1'
fi

####################### CONFIGURATION ENDS HERE ################################


####################### BINARIES ###############################################

# Path to frequently used binaries
IPTABLES=/sbin/iptables

####################### PREPARE FOR CONFIGURATION ##############################

# Flush (remove) all existing IPTables rules
$IPTABLES -F

# Remove all existing user-defined chains
$IPTABLES -X

# Set default policy - Drop everything unmatched
$IPTABLES -P INPUT DROP
$IPTABLES -P OUTPUT DROP
$IPTABLES -P FORWARD DROP


####################### CUSTOM DEFINED CHAINS ##################################

# If LOGGING is true or matches 'INPUT' - INPUT connections are passed through this chain
if [ $LOGGING = true -o $(echo $LOGGING | tr [:lower:] [:upper:]) = INPUT ]; then
  $IPTABLES -N $LOGINPUTCHAIN
  $IPTABLES -A $LOGINPUTCHAIN -p tcp -m limit --limit $LOGLIMIT --limit-burst $LOGLIMITBURST -j LOG --log-prefix 'INPUT TCP: '
  $IPTABLES -A $LOGINPUTCHAIN -p udp -m limit --limit $LOGLIMIT --limit-burst $LOGLIMITBURST -j LOG --log-prefix 'INPUT UDP: '
  $IPTABLES -A $LOGINPUTCHAIN -p icmp -m limit --limit $LOGLIMIT --limit-burst $LOGLIMITBURST -j LOG --log-prefix 'INPUT ICMP: '
fi

# If LOGGING is true or matches 'OUTPUT' - OUTPUT connections are passed through this chain
if [ $LOGGING = true -o $(echo $LOGGING | tr [:lower:] [:upper:]) = OUTPUT ]; then
  $IPTABLES -N $LOGOUTPUTCHAIN
  $IPTABLES -A $LOGOUTPUTCHAIN -p tcp -m limit --limit $LOGLIMIT --limit-burst $LOGLIMITBURST -j LOG --log-prefix 'OUTPUT TCP: '
  $IPTABLES -A $LOGOUTPUTCHAIN -p udp -m limit --limit $LOGLIMIT --limit-burst $LOGLIMITBURST -j LOG --log-prefix 'OUTPUT UDP: '
  $IPTABLES -A $LOGOUTPUTCHAIN -p icmp -m limit --limit $LOGLIMIT --limit-burst $LOGLIMITBURST -j LOG --log-prefix 'OUTPUT ICMP: '
fi

####################### IPTABLES INPUT RULES ###################################

# Accept all incoming connections which is related or already established
$IPTABLES -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

# Accept connections from loopback
$IPTABLES -A INPUT -i lo -j ACCEPT

# Accept all custom TCP-ports defined by $IN_TCP_PORTS
for TCPPORT in ${IN_TCP_PORTS[@]}; do
  $IPTABLES -A INPUT -p tcp --dport $TCPPORT -d $IP -j ACCEPT
done

# Accept all custom UDP-ports defined by $IN_UDP_PORTS
for UDPPORT in ${IN_UDP_PORTS[@]}; do
  $IPTABLES -A INPUT -p udp --dport $UDPPORT -d $IP -j ACCEPT
done

# Accept incoming icmp-requests (ping)
$IPTABLES -A INPUT -p icmp --icmp-type 8 -d $IP -j ACCEPT
# Block incoming brodcast
$IPTABLES -A INPUT -m pkttype --pkt-type broadcast -j DROP

# Decide if logging unmatched INPUT traffic is to be done.
if [ $LOGGING = true -o $(echo $LOGGING | tr [:lower:] [:upper:]) = INPUT ]; then
  $IPTABLES -A INPUT -j $LOGINPUTCHAIN
fi

# Be polite and reject packages instead of dropping them, to a limit.
$IPTABLES -A INPUT -p icmp $LIMIT -d $IP -j REJECT --reject-with icmp-admin-prohibited
$IPTABLES -A INPUT -p udp $LIMIT -d $IP -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A INPUT -p tcp $LIMIT -d $IP -j REJECT --reject-with tcp-reset


####################### IPTABLES OUTPUT RULES ##################################

# Accept all outgoing connections which is established or already established.
$IPTABLES -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

# Accept outgoing connections from lo interface
$IPTABLES -A OUTPUT -o lo -j ACCEPT

# Accept dns lookups (udp and tcp)
$IPTABLES -A OUTPUT -p tcp --dport 53 -s $IP -j ACCEPT
$IPTABLES -A OUTPUT -p udp --dport 53 -s $IP -j ACCEPT

# Accept outgoing SSH, HTTP and FTP connections.
$IPTABLES -A OUTPUT -p tcp --dport 22 -s $IP -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --dport 20:21 -s $IP -j ACCEPT
$IPTABLES -A OUTPUT -p tcp -m multiport --dports 80,443 -s $IP -j ACCEPT

# Accept all custom TCP-ports defined by $OUT_UDP_PORTS
for TCPPORT in ${OUT_TCP_PORTS[@]}; do
  $IPTABLES -A OUTPUT -p tcp --dport $TCPPORT -s $IP -j ACCEPT
done

# Accept all custom UDP-ports defined by $OUT_UDP_PORTS
for UDPPORT in ${OUT_UDP_PORTS[@]}; do
  $IPTABLES -A OUTPUT -p udp --dport $UDPPORT -s $IP -j ACCEPT
done

# Accept outgoing icmp-requests
$IPTABLES -A OUTPUT -p icmp --icmp-type 8 -s $IP -j ACCEPT

# Accept outgoing broadcast messages
$IPTABLES -A OUTPUT -d $BCAST -s $IP -j ACCEPT
$IPTABLES -A OUTPUT -d 255.255.255.255 -s $IP -j ACCEPT

# Decide if logging unmatched OUTPUT traffic is to be done.
if [ $LOGGING = true -o $(echo $LOGGING | tr [:lower:] [:upper:]) = OUTPUT ]; then
  $IPTABLES -A OUTPUT -j $LOGOUTPUTCHAIN
fi

# vim: set expandtab ts=2 sw=2:
