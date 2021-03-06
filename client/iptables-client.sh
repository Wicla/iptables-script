#!/bin/bash
####################### READ THIS INTRODUCTION #################################
# This script allows some generic input and output traffic (see list below, please keep it updated if file is edited).
# There're also arrays which can be filled with ports which is wanted to be allowed (in all directions and protocol).
# Default policy is set to DROP all unmatched traffic in both directions.
#
# This script supports to be used as a script to wicd (network manager). To use this feature changed USEWICD to true.
# It accepts either wired or wireless as argument Argument decides which interface the rules are to based upon.
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

# Test if user has super privileges
if [ $(id -u) -ne 0 ]; then
  echo 'This script requires to be run as root.'
  exit 1
fi

####################### CONFIGURATION BEGINS HERE ##############################

# Set USEWICD to true be able to use this script as a wicd script.
USEWICD=false

# NICs. Only LANIF is needed to be configured if WLAN isn't used.
# Configure interfaces correctly. It's from this value it gets the source/destination IP- and broadcast-address to allow.
HOST_LANIF=eth0
HOST_WLANIF=wlan0

# Dynamically opened ports. Whitespace separates each value. Both port number and service name allowed (see /etc/services)
# PORTS_TCPIN, PORTS_UDPIN, PORTS_TCPOUT and PORTS_UDPOUT are arrays. Please enter each port number (or service name) seperated by space.
PORTS_TCPIN=( )
PORTS_UDPIN=( )
PORTS_TCPOUT=( )
PORTS_UDPOUT=( )

# Used for reject (if no INPUT connection is matched). Reject first 10 packets each 10 minute, then just drop them. 
LIMIT="-m hashlimit --hashlimit 10/minute --hashlimit-burst 10 --hashlimit-mode srcip --hashlimit-name limreject"

# This section is used by wicd (called as a script on connect).
# Variable $IF contains your NIC. Please make sure this value is correct. 
if [ $USEWICD == true ]; then
  if [ "$1" == 'wireless' ]; then
    HOST_IF=$HOST_WLANIF
  elif [ "$1" == 'wired' ]; then
    HOST_IF=$HOST_LANIF
  else
    echo 'Something is wrong.'
    echo 'Missing argument (which should be wireless or wired)'
    echo 'Exiting.'
    exit 1
  fi
else
  HOST_IF=$HOST_LANIF
fi

# IP contains the IP-address of interface $IF
# BCAST contains the broadcast address of interface $IF
HOST_IP=($(ifconfig $HOST_IF)); HOST_IP=$(echo ${HOST_IP[6]#*:})
HOST_BCAST=($(ifconfig $HOST_IF)); HOST_BCAST=$(echo ${HOST_BCAST[7]#*:})

# LOGGING defines if unmatched connections should be logged.
# Possibles values are following:
# * false   -- Nothing is logged (defaults to false)
# * true    -- Logs both INPUT and OUTPUT
# * input   -- Logs INPUT
# * output  -- Logs OUTPUT
LOGGING=false
if [ $LOGGING = true \
  -o $(echo $LOGGING | tr [:lower:] [:upper:]) = INPUT \
  -o $(echo $LOGGING | tr [:lower:] [:upper:]) = OUTPUT ]; then
# Chain for INPUT and OUTPUT for LOGGING
  CHAIN_LOGINPUT=LOGINPUT
  CHAIN_LOGOUTPUT=LOGOUTPUT
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
  $IPTABLES -N $CHAIN_LOGINPUT
  $IPTABLES -A $CHAIN_LOGINPUT -p tcp -m limit --limit $LOGLIMIT --limit-burst $LOGLIMITBURST -j LOG --log-prefix 'INPUT TCP: '
  $IPTABLES -A $CHAIN_LOGINPUT -p udp -m limit --limit $LOGLIMIT --limit-burst $LOGLIMITBURST -j LOG --log-prefix 'INPUT UDP: '
  $IPTABLES -A $CHAIN_LOGINPUT -p icmp -m limit --limit $LOGLIMIT --limit-burst $LOGLIMITBURST -j LOG --log-prefix 'INPUT ICMP: '
fi

# If LOGGING is true or matches 'OUTPUT' - OUTPUT connections are passed through this chain
if [ $LOGGING = true -o $(echo $LOGGING | tr [:lower:] [:upper:]) = OUTPUT ]; then
  $IPTABLES -N $CHAIN_LOGOUTPUT
  $IPTABLES -A $CHAIN_LOGOUTPUT -p tcp -m limit --limit $LOGLIMIT --limit-burst $LOGLIMITBURST -j LOG --log-prefix 'OUTPUT TCP: '
  $IPTABLES -A $CHAIN_LOGOUTPUT -p udp -m limit --limit $LOGLIMIT --limit-burst $LOGLIMITBURST -j LOG --log-prefix 'OUTPUT UDP: '
  $IPTABLES -A $CHAIN_LOGOUTPUT -p icmp -m limit --limit $LOGLIMIT --limit-burst $LOGLIMITBURST -j LOG --log-prefix 'OUTPUT ICMP: '
fi

####################### IPTABLES INPUT RULES ###################################

# Accept all incoming connections which is related or already established
$IPTABLES -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

# Accept connections from loopback
$IPTABLES -A INPUT -i lo -j ACCEPT

# Accept all custom TCP-ports defined by $PORTS_TCPIN
for TCPPORT in ${PORTS_TCPIN[@]}; do
  $IPTABLES -A INPUT -p tcp --dport $TCPPORT -d $HOST_IP -j ACCEPT
done

# Accept all custom UDP-ports defined by $PORTS_UDPIN
for UDPPORT in ${PORTS_UDPIN[@]}; do
  $IPTABLES -A INPUT -p udp --dport $UDPPORT -d $HOST_IP -j ACCEPT
done

# Accept incoming icmp-requests (ping)
$IPTABLES -A INPUT -p icmp --icmp-type 8 -d $HOST_IP -j ACCEPT
# Block incoming brodcast
$IPTABLES -A INPUT -m pkttype --pkt-type broadcast -j DROP

# Decide if logging unmatched INPUT traffic is to be done.
if [ $LOGGING = true -o $(echo $LOGGING | tr [:lower:] [:upper:]) = INPUT ]; then
  $IPTABLES -A INPUT -j $CHAIN_LOGINPUT
fi

# Be polite and reject packages instead of dropping them, to a limit.
$IPTABLES -A INPUT -p icmp $LIMIT -d $HOST_IP -j REJECT --reject-with icmp-admin-prohibited
$IPTABLES -A INPUT -p udp $LIMIT -d $HOST_IP -j REJECT --reject-with icmp-port-unreachable
$IPTABLES -A INPUT -p tcp $LIMIT -d $HOST_IP -j REJECT --reject-with tcp-reset


####################### IPTABLES OUTPUT RULES ##################################

# Accept all outgoing connections which is established or already established.
$IPTABLES -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

# Accept outgoing connections from lo interface
$IPTABLES -A OUTPUT -o lo -j ACCEPT

# Accept dns lookups (udp and tcp)
$IPTABLES -A OUTPUT -p tcp --dport 53 -s $HOST_IP -j ACCEPT
$IPTABLES -A OUTPUT -p udp --dport 53 -s $HOST_IP -j ACCEPT

# Accept outgoing SSH, HTTP and FTP connections.
$IPTABLES -A OUTPUT -p tcp --dport 22 -s $HOST_IP -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --dport 20:21 -s $HOST_IP -j ACCEPT
$IPTABLES -A OUTPUT -p tcp -m multiport --dports 80,443 -s $HOST_IP -j ACCEPT

# Accept all custom TCP-ports defined by $PORTS_UDPOUT
for TCPPORT in ${PORTS_TCPOUT[@]}; do
  $IPTABLES -A OUTPUT -p tcp --dport $TCPPORT -s $HOST_IP -j ACCEPT
done

# Accept all custom UDP-ports defined by $PORTS_UDPOUT
for UDPPORT in ${PORTS_UDPOUT[@]}; do
  $IPTABLES -A OUTPUT -p udp --dport $UDPPORT -s $HOST_IP -j ACCEPT
done

# Accept outgoing icmp-requests
$IPTABLES -A OUTPUT -p icmp --icmp-type 8 -s $HOST_IP -j ACCEPT

# Accept outgoing broadcast messages
$IPTABLES -A OUTPUT -d $HOST_BCAST -s $HOST_IP -j ACCEPT
$IPTABLES -A OUTPUT -d 255.255.255.255 -s $HOST_IP -j ACCEPT

# Decide if logging unmatched OUTPUT traffic is to be done.
if [ $LOGGING = true -o $(echo $LOGGING | tr [:lower:] [:upper:]) = OUTPUT ]; then
  $IPTABLES -A OUTPUT -j $CHAIN_LOGOUTPUT
fi

# vim: set expandtab ts=2 sw=2:
