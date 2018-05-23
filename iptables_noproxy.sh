#!/bin/bash
# BEGIN LICENSE #
#
# CERT Tapioca
#
# Copyright 2018 Carnegie Mellon University. All Rights Reserved.
#
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE
# ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS.
# CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER
# EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED
# TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY,
# OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON
# UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO
# FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
#
# Released under a BSD (SEI)-style license, please see license.txt or
# contact permission@sei.cmu.edu for full terms.
#
# [DISTRIBUTION STATEMENT A] This material has been approved for
# public release and unlimited distribution.  Please see Copyright
# notice for non-US Government use and distribution.
# CERT(R) is registered in the U.S. Patent and Trademark Office by
# Carnegie Mellon University.
#
# DM18-0637
#
# END LICENSE #

source ./tapioca.cfg

internal=`echo $internal_subnet | awk -F/ '{print $1}'`

if [ "$internal_net" ==	"LAN_DEVICE" ];	then
  nmcli dev status
  echo "Please edit tapioca.cfg	to specify your	LAN device"
  sleep	10
  exit 1
fi

if [ "$external_net" ==	"WAN_DEVICE" ];	then
  nmcli dev status
  echo "Did you run ./install_tapioca.sh first?"
  sleep	10
  exit 1
fi

detected_external=`netstat -rn | egrep "^0.0.0.0" | awk '{print $NF}' | head -n1`
detected_external_ip=`netstat -rn | egrep "^0.0.0.0" | awk '{print $2}' | head -n1`
detected_external_subnet=`echo $detected_external_ip | awk -F. '{print $1 "." $2}'`
detected_internal=`netstat -rn | egrep "^$internal" | awk '{print $NF}' | head -n1`


echo "detected external network adapter: $detected_external"
echo "configured external network adapter: $external_net"
echo "detected internal network adapter: $detected_internal"
echo "configured internal network adapter: $internal_net"

if [[ $internal_subnet = $detected_external_subnet* ]]; then
  # The external IP address is in internal subnet. This won't work
  echo "*** External IP address $detected_external_ip$ is in the internal subnet ***"
  echo "*** External connection $detected_external is using the same internal subnet specified in tapioca.cfg ***"
  echo "*** If you have no control of your external subnet, you must edit both tapioca.cfg and /etc/dhcp/dhcpd.conf ***"
  sleep 10
  exit 1
fi

if [ "$detected_external" = "$detected_internal" ]; then
    echo "Your upstream internet is using the same subnet as the default LAN side (10.0.0.0/24)"
    echo "This will require some manual configuration to avoid conflicts."
    sleep 10
fi

if [ "$detected_external" != "$external_net" ]; then
  nmcli device status
  echo ""
  echo "*** tapioca.cfg doesn't seem to be configured properly! ***"
  echo "*** $detected_external is detected as external, but $external_net is configured in tapioca.cfg ***"
  sleep 10
  exit 1
fi

if [ "$detected_internal" != "$internal_net" ]; then
  nmcli device status
  echo ""
  echo "*** tapioca.cfg doesn't seem to be configured properly! ***"
  echo "*** $detected_internal is detected as internal, but $internal_net is configured in tapioca.cfg ***"
  sleep 10
  exit 1
fi

if [ -z "$external_net" ]; then
  Defaulting external interface to eth0
  external_net=eth0
fi

if [ -z "$internal_net" ]; then
  Defaulting internal interface to eth1
  internal_net=eth1
fi

if [ -z "$internal_subnet" ]; then
  Defaulting internal subnet to 10.0.0.0/24
  internal_subnet=10.0.0.0/24
fi

# Flush established connections
conntrack -F

# Flush rules
iptables -P INPUT ACCEPT
iptables -F

# Default block incoming traffic
iptables -P INPUT DROP

# Accept on internal network
iptables -A INPUT -i $internal_net -j ACCEPT
iptables -A OUTPUT -o $internal_net -j ACCEPT
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Accept on loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# NAT magic
iptables -t nat -F PREROUTING
iptables -t nat -A POSTROUTING -o $external_net -s $internal_subnet -j MASQUERADE
iptables -A FORWARD -o $external_net -i $internal_net -s $internal_subnet -m conntrack --ctstate NEW -j ACCEPT
iptables -A FORWARD -i $external_net -o $internal_net -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i $internal_net -o $external_net -j ACCEPT
iptables -t nat -F POSTROUTING
iptables -t nat -A POSTROUTING -o $external_net -j MASQUERADE