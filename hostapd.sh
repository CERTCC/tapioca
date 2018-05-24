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

unset_pass=`grep PASSWORD_HERE hostapd.conf`
unset_LAN=`grep LAN_DEVICE tapioca.cfg`
ssid=`grep ssid= hostapd.conf | awk -F= '{print $NF}'`
nmclimajor=`nmcli --version | awk '{print $NF}' | awk -F. '{print $1}'`

ethtool_bin=`which ethtool 2> /dev/null`
if [ -z "$ethtool_bin" ]; then
  # Raspbian minimial install doesn't set up path
  ethtool_bin=/sbin/ethtool
fi

if [ ! -f "$ethtool_bin" ]; then
  # Try other path
  ethtool_bin=/usr/sbin/ethtool
fi

hostapd_bin=`which hostapd 2> /dev/null`
if [ -z "$hostapd_bin" ]; then
  # Raspbian minimial install doesn't set up path
  hostapd_bin=/usr/sbin/hostapd
fi


if [ ! -z "$unset_pass" ]; then
  echo "*** You must set the wireless password in hostapd.conf ***"
  sleep 5
  mousepad hostapd.conf
fi

source ./tapioca.cfg

unset_pass=`grep PASSWORD_HERE hostapd.conf`
unset_LAN=`grep LAN_DEVICE tapioca.cfg`
ssid=`grep ssid= hostapd.conf | awk -F= '{print $NF}'`

if [ ! -z "$unset_pass" ]; then
  echo "*** You must set the wireless password in hostapd.conf ***"
  sleep 5
  exit 1
fi

network_up=`nmcli device status | grep " connected " | head -n1`

if [ -z "$network_up" ]; then
    echo "*** No network connection appears to be up ***"
    echo "Please make sure your upstream network is working"
    echo "before proceeding with a soft AP"
    nmcli dev status
    sleep 10
    nm-connection-editor
    exit 1
fi


eth_count=`nmcli device status | awk '{print $2}' | egrep "ethernet|wifi|wireless" | wc -l`

if [ "$eth_count" -lt 2 ]; then
    nmcli device status
    echo "*** Ethernet devices detected: $eth_count. Cannot proceed. ***"
    sleep 10
    exit 1
fi


free_wifi=`nmcli device status | egrep " wifi | 802-11-wireless " | grep -v " connected " | head -n1`

if [ -z "$free_wifi" ]; then
    nmcli device status
    echo "*** No unconfigured wireless adapter detected ***"
    sleep 10
    exit 1
else
    wifi_adapter=`echo $free_wifi | awk '{print $1}'`
    wifi_state=`echo $free_wifi | awk '{print $3}'`
    
    if [ "$nmclimajor" -gt 0 ]; then
        # Old nmcli doesn't support checking wifi properties it seems
        ap_supported=`nmcli -f WIFI-PROPERTIES dev show $wifi_adapter | grep WIFI-PROPERTIES.AP | awk '{print $NF}'`
        
        if [ "$ap_supported" == "no" ]; then
            echo "*** Wireless device $wifi_adapter is available, but it does not appear to support AP mode. ***"
            sleep 10
            exit 1
        fi 
    fi
    
    if [ "$wifi_state" == "disconnected" ]; then
        echo "Wireless device $wifi_adapter is available, but it is managed by NetworkManager."
        echo "Reconfiguring $wifi_adapter to be unmanaged..."
         
        ap_mac=`$ethtool_bin -P $wifi_adapter | awk '{print $NF}'`
        keyfile_present=`grep '\[keyfile\]' /etc/NetworkManager/NetworkManager.conf`
        if [ -z "$keyfile_present" ]; then      
            sudo sh -c "echo '[keyfile]' >> /etc/NetworkManager/NetworkManager.conf"
        fi
        sudo sh -c "echo unmanaged-devices=mac:$ap_mac >> /etc/NetworkManager/NetworkManager.conf"
        
        sudo systemctl restart NetworkManager.service
        
        sleep 10
        
        free_wifi=`nmcli device status | grep " wifi " | grep -v " connected " | head -n1`
        wifi_state=`echo $free_wifi | awk '{print $3}'`
        
        if [ "$wifi_state" == "disconnected" ]; then
            echo "*** Please reboot to activate network changes. ***"
            sleep 10
            exit 1
        fi
        
    fi
    
fi

echo "Detected internal wireless AP adapter: $wifi_adapter"
sed -i.bak -e "s/internal_net=.*/internal_net=$wifi_adapter/" tapioca.cfg
source ./tapioca.cfg


# Get hostapd adapter IP address via internal_subnet
# e.g. "10.0.0.0/24" -> "10.0.0.1/24"
ip_mask=`echo $internal_subnet | sed "s/0\//1\//"`

# Replace wireless adapter in hostapd.conf file
sed -i.bak -e "s/interface=.*/interface=$internal_net/" hostapd.conf

# Copy customized hostapd.conf to system-wide location
if [ -d /etc/hostapd ]; then
    sudo cp hostapd.conf /etc/hostapd/
else
    sudo cp hostapd.conf /etc/
fi

# Set static IP address and subnet for hostapd adapter
sudo ip a flush dev $internal_net
sudo ip a add $ip_mask dev $internal_net


# Start hostapd
sudo service hostapd restart

if [ $? -ne 0 ]; then
    # Assume that hostapd was started manually.  Kill manually.
    sudo killall $hostapd_bin
fi

sleep 5

# Some OS versions like Raspbian will kill off the internal_net adapter
# Check if hostapd is really running
hostapd_running=`ps aux | grep $hostapd_bin | grep -v grep`
if [ -z "$hostapd_running" ]; then
    echo Restarting hostapd...
    sudo service hostapd restart
fi

# Maybe hostapd service runner isn't working (Ubuntu 17.10)
hostapd_running=`ps aux | grep $hostapd_bin | grep -v grep`
if [ -z "$hostapd_running" ]; then
    echo Starting hostapd manually...
    sudo $hostapd_bin -B -P /run/hostapd.pid /etc/hostapd/hostapd.conf
fi

sleep 5

# Start dhcpd
sudo service dhcpd restart
sudo service isc-dhcp-server restart

sudo service dnsmasq restart

sudo ./iptables_noproxy.sh

if [ $? -eq 0 ]; then
    echo "*** WiFi SSID $ssid should now be available! ***"
fi
sleep 8

