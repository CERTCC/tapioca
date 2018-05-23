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

echo External network: $external_net
echo Internal network: $internal_net

testmode=$1
outputdir="$2"

mkdir -p $outputdir

export LANG=en_US.UTF-8
sudo killall tcpdump
sudo killall mitmproxy
sudo killall mitmweb
killall tail

sudo ifdown $internal_net
sudo ifup $internal_net

if [ "$testmode" == "ssltest" ]; then
    # Test for clients not validating ssl certificate trust
    rm -f logs/ssltest.log
    rm -f logs/flows.log.uris
    sleep 0.2
    xterm -geometry -100-100 -e "tail -F $outputdir/ssltest.log | strings | grep \"5:https,\"" &
    sudo ./iptables_mitmproxy.sh
    mitmproxy --showhost --anticache --ssl-insecure --mode transparent -w $outputdir/ssltest.log
    ./uris.py $outputdir/ssltest.log
elif [ "$testmode" == "full" ]; then
    # Test full HTTPS inspection (certificate installed)
    rm -f logs/flows.log 
    sudo ./iptables_mitmproxy.sh
    mitmproxy --showhost --anticache --ssl-insecure --mode transparent -w $outputdir/flows.log    
elif [ "$testmode" == "tcpdump" ]; then
    # Just capture raw traffic without interfering
    rm -f logs/tcpdump.pcap
    xfce4-terminal --disable-server -T "tcpdump" -e "sudo tcpdump -U -i $internal_net -w $outputdir/tcpdump.pcap -v"
fi

