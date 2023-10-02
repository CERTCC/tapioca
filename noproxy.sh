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

# Get window ID for mitmproxy
mitmwin=`xdotool search --onlyvisible --name "mitmproxy" | head -n1 2>/dev/null`

if [ -n "$mitmwin" ]; then
    # Cleanly exit mitmproxy to flush buffers
    echo "*** Sending quit keys to window $mitmwin ***"
    xdotool search --onlyvisible --name "mitmproxy" windowactivate; xdotool key q; xdotool key q; xdotool key y
fi

# Give time to clean up
sleep 1

# Kill any existing processes
sudo killall -HUP mitmproxy
sudo killall -HUP tcpdump
sudo killall -HUP tail

# Reset iptables to perform just NAT
sudo ./iptables_noproxy.sh

# Save iptables to pass-through by default
sudo service iptables save

# Notify user
echo Intercepting proxy disabled
sleep 1
