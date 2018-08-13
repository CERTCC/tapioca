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

user_id=`whoami`
yum=`which yum 2>/dev/null`
dnf=`which dnf 2>/dev/null`
apt=`which apt-get 2>/dev/null`
zypper=`which zypper 2>/dev/null`
sudogroup=`egrep "^wheel:|^sudo:" /etc/group | awk -F: '{print $1}'`
tapiocasudo=`egrep "^$sudogroup" /etc/group | grep tapioca`
arch=`uname -m`

if [ -f /etc/os-release ]; then
    source /etc/os-release
fi

if [ -z $(which sudo) ]; then
    echo "sudo command not found"
    echo "Please ensure that sudo is installed before running this installer."
    exit 1
fi

if [ "$user_id" != "tapioca" ] && [ "$user_id" != "root" ]; then
    if [ -z "$apt" ]; then
        # Redhat adduser doesn't prompt to set password
        cat << EOF
Please run this installer as user "tapioca", not $user_id.
For example:
# adduser tapioca
# passwd tapioca
# usermod -aG $sudogroup tapioca
EOF
    else
        # No need to set passwd on Ubuntu-like
        cat << EOF
Please run this installer as user "tapioca", not $user_id.
For example:
# adduser tapioca
# usermod -aG $sudogroup tapioca
EOF
    fi
    exit 1
fi

if [ "$PWD" != "/home/tapioca/tapioca" ]; then
    echo This installer must be run from the /home/tapioca/tapioca directory.
    exit 1
fi

root_privs=`grep tapioca /etc/sudoers 2>/dev/null`

if [ ! -z "$root_privs" ] || [ "$user_id" == "root" ]; then
    echo "Please do not run this script with root privileges"
    exit 1
fi

# Redirect stdout ( > ) into a named pipe ( >() ) running "tee"
exec > >(tee -i install.log)

# Without this, only stdout would be captured - i.e. your
# log file would not contain any error messages.
# SEE (and upvote) the answer by Adam Spiers, which keeps STDERR
# as a separate stream - I did not want to steal from him by simply
# adding his answer to mine.
exec 2>&1

if [ -z "$tapiocasudo" ]; then
    echo "$user_id isn't part of the \"$sudogroup\" group."
    echo "please run the following command as root and re-run $0:"
    echo "usermod -aG $sudogroup tapioca"
    exit 1
fi

sudo_configured=`sudo grep "tapioca ALL=NOPASSWD: ALL" /etc/sudoers`

if [ -z "$sudo_configured" ]; then
    # Don't require password for tapioca sudo
    echo "$user_id isn't properly configured in /etc/sudoers.  Correcting."
    echo ""
    sudo sh -c "echo 'tapioca ALL=NOPASSWD: ALL' >> /etc/sudoers"
fi

netstat=`which netstat 2>/dev/null`

# Detect internal and external network adapters
if [ -z "$netstat" ]; then
    detected_external=`ip route show | egrep "^default " | awk -F' dev ' '{print $2}' | awk '{print $1}' | head -n1`
    detected_internal=`ip route show | egrep "^10.0.0.0/24 " | awk -F' dev ' '{print $2}' | awk '{print $1}' | head -n1`
else
    detected_external=`netstat -rn | egrep "^0.0.0.0" | awk '{print $NF}' | head -n1`
    detected_internal=`netstat -rn | egrep "^10.0.0.0" | awk '{print $NF}' | head -n1`
fi


if [ ! -z "$detected_external" ]; then
    echo "detected external network adapter: $detected_external"
    # Replace WAN adapter in tapioca.cfg file
    sed -i.bak -e "s/external_net=.*/external_net=$detected_external/" tapioca.cfg
else
    echo "Cannot detect WAN adapter. Be sure to edit tapioca.cfg to specify your device!"
    sleep 10
fi

if [ ! -z "$detected_internal" ]; then
    echo "detected internal network adapter: $detected_internal"
    # Replace LAN adapter in tapioca.cfg file
    sed -i.bak -e "s/internal_net=.*/internal_net=$detected_internal/" tapioca.cfg
else
    echo "Cannot detect LAN adapter. Be sure to edit tapioca.cfg to specify your device!"
    echo "Recommended configuration is a WiFi adapter that supports HOSTAP or a wired LAN adapter at IP 10.0.0.1/24"
    sleep 10
fi

if [ "$detected_external" = "$detected_internal" ]; then
    echo "Your upstream internet is using the same subnet as the default LAN side (10.0.0.0/24)"
    echo "This will require some manual configuration to avoid conflicts."
    sleep 10
fi

source ./tapioca.cfg

# At some point, I've seen ~/.cache created as root.  That'd be bad.
mkdir -p ~/.cache

if [ ! -f ~/.bash_profile ]; then
    echo "PATH=$PATH" > ~/.bash_profile
fi
path_set=`egrep "^PATH=" ~/.bash_profile`

if [ -z "$path_set" ]; then
    # there is a ~/.bash_profile file, but no PATH is set
    # so we'll prepend our own
    echo 'PATH=$PATH' > .bash_profile.tmp
    cat ~/.bash_profile >> .bash_profile.tmp
    cp .bash_profile.tmp ~/.bash_profile
fi

if [ ! -z "$dnf" ]; then
    # dnf is present. So probably Fedora
    sudo dnf -y group install "Fedora Workstation"
    sudo dnf -y group install xfce "Development tools" "Development Libraries"
    sudo dnf -y install perl-Pod-Html gcc-c++ redhat-rpm-config python3-devel
fi

if [ ! -z "$yum" ] && [ -z "$dnf" ]; then
    #EL7 and not Fedora
    sudo yum makecache fast
    sudo yum -y install epel-release
    sudo yum -y groupinstall "Development tools" "Server with GUI" xfce "Development Libraries"
fi

if [ ! -z "$zypper" ] && [ ! -z "$apt" ]; then
    # zypper and apt-get are present.  So probably OpenSUSE Tumbleweed
    # zypper is present.  So probably OpenSUSE Tumbleweed
    sudo zypper -n install patterns-devel-base-devel_basis patterns-xfce-xfce_basis \
     man libxml2-devel libxml2 libxslt libxslt-devel python3-devel libopenssl-devel dnsmasq tcpdump \
    dhcp bind-utils nano wget net-tools telnet xdotool nmap xterm \
    tmux iw hostapd python-wxWidgets-3_0 mousepad tk-devel \
    glib2-devel libqt4-devel libgnutls-devel c-ares-devel libsmi-devel libcap-devel \
    libGeoIP-devel libnl3-devel libpcap-devel python2-qt4 python2-colorama gnome-icon-theme \
    conntrack-tools libqt5-qtbase-devel libqt5-linguist snappy-devel \
    libnghttp2-devel libcap-progs NetworkManager-applet lightdm dhcp-server \
    net-tools-deprecated
elif [ ! -z "$zypper" ]; then
    # zypper is present.  So probably OpenSUSE
    sudo zypper -n install patterns-openSUSE-devel_basis patterns-openSUSE-xfce_basis \
     man libxml2-devel libxml2 libxslt libxslt-devel python3-devel openssl-devel dnsmasq tcpdump \
    dhcp bind-utils nano wget net-tools telnet xdotool nmap xterm \
    tmux iw hostapd wxPython mousepad tk-devel \
    glib2-devel qt-devel gnutls-devel libcares-devel libsmi-devel libcap-devel \
    libGeoIP-devel libnl3-devel libpcap-devel python-qt4 python-colorama gnome-icon-theme \
    conntrack-tools libqt5-qtbase-devel libqt5-linguist snappy-devel\
    libnghttp2-devel libcap-progs NetworkManager-gnome lightdm dhcp-server
elif [ ! -z "$yum" ]; then
    # yum is present. EL7 and Fedora.
    sudo yum -y install gcc libxml2 libxml2-devel libxslt libxslt-devel \
    python-devel openssl-devel dnsmasq tcpdump \
    dhcp bind-utils nano chromium wget net-tools telnet xdotool nmap xterm \
    tmux iptables-services iw hostapd wxPython mousepad tk-devel \
    glib2-devel qt-devel gnutls-devel c-ares-devel libsmi-devel libcap-devel \
    GeoIP-devel libnl3-devel libpcap-devel PyQt4 python-colorama gnome-icon-theme.noarch \
    conntrack-tools qt5-qtbase-devel qt5-linguist snappy-devel libnghttp2-devel \
    libgcrypt-devel
elif [ ! -z "$apt" ]; then
    #apt-get is present.  So probably Ubuntu
    sudo apt-get -y update
    DEBIAN_FRONTEND=noninteractive sudo -E apt-get -y install xfce4 xfce4-goodies build-essential libxml2-dev \
    libxslt1-dev python-dev libssl-dev dnsmasq tcpdump isc-dhcp-server \
    chromium-browser telnet nano xdotool tmux iptables iw nmap xterm \
    libglib2.0-dev libqt4-dev libc-ares-dev libsmi2-dev \
    libcap-dev libgeoip-dev libnl-3-dev libpcap-dev python-qt4 \
    python3-pyqt4 python-colorama python3-colorama python3-pip \
    network-manager ethtool hostapd gnome-icon-theme \
    libwiretap-dev zlib1g-dev libcurl4-gnutls-dev curl conntrack iptables-persistent\
    libsnappy-dev libgcrypt-dev ifupdown
fi

if [ $? -ne 0 ]; then
  echo "Error installing dependency packages. Please check errors and try again."
  exit 1
fi

if [ ! -z "$zypper" ]; then
    sudo zypper install chromium
fi

python=`which python  2> /dev/null`

# Tapioca scripts that use the GUI will use system-wide python
if [ ! -f /usr/bin/python ]; then
    ln -s $python /usr/bin/python
fi

if [ ! -z "$yum" ]; then
    # If already installed, these packages can interfere with our Wireshark
    sudo yum remove -y pyOpenSSL wireshark 2> /dev/null
fi

if [ ! -z "$apt" ]; then
    # set the default terminal emulator
    sudo update-alternatives --set x-terminal-emulator /usr/bin/xfce4-terminal.wrapper

    # Newer ubuntu versions have different package names between releases.
    # Don't error out on these if they're not present
    sudo apt-get -y install gnome-icon-theme-full
    sudo apt-get -y install libgnutls-dev
    sudo apt-get -y install libgnutls28-dev
    sudo apt-get -y install python-wxgtk2.8
    sudo apt-get -y install python-wxgtk3.0
    sudo apt-get -y install libffi-dev
    sudo apt-get -y install network-manager-gnome
    sudo apt-get -y install net-tools
    sudo apt-get -y install qttools5-dev-tools
    sudo apt-get -y install qttools5-dev
    sudo apt-get -y install libnghttp2-dev
fi

if [ -f /etc/sysconfig/dhcpd ]; then
    sudo sed -i.bak -e 's/^DHCPD_INTERFACE=""/DHCPD_INTERFACE="ANY"/' /etc/sysconfig/dhcpd
fi

# Make xfce the default for tapioca user
if [ -f /var/lib/AccountsService/users/tapioca ]; then
    # There may be a default session
    grep XSession /var/lib/AccountsService/users/tapioca > /dev/null
    if [ $? -eq 0 ]; then
        # Match found.  Replace existing XSession line
        sudo sed -i.bak -e 's/XSession=.*/XSession=xfce/' /var/lib/AccountsService/users/tapioca
    else
        # Append a new XSession line
        sudo bash -c "echo XSession=xfce >> /var/lib/AccountsService/users/tapioca"
    fi
else
    # Set x-session-manager alternative (Raspberry Pi)
    sudo update-alternatives --set x-session-manager /usr/bin/xfce4-session
fi

if [ "$ID" = "raspbian" ]; then
    # Switch to using NetworkManager (Raspberry Pi)
    sudo apt-get -y install network-manager-gnome
    sudo apt-get -y purge openresolv dhcpcd5
    sudo ln -sf /lib/systemd/resolv.conf /etc/resolv.conf
fi

# Automatically log in as tapioca user with gdm3 (e.g. Ubuntu)
if [ -f /etc/gdm3/custom.conf ]; then
    # Match found.  Replace existing AutomaticLogin line
    sudo sed -i.bak -e 's/AutomaticLogin=.*/AutomaticLogin=tapioca/' /etc/gdm3/custom.conf
fi

# Automatically log in as tapioca user with lightdm
if [ -f /etc/lightdm/lightdm.conf ]; then
    # Match found.  Replace existing autologin-user line
    sudo sed -i.bak -e 's/autologin-user=.*/autologin-user=tapioca/' /etc/lightdm/lightdm.conf
fi


# Check if the miniconda python3.6 binary exists
if [ ! -f ~/miniconda/bin/python3.6 ]; then
    # install miniconda
    if [ "$arch" == "x86_64" ]; then
        echo "Installing x86_64 miniconda..."
        curl https://repo.continuum.io/miniconda/Miniconda3-latest-Linux-x86_64.sh -o miniconda.sh
        bash ./miniconda.sh -f -b -p $HOME/miniconda
        miniconda_python=1
    elif [ "$arch" == "x86" ]; then
        echo "Installing x86 miniconda..."
        curl https://repo.continuum.io/miniconda/Miniconda3-latest-Linux-x86.sh -o miniconda.sh
        bash ./miniconda.sh -f -b -p $HOME/miniconda
        miniconda_python=1
    fi
else
    # Miniconda already installed
    miniconda_python=1
fi

if [ -z "$miniconda_python" ]; then
    # No miniconda (e.g. Raspberry Pi), so standard Python install
    python36=`which python3.6 2> /dev/null`

    if [ -z "$python36" ]; then
        mkdir -p ~/in
        pushd ~/in
        rm -f Python-3.6.1.tgz
        rm -rf Python-3.6.1
        wget https://www.python.org/ftp/python/3.6.1/Python-3.6.1.tgz
        tar xavf Python-3.6.1.tgz
        pushd Python-3.6.1/
        ./configure --prefix=/usr/local && sudo make altinstall
        if [ $? -ne 0 ]; then
          echo "Error building python 3.6. Please check errors and try again."
          exit 1
        fi
        popd; popd
    fi

else
    # miniconda python install
    # Check if the PATH var is already set in .bash_profile
    touch ~/.bash_profile
    path_set=`egrep "^PATH=" ~/.bash_profile | grep $HOME/miniconda/bin`


    if [ -z "$path_set" ]; then
        # Put miniconda path at beginning
        sed -i.bak -e "s@^PATH=@PATH=$HOME/miniconda/bin/:@" ~/.bash_profile
    fi

    sbin_path_set=`grep PATH= ~/.bash_profile | grep /sbin`

    if [ -z "$sbin_path_set" ]; then
        # Put the sbin paths into the PATH env variable.
        sed -i.bak -e "s@^PATH=@PATH=/sbin:/usr/sbin:@" ~/.bash_profile
    fi


    # Check if the PATH var is already set in .profile
    profile_exists=`grep PATH= ~/.profile`

    if [ ! -z "$profile_exists" ]; then
        path_set=`grep PATH=$HOME/miniconda/bin ~/.profile`
        if [ -z "$path_set" ]; then
            cat ~/.profile > ~/.profile.orig
            echo "PATH=$HOME/miniconda/bin:$PATH" > ~/.profile
            cat ~/.profile.orig >> ~/.profile
        fi
    fi

    export PATH="$HOME/miniconda/bin:$PATH"

    python36=`which python3.6 2> /dev/null`

    if [ -z "$python36" ]; then
        # Python 3.6 binary is there, but not in path
        export PATH="$HOME/miniconda/bin:$PATH"
        python36=`which python3.6 2> /dev/null`
    fi


    if [ -z "$python36" ]; then
        echo "python 3.6 not found in path. Please check miniconda installation."
        exit 1
    fi

fi


# Ubuntu with qt5 installed (e.g. UbuFuzz)
qt5=`dpkg -l qt5-qmake 2>/dev/null`
if [ ! -z "$qt5" ] && [ ! -z "$apt" ]; then
    # We need qttools5-dev-tools to compile wireshark
    sudo apt-get -y install qttools5-dev-tools
fi

# Build Wireshark if /usr/local/bin/tshark isn't there
if [ ! -f /usr/local/bin/tshark ]; then
    mkdir -p ~/in
    pushd ~/in
    rm -f wireshark-2.6.2.tar.xz
    rm -rf wireshark-2.6.2
    wget https://www.wireshark.org/download/src/all-versions/wireshark-2.6.2.tar.xz
    tar xavf wireshark-2.6.2.tar.xz
    pushd wireshark-2.6.2/
    ./configure && make && sudo make install
    if [ $? -ne 0 ]; then
        echo "Error building Wireshark. Please check errors and try again."
        exit 1
    fi
    if [ "$ID" = "raspbian" ]; then
        # Wireshark install on raspbian doesn't colorize by default.
        # Why?  Nobody knows.
        mkdir -p ~/.config/wireshark
        cp colorfilters ~/.config/wireshark
    fi
    sudo ldconfig
    popd; popd
fi

# Set capture permissions
sudo setcap cap_net_raw,cap_net_admin+ep `which dumpcap 2> /dev/null`


# Confirm pip is there
if [ -z "$miniconda_python" ]; then
    # No miniconda (e.g. Raspberry Pi), so standard Python install
    mypip=`which pip3.6 2> /dev/null`
    echo "Using systemwide pip: $mypip"
else
    # miniconda python
    mypip=`which pip 2> /dev/null`
    echo "Using miniconda pip: $mypip"
fi

if [ -z "$mypip" ]; then
    "python 3.6 not found in path. Please check miniconda installation."
    exit 1
fi

# Install mitmproxy pyshark and deps into miniconda installation
if [ ! -z "$miniconda_python" ]; then
    # We have miniconda, so leverage that for what we can
    conda install -y sortedcontainers passlib certifi pyparsing click ruamel_yaml colorama pyopenssl
    $mypip install mitmproxy pyshark GitPython
else
    # system-wide installed python
    sudo $mypip install colorama mitmproxy pyshark GitPython
fi

# Enable services on boot
if [ ! -z "$zypper" ]; then
    sudo systemctl set-default graphical.target
    sudo chkconfig NetworkManager on
    sudo systemctl enable dnsmasq
    sudo systemctl enable dhcpd
elif [ ! -z "$yum" ]; then
    sudo systemctl disable libvirtd
    sudo chkconfig dnsmasq on
    sudo chkconfig dhcpd on
    sudo chkconfig firewalld off
    sudo chkconfig iptables on
elif [ ! -z "$apt" ]; then
    sudo update-rc.d dnsmasq enable
    sudo update-rc.d isc-dhcp-server enable
fi

# Save default iptables rule if both network devices detected
if [ "$internal_net" != "LAN_DEVICE" ] && [ "$external_net" !=  "WAN_DEVICE" ] ; then
    # LAN and WAN devices are already configured.  Load passthrough iptables rule
    sudo ./iptables_noproxy.sh
    # Save iptables rule as default
    sudo service iptables save
    sudo iptables-save
else
    # Set up basic iptables default deny for incoming traffic

    # Flush existing rules
    sudo iptables -F

    # Set default chain policies
    sudo iptables -P INPUT DROP
    sudo iptables -P FORWARD DROP
    sudo iptables -P OUTPUT ACCEPT

    # Accept on localhost
    sudo iptables -A INPUT -i lo -j ACCEPT
    sudo iptables -A OUTPUT -o lo -j ACCEPT

    # Allow established sessions to receive traffic
    sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    sudo iptables-save
    sudo service iptables save
fi

# Copy over preconfigured xfce
if [ -d ~/.config ]; then
    if [ -d ~/.config/xfce4 ]; then
        mv ~/.config/xfce4 ~/.config/xfce4.orig
    fi
else
    mkdir -p ~/.config
fi
cp -r config/xfce4 ~/.config/
cp config/mimeapps.list ~/.config/

if [ -d ~/.local ]; then
    if [ -d ~/.local/share ]; then
        mv ~/.local/share ~/.local/share.orig
    fi
else
    mkdir -p ~/.local
fi

cp -r local/share ~/.local/
pushd ~/.local/share/mime
update-mime-database $PWD
popd

mkdir -p ~/tapioca/results

mkdir -p ~/.config/Mousepad
touch ~/.config/Mousepad/mousepadrc
mousepad_wordwrap=`grep "ViewWordWrap=true" ~/.config/Mousepad/mousepadrc`
if [ -z "$mousepad_wordwrap" ]; then
    # Wrap mousepad long lines by default
    echo ViewWordWrap=true >> ~/.config/Mousepad/mousepadrc
fi
gsettings set org.xfce.mousepad.preferences.view word-wrap true

sudo cp mitmweb.sh /usr/local/bin/

# Start x / xfce on login
if [ -f ~/.xinitrc ]; then
    cp ~/.xinitrc ~/.xinitrc.orig
fi
echo "sudo service dnsmasq restart" > ~/.xinitrc
echo "exec /usr/bin/xfce4-session" >> ~/.xinitrc

startx=`grep startx ~/.bash_profile`
if [ -z "$startx" ]; then
    echo startx >> ~/.bash_profile
fi


if [ ! -z "$apt" ]; then
    # Ubuntu systems need to have network-manager for Tapioca
    sudo mv /etc/network/interfaces /etc/network/interfaces.orig
    sudo cp etc/network/interfaces /etc/network/interfaces
    sudo sed -i.bak -e 's@#DAEMON_CONF=""@DAEMON_CONF="/etc/hostapd/hostapd.conf"@' /etc/default/hostapd
    sudo mv /etc/dnsmasq.d/network-manager /etc/dnsmasq.d/network-manager.orig 2>/dev/null

    if [ -e "/etc/netplan/01-netcfg.yaml" ]; then
        # Ubuntu 17.10 uses networkd instead of NetworkManager.  We need the latter.
        sudo mv /etc/netplan/01-netcfg.yaml /etc/netplan/01-network-manager-all.yaml
        sudo sed -i.bak -e "s/  renderer: networkd/  renderer: NetworkManager/" /etc/netplan/01-network-manager-all.yaml
        sudo netplan apply
        sudo service network-manager restart
    fi

    if [ -e "/etc/netplan/50-cloud-init.yaml" ]; then
        # Ubuntu 18.04 uses networkd instead of NetworkManager.  We need the latter.
        sudo mv /etc/netplan/50-cloud-init.yaml /etc/netplan/01-network-manager-all.yaml
        networkmanager=`grep "renderer: NetworkManager" /etc/netplan/01-network-manager-all.yaml`
        if [ -z "$networkmanager" ]; then
            sudo bash -c "echo '    renderer: NetworkManager' >> /etc/netplan/01-network-manager-all.yaml"
        fi
        sudo netplan apply
        sudo service network-manager restart
    fi

    if [ -e "/etc/systemd/resolved.conf" ]; then
        # Ubuntu 18.04 uses systemd-resolve instead of dnsmasq.
        # We need to enable udp-listening resolver.
        udplistener=`egrep "^DNSStubListener=udp" /etc/systemd/resolved.conf`
        if [ -z "$udplistener" ]; then
            sudo bash -c "echo 'DNSStubListener=udp' >> /etc/systemd/resolved.conf"
        fi
    fi

fi

if [ ! -z "$dnf" ] && [ ! -f /usr/bin/xfce4-session ]; then
    # Fedora can be silly.  It can have xfce installed, but not present.
    # In such a case, remove it and reinstall it.
    sudo dnf group remove xfce
    sudo dnf group install xfce
fi

# Install system-wide config files
sudo cp ~/tapioca/sysctl.conf /etc/
if [ -d /etc/dhcp ]; then
    sudo cp ~/tapioca/dhcpd.conf /etc/dhcp/
fi
if [ -f /etc/dhcpd.conf ]; then
    # Some platforms (e.g. openSUSE) put dhdpd.conf in /etc
    sudo cp ~/tapioca/dhcpd.conf /etc/dhcpd.conf
fi

echo Installation complete!
echo Please reboot and log in.
