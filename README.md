* [Overview](#overview)
* [Pre-installation](#pre-installation)  
   * [Client connectivity options](#client-connectivity-options)
* [Installation](#installation)
* [Tapioca Quick Start](#tapioca-quick-start)
   * [Testing Apps on Wireless Devices Using HOSTAP Adapter](#testing-apps-on-wireless-devices-using-hostap-adapter)
   * [Testing Apps on Wireless Devices](#testing-apps-on-wireless-devices-using-access-point)
   * [Testing Apps on Virtual Machines](#testing-apps-on-virtual-machines)
* [Tapioca Desktop Layout](#tapioca-desktop-layout)
* [Tapioca GUI Usage](#tapioca-gui-usage)
* [Tapioca Capture Modes](#tapioca-capture-modes)
   * [All traffic with tcpdump](#all-traffic-with-tcpdump-mode)
   * [Verify SSL validation](#verify-ssl-validation-mode)
   * [Full HTTPS inspection](#full-https-inspection-mode)
* [Strategies for Using Tapioca](#strategies-for-using-tapioca)
* [Manual Execution of Scripts](#manual-execution-of-scripts)


# Overview
CERT Tapioca is a utility for testing mobile or any other application using MITM techniques.  CERT Tapioca development was sponsored by the United States Army Armament Research, Development and Engineering Center (ARDEC) as well as the United States Department of Homeland Security (DHS).  Installation requirements:

1. Supported platforms include: Raspbian (Jessie or Stretch), Centos 7, RedHat Enterprise Linux 7, Fedora (24 through 28), or Ubuntu (14.04, 16.04, 18.04, or 20.04).   Other platforms may work, but the installer has only been tested on these distros.
1. 1GB of RAM
1. Upstream internet connectivity that does **not** require an explicit proxy.
1. Ability to provide wireless access to your device under test, which means **either**:
   * An available wired network adapter that a wireless access point can be plugged into.
   * A USB wireless adapter that supports HOSTAP mode.  e.g. https://smile.amazon.com/TP-Link-N150-Wireless-Adapter-TL-WN722N/dp/B002SZEOLG

**NOTE:** CERT Tapioca installation will transform your system into a Tapioca "appliance".  It is not recommended to install it on a system that you use for other purposes.

# Pre-installation
Install a supported Linux distribution on your machine.  Running on bare metal and in a virtual machine are supported.  Any installation style (from text-only through full GUI) for the host OS is supported.  Just ensure:

1. Internet connectivity is working.
1. A user named "tapioca" exists, and has administrative privileges.
1. The "tapioca" user is logged in.

### Client connectivity options
Before installing Tapioca, decide how you will be providing network connectivity to the clients under test.  Options include:

1. Use a wired network adapter.  This adapter should be configured to use the IP `10.0.0.1/24` before attempting installation.  Other addressing schemes can be used, but will require editing `tapioca.cfg` and `/etc/dhcp/dhcpd.conf`
1. Use a wireless USB adapter that supports HOSTAP mode.

### Security notes
CERT Tapioca requires root privileges for several capabilities that it uses.  For this reason, the Tapioca installer configures a system to not prompt the user for sudo privileges.  Any user with access to the CERT Tapioca system will have root privileges.  The "Full HTTPS inspection" certificate/key combination is static across all CERT Tapioca installations.  For this reason, any system or device that has the full HTTPS inspection mitmproxy root CA certificate installed should not be used on untrusted networks.  The same capability that allows you to use Tapioca to fully inspect HTTPS traffic can allow anyone else with a CERT Tapioca installation to perform the same inspection.

# Installation
1. Obtain the Tapioca code.  This can be accomplished by performing a `git clone` of the [Tapioca repository](https://github.com/CERTCC/tapioca.git), or by downloading and extracting a [zip file of the repository](https://github.com/CERTCC/tapioca/archive/master.zip).
1. Ensure that the Tapioca code lives in the `/home/tapioca/tapioca` directory. If you have obtained Tapioca via a zip file, this may require that you rename the `tapioca-master` directory to `tapioca`.
1. Run the installer:
`[tapioca@localhost tapioca]$ ./install_tapioca.sh`
Follow any prompts.
1. Reboot when done.
1. If given a choice, log in with the tapioca user and choose the Xfce login session.
If for any reason the installation fails, check and correct any relevant errors and run `./install_tapioca.sh` again.

### About Wireshark Versions
Tapioca downloads and compiles Wireshark to ensure compatibility with RedHat Enterprise Linux and Centos, which provide Wireshark versions older than what Tapioca needs.  If you wish to have Tapioca use your own version of Wireshark, simply ensure that `/usr/local/bin/tshark` is from the version of Wireshark that you wish to use before running `./install_tapioca.sh`.

# Tapioca Quick Start

### Testing Apps on Wireless Devices Using HOSTAP adapter
1. Connect a HOSTAP-capable WiFi adapter to your Tapioca machine.
1. Click the Software WiFi AP button (Radio tower) to enable your wireless access point.
1. Connect your device to the Tapioca access point.
1. Click the Tapioca GUI button to launch the main testing interface.

### Testing Apps on Wireless Devices Using Access point
1. Configure the Tapioca machine second network adapter to be `10.0.0.1/24`
1. If this network was not already configured at install time, re-run `./install_tapioca.sh` or manually edit `tapioca.cfg` to specify this network device name for `internal_net`.
1. Connect the access point uplink port to the Tapioca LAN port.
2. Connect your device to the access point.
1. Click the Tapioca GUI button to launch the main testing interface.

### Testing Apps on Virtual Machines
1. Configure the Tapioca machine second second network adapter to be `10.0.0.1/24`
1. If this network was not already configured at install time, re-run `./install_tapioca.sh` or manually edit `tapioca.cfg` to specify this network device name for `internal_net`.
1. Click the Tapioca GUI button to launch the main testing interface.

# Tapioca Desktop Layout
Once you have installed Tapioca, you should end up with a screen like the below. Individual icons may vary slightly across platforms.

![Tapioca desktop](images/tapioca-installed-annotated.png?raw=true)

##### Browse results
Open a file manager to view already-tested applications.

##### Terminal
Open a terminal to allow manual execution of scripts.

##### Web Browser
Open Chromium web browser.

##### Enable software WiFi AP
This button will configure a connected WiFi adapter for HOSTAP mode.  This will allow you to wirelessly connect your client device to Tapioca for traffic inspection.

##### Tapioca GUI
Launch the main Tapioca interface.

##### Capture all traffic
Use tcpdump to capture all raw network traffic without interfering.

##### SSL validation
Use mitmproxy to intercept HTTP/HTTPS traffic, using an untrusted root certificate. Any HTTPS traffic that passes through is an indication of a client that isn't validating HTTPS certificates.

##### Full HTTPS inspection
Use mitmproxy to intercept HTTP/HTTPS traffic, using a root certificate that has been installed on the client system. This allows full inspection of non-pinned HTTPS traffic.

##### Stop capture
Stop any (tcpdump, mitmproxy) capture.

# Tapioca GUI usage
While the Tapioca platform provides buttons to launch individual tests, the Tapioca GUI will provide most of the capabilities that you will need.

![Tapioca GUI](images/tapioca-opened-annotated.png?raw=true)

# Tapioca Capture Modes
To be able to run all of the reports included with Tapioca, **three** captures are required.:

### All traffic with tcpdump mode
![tcpdump](images/tapioca-tcpdump.png?raw=true)

In "**All traffic with tcpdump**" mode, Tapioca doesn't interfere with HTTPS negotiation. This allows Tapioca to inspect the HTTPS handshakes that occur between a client and a server.  If a client is using insecure crypto, or protocols other than HTTP/HTTPS, then the tcpdump capture will be required to detect this. This capture is required to allow the **Crypto test** report to be generated.

### Verify SSL validation mode
![SSL validation](images/tapioca-ssltest.png?raw=true)

In "**Verify SSL validation**" mode, Tapioca will intercept web traffic, and the HTTPS communications between the client and Tapioca will use an **invalid** root CA certificate. Any client that allows HTTPS traffic through Tapioca without warning is vulnerable to malicious interception. Despite the client using HTTPS, it is not receiving the benefits that HTTPS aims to provide. This capture is required to allow the SSL test report to be generated.


### Full HTTPS inspection mode
![Full HTTPS inspection](images/tapioca-full.png?raw=true)

In "**Full HTTPS inspection**" mode, Tapioca will intercept web traffic, and the HTTPS communications between the client and Tapioca will use a valid root CA certificate that has been [installed on the client](https://docs.mitmproxy.org/stable/concepts-certificates/). This allows searching for content in web traffic, even if it has been encrypted with HTTPS. This capture is required to allow Search capabilities within encrypted, but not pinned, network traffic.

# Strategies for Using Tapioca
For each client application being tested, run through the normal operations for using the client while the traffic is being captured in each of the three modes:

1. **All traffic with tcpdump**
1. **Verify SSL validation**
1. **Full HTTPS inspection**

At the end of each test, be sure to stop the capture using the Tapioca GUI or by clicking the stop sign icon at the bottom of the screen.  Before starting the next test, be sure to terminate the application being tested. An uninstall of the application between tests will ensure thoroughness of the test. For example, some applications install a service that continues to run even after the application is terminated.

After traffic is captured in all three modes, press the "Generate reports" button.  The SSL test and the Crypto test have PASSED/FAILED statuses. The network connectivity test simply generates a report of hosts contacted.  Results for all three tests can be viewed by using the Tapioca GUI.

When entering any data into a form, **always** use the same values. This can allow you to search for your data.  For example, if you are presented with a password field, if you always use "passssss" that will allow you to search for that value in the traffic.

# Manual Execution of Scripts
If you are not using the Tapioca GUI, need to troubleshoot problems, or if you would like to run the utilities against existing network captures (e.g. a pcap file), there are command-line utilities:

* `checkcrypto.py` - Validate that HTTPS negotiations are secure (pcap required)
* `checknet.py` - Enumerate hosts contacted using which protocols, as well as which host names are resolved (pcap required)
* `checkssl.py` - Validate that a client is verifying that an SSL certificate is issued by a trusted provider (mitmproxy log file required)
* `search.py` - Search for strings in network captures (pcap and/or mitmproxy log file required)
