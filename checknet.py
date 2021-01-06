#!/usr/bin/env python3.7
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

from __future__ import print_function
import pyshark
import socket
import color
import os
import sys
import argparse
import pickle
import json
import net
from misc import eprint, Logger

local_prefix = '10.0'
report_output = 'net.txt'
json_output = 'net.json'


def get_protos_full(protolist):
    '''
    For protocols where tshark is aware of a higher-layer protocol
    description, report only the higher-layer description.
    For example, if a connection is SSL (443/TCP), there is no need
    to also report the "TCP (443/TCP)" part

    input: list of protocols reported by tshark
    returns: list of protocols with redundancy removed
    '''
    named_protocols = []
    trimmedlist = []

    # Go through each protocol in list and get only the port/protocol pair.
    # For example, for "TCP (443/TCP)" get just "(443/TCP)"
    for proto in protolist:
        porttransport = proto.split(' ')[1]
        # if tshark reports something more specific than TCP or UDP,
        # append it to the list of protocols that are named
        if porttransport in proto and not proto.startswith('TCP') and not proto.startswith('UDP'):
            named_protocols.append(proto)

    if named_protocols:
        # We have at least one specifically-named protocol
        # No need to get TCP setup
        for proto in protolist:
            # Go through each protocol in the list
            porttransport = proto.split(' ')[1]
            # Get just the port/transport part
            matching = [s for s in named_protocols if porttransport in s]
            # Get list of named protocols where the port/transport pair
            # matches the entire entry.
            # e.g. get "SSL (443/TCP)" if our current porttransport is:
            # "(443/TCP)
            if proto in matching:
                # Use the named protocol
                trimmedlist.append(proto)
    else:
        # No named protocol. Just stick with the basic port + TCP/UDP.
        trimmedlist.append(proto)

    return trimmedlist


def get_protos(protolist):
    '''
    For protocols where tshark is aware of a higher-layer protocol
    description, report only the higher-layer description.
    For example, if a connection is SSL (443/TCP), there is no need
    to also report the "TCP (443/TCP)" part

    input: list of protocols reported by tshark
    returns: list of protocols with redundancy removed
    '''
    named_protocols = []
    trimmedlist = []

    # For each protocol in list for host
    for proto in protolist:
        # if tshark reports something more specific than TCP or UDP,
        # append it to the list of protocols that are named
        if proto not in named_protocols and not ('/TCP' in proto) and not ('/UDP' in proto) \
                and proto != 'TCP' and proto != 'UDP':
            named_protocols.append(proto)

    if named_protocols:
        # We have at least one specifically-named protocol
        # No need to get TCP setup
        for proto in protolist:

            if proto == '443/TCP':
                matching = [
                    s for s in named_protocols if ('TLS' in s or 'SSL' in s)]
                if matching:
                    # No need to add '443/TCP' if we already have something
                    # with SSL or TLS in it
                    continue

            if proto == '80/TCP' and 'HTTP' in named_protocols:
                # No need to add '80/TCP' if we already have HTTP protocol
                continue

#            if 'TLS' in proto and 'SSL' in named_protocols:
#                # No need to individually list both SSL and TLS
#                continue

            trimmedlist.append(proto)
    else:
        # No named protocol. Just stick with the basic port + TCP/UDP.
        for proto in protolist:
            trimmedlist.append(proto)

    return trimmedlist


def generate_report(app, fullpacket=False, pcapfile=''):
    '''
    Print report based on collected data
    '''

    report = {}
    report['app'] = app
    report['testtime'] = os.path.getmtime(pcapfile)
    # This is an un-failable test
    report['failedtest'] = False
    report['targets'] = net.targets
    report['dnsreqs'] = net.dnsreqs

    if app.endswith('.pcap'):
        app_or_pcap = 'pcap'
        jsonfile = '%s.%s' % (app, json_output)
    else:
        app_or_pcap = 'application'
        jsonfile = os.path.join(os.path.dirname(pcapfile), 'net.json')

    print('')
    print('Summary for %s: %s' % (app_or_pcap, color.bright(color.cyan(app))))
    print('')
    print(color.bright('Hosts contacted:'))
    # For each target (unsorted)
    for target in net.targets:
        # Get protocols used
        if fullpacket:
            protos = get_protos_full(net.targets[target])
        else:
            protos = get_protos(net.targets[target])
        # Get host name
        host = net.get_hostname(target)
        protolist = ', '.join(protos)
        print('%s : %s : %s' % (color.bright('CONNECT'), host, protolist))
    print('')
    print(color.bright('DNS queries made:'))
    for dnsreq in net.dnsreqs:
        print('%s : %s' % (color.bright('LOOKUP'), dnsreq))

    with open(jsonfile, 'w') as fp:
        json.dump(report, fp)


def check_app(app, fullpacket=False, force=False):
    '''
    Check application based on app name in Tapioca results
    '''

    dnscacheloaded = False
    targetscacheloaded = False
    largewarned = False

    # load local network from config
    net.set_local()

    # Get pcap file location
    if app.endswith('.pcap'):
        pcapfile = app
        if os.path.exists(pcapfile):
            sys.stdout = Logger('%s.%s' % (pcapfile, report_output))
    else:
        pcapfile = os.path.join('results', app, 'tcpdump.pcap')
        if os.path.exists(pcapfile):
            sys.stdout = Logger(os.path.join('results', app, report_output))

    if os.path.exists(pcapfile):

        pcapdir = os.path.dirname(pcapfile)
        dnspkl = os.path.join(pcapdir, '.dnsmap.pkl')
        targetspkl = os.path.join(pcapdir, '.targets.pkl')

        eprint(color.bright('Checking app %s...' % color.cyan(app)))

        if os.path.exists(dnspkl) and not force:
            eprint('Loading cached DNS info...')
            with open(dnspkl, 'rb') as pklhandle:
                try:
                    net.dnsmap = pickle.load(pklhandle)
                    net.dnsreqs = pickle.load(pklhandle)
                    dnscacheloaded = True
                except:
                    pass

        if not dnscacheloaded:
            if os.path.getsize(pcapfile) > 100000000:
                # Over 100MB
                eprint(
                    color.bright(color.yellow('Warning: capture size is large. Please be patient.')))
                largewarned = True
            # Get captured DNS info for IP addresses
            eprint('Getting DNS info...')
            dnspackets = pyshark.FileCapture(
                pcapfile, keep_packets=False, display_filter='dns')
            dnspackets.apply_on_packets(net.get_dns_info, timeout=1000)
            with open(dnspkl, 'wb') as pklhandle:
                pickle.dump(
                    net.dnsmap, pklhandle, protocol=pickle.HIGHEST_PROTOCOL)
                pickle.dump(
                    net.dnsreqs, pklhandle, protocol=pickle.HIGHEST_PROTOCOL)

#        if os.path.exists(targetspkl) and not force:
#            eprint('Loading cached targets...')
#            with open(targetspkl, 'rb') as pklhandle:
#                try:
#                    net.targets = pickle.load(pklhandle)
#                    targetscacheloaded = True
#                except:
#                    pass

        if not targetscacheloaded:
            if fullpacket:
                packets = pyshark.FileCapture(
                    pcapfile, keep_packets=False)
                # Get hosts contacted
                eprint('Getting hosts contacted...')
                packets.apply_on_packets(
                    net.get_hosts_contacted_fullpacket, timeout=1000)
            else:
                packets = pyshark.FileCapture(
                    pcapfile, keep_packets=False, only_summaries=True)
                # Get hosts contacted
                eprint('Getting hosts contacted...')
                packets.apply_on_packets(net.get_hosts_contacted, timeout=1000)
#                with open(targetspkl, 'wb') as pklhandle:
#                    pickle.dump(
# net.targets, pklhandle, protocol=pickle.HIGHEST_PROTOCOL)

        # Print report
        generate_report(app, fullpacket=fullpacket, pcapfile=pcapfile)

        # Reset globals
        net.clear()


def main():
    if os.path.exists('tapioca.cfg'):
        with open('tapioca.cfg') as f:
            configlines = f.readlines()
        for line in configlines:
            if line.startswith('internal_subnet'):
                line = line.rstrip()
                local_subnet = line.split('=')[1]
                ip = local_subnet.split('/')[0]
                nums = ip.split('.')
                local_prefix = '.'.join(nums[:2])

    parser = argparse.ArgumentParser(
        description='Show network connectivity for one or more tested application')
    parser.add_argument('app_or_capture', metavar='appname', nargs='?',
                        help='Application name or network capture file')
    parser.add_argument('--fullpacket', dest='fullpacket', action='store_true',
                        help='Parse full packets (slow)')
    parser.add_argument('-f', '--force', dest='force', action='store_true',
                        #                    const=sum, default=max,
                        help='Force re-parsing of capture file')
    args = parser.parse_args()

    app = args.app_or_capture

    # if args.fullpacket:
    # Check only one app
    # Option to use full packets perhaps specified
    #    check_app(app, fullpacket=args.fullpacket)
    if args.app_or_capture:
        # Check only one app
        check_app(app, fullpacket=args.fullpacket, force=args.force)
    else:
        # Check all apps tested
        for entry in os.listdir('results'):
            if os.path.isdir(os.path.join('results', entry)):
                app = entry
                check_app(
                    app, fullpacket=args.fullpacket, force=args.force)
            elif os.path.isdir(os.path.join('results', entry.lower())):
                app = entry
                check_app(
                    app, fullpacket=args.fullpacket, force=args.force)

if __name__ == "__main__":
    main()
